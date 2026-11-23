/**
 * Path syntax helpers that must work for a target platform that differs from
 * the one the Harness runs on (self-tests simulate win32 on any host).
 *
 * Everything here is lexical: no filesystem access, no model-visible concepts.
 * The only side-effecting helper is {@link resolveReal}, which takes an
 * injected `fs` module so callers keep the guard synchronous and testable.
 *
 * @module system-protection/paths
 */

/**
 * Characters a backslash legitimately escapes in a shell word. Anything else
 * keeps the backslash literal, so `C:\Windows\System32` survives tokenizing
 * instead of collapsing to `C:WindowsSystem32`.
 */
export const SHELL_SPECIAL = new Set([' ', '\t', '\n', '\r', '"', "'", '`', '\\', '|', '&', ';', '<', '>', '(', ')', '$', '*', '?', '[', ']', '{', '}', '#', '!', '~'])

/**
 * True when a backslash at this point escapes the following character.
 * @param {string} next
 */
export function escapesNext(next) {
  return next !== undefined && SHELL_SPECIAL.has(next)
}
/** Windows drive root: `C:`, `C:\`, `C:/`. */
const DRIVE_RE = /^[a-zA-Z]:/
/** UNC root: `\\server\share`. */
const UNC_RE = /^\\\\[^\\?]+\\[^\\]+/i
/** Windows extended-length prefix: `\\?\C:\Windows`. */
const EXTENDED_RE = /^\\\\[?.]\\/

/**
 * Strip one layer of matching quotes and any trailing shell line-continuation.
 * @param {string} raw
 * @returns {string}
 */
export function stripQuotes(raw) {
  let text = String(raw).trim()
  for (;;) {
    const before = text
    if (text.length >= 2) {
      const first = text[0]
      const last = text[text.length - 1]
      if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
        text = text.slice(1, -1).trim()
      }
      else if (first === '"' && text.endsWith('\\"')) {
        // `"C:\foo\"` style: a quoted path whose closing quote is escaped.
        text = text.slice(1, -2).trim()
      }
    }
    if (text.endsWith('\\') && !text.endsWith('\\\\')) text = text.slice(0, -1).trim()
    if (text === before) break
  }
  return text
}

/**
 * Case-insensitive environment lookup (Windows names are case-insensitive).
 * @param {Record<string, string | undefined>} env
 * @param {string} name
 * @param {boolean} insensitive
 * @returns {string | undefined}
 */
export function readEnv(env, name, insensitive) {
  const direct = env[name]
  if (direct !== undefined) return direct
  if (!insensitive) return undefined
  const want = name.toLowerCase()
  for (const key of Object.keys(env)) {
    if (key.toLowerCase() === want) return env[key]
  }
  return undefined
}

/**
 * Expand the variable spellings a model writes into a path:
 * `~`, `~user`, `$VAR`, `${VAR}`, `$env:VAR`, `${env:VAR}`, `%VAR%`.
 *
 * An unresolvable variable is left in place and reported, so the caller can
 * decide whether an unexpanded path is worth asking about instead of silently
 * treating a literal `$DEPLOY_ROOT/bin` as a relative path.
 *
 * @param {string} raw
 * @param {{ env: Record<string, string | undefined>, homedir: string, insensitive: boolean }} ctx
 * @returns {{ text: string, unresolved: string[] }}
 */
export function expandVariables(raw, ctx) {
  const unresolved = []
  const lookup = (name) => {
    const value = readEnv(ctx.env, name, ctx.insensitive)
    if (value !== undefined && value !== '') return value
    unresolved.push(name)
    return undefined
  }
  let text = String(raw)

  // PowerShell spellings first: `$env:NAME`, `${env:NAME}`, `$env:NAME\sub`.
  text = text.replace(/\$\{env:([A-Za-z_][A-Za-z0-9_( )]*)\}/gi, (_m, name) => lookup(name) ?? _m)
  text = text.replace(/\$env:([A-Za-z_][A-Za-z0-9_( )]*)/gi, (_m, name) => lookup(name) ?? _m)
  // POSIX `${NAME}`, then `$NAME` (stop at a path separator).
  text = text.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_m, name) => lookup(name) ?? _m)
  text = text.replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (match, name) => {
    const value = lookup(name)
    return value === undefined ? match : value
  })
  // Windows `%NAME%`.
  text = text.replace(/%([A-Za-z_][A-Za-z0-9_() ]*)%/g, (_m, name) => lookup(name) ?? _m)

  if (text === '~' || text.startsWith('~/') || text.startsWith('~\\')) {
    const tail = text.slice(1)
    text = joinRaw(ctx.homedir, tail)
  }
  else if (text.startsWith('~')) {
    unresolved.push(text.slice(1).split(/[\\/]/)[0])
  }

  // A trailing separator from variable expansion, e.g. `%USERPROFILE%\`.
  return { text, unresolved }
}

/**
 * Join two raw path spellings without assuming the host separator.
 * @param {string} head
 * @param {string} tail
 * @returns {string}
 */
export function joinRaw(head, tail) {
  if (tail === '' || tail === undefined || tail === null) return head
  const sep = /\\/.test(head) && !/\//.test(head) ? '\\' : '/'
  return head.endsWith(sep) || head.endsWith('/') || head.endsWith('\\')
    ? head + String(tail).replace(/^[/\\]+/, '')
    : head + sep + String(tail).replace(/^[/\\]+/, '')
}

/**
 * @param {string} raw
 * @param {{ insensitive: boolean }} ctx
 * @returns {boolean} whether the spelling is already absolute for its platform
 */
export function isAbsoluteLike(raw, ctx) {
  const text = String(raw)
  if (DRIVE_RE.test(text)) return true
  if (text.startsWith('\\\\') || text.startsWith('//')) return true
  if (text.startsWith('/') || text.startsWith('\\')) return ctx.insensitive ? text.startsWith('\\') : true
  return false
}

/** The Node path implementation matching the target platform family. */
function impl(ctx) {
  return ctx.insensitive ? ctx.path.win32 : ctx.path.posix
}

/**
 * Lexically normalize `raw` into an absolute path on the target platform.
 *
 * @param {string} raw
 * @param {{ insensitive: boolean, path: typeof import('node:path'), cwd: string }} ctx
 * @param {string} base directory used for relative spellings
 * @returns {string | undefined} undefined when nothing sensible can be derived
 */
export function normalizeAbsolute(raw, ctx, base) {
  const text = String(raw).trim()
  if (text === '') return undefined
  const p = impl(ctx)
  // `cd ..`, `./x`, `dir/../y` all resolve against `base`; `C:\x`, `/x`, `\\s\s` do not.
  if (isAbsoluteLike(text, ctx)) return p.normalize(text)
  if (/^~/.test(text)) return undefined // already expanded by expandVariables
  const anchor = base && base !== '' ? base : ctx.cwd
  if (!anchor) return undefined
  return p.resolve(anchor, text)
}

/**
 * The comparable form of a normalized absolute path.
 *
 * @param {string} absolute
 * @param {{ insensitive: boolean, path: typeof import('node:path') }} ctx
 * @returns {string}
 */
export function pathKey(absolute, ctx) {
  let text = String(absolute)
  const p = impl(ctx)
  text = text.replace(/\\/g, p.sep)
  if (EXTENDED_RE.test(text)) text = text.replace(/^\\\\[?.]\\/, '')
  if (ctx.insensitive) {
    text = text.toLowerCase()
    // A drive letter must keep its colon: `c:` alone is a drive-relative path.
    if (/^[a-z]:$/.test(text)) text += '\\'
  }
  // Collapse separators, drop trailing separators, and trim the DOS trailing-dot rule.
  text = text.replace(new RegExp(`\\${p.sep}{2,}`, 'g'), p.sep)
  text = text.replace(/[. ]+$/g, '')
  if (text.length > 1) text = text.replace(new RegExp(`\\${p.sep}$`), '')
  // A volume root keeps its separator: `c:` is a drive-relative path, `c:\` is the drive.
  if (ctx.insensitive && /^[a-z]:$/.test(text)) text += p.sep
  if (!ctx.insensitive && text === '') return '/'
  return text
}

/**
 * @param {string} parentKey result of {@link pathKey}
 * @param {string} childKey result of {@link pathKey}
 * @param {{ insensitive: boolean, path: typeof import('node:path') }} ctx
 * @returns {boolean} whether `childKey` is `parentKey` or below it
 */
export function isWithin(parentKey, childKey, ctx) {
  if (parentKey === '' || childKey === '') return false
  if (parentKey === childKey) return true
  const sep = impl(ctx).sep
  const head = parentKey.endsWith(sep) ? parentKey : parentKey + sep
  return childKey.startsWith(head)
}

/**
 * Segments below `parentKey`, as a depth count used by depth-limited rules.
 * @param {string} parentKey
 * @param {string} childKey
 * @param {{ insensitive: boolean, path: typeof import('node:path') }} ctx
 * @returns {number} 0 for the parent itself, -1 when not inside
 */
export function depthBelow(parentKey, childKey, ctx) {
  if (!isWithin(parentKey, childKey, ctx)) return -1
  if (parentKey === childKey) return 0
  const sep = impl(ctx).sep
  const head = parentKey.endsWith(sep) ? parentKey : parentKey + sep
  const rest = childKey.slice(head.length)
  if (rest === '') return 0
  return rest.split(sep).filter(part => part !== '').length
}

/**
 * Resolve symlinks so `ln -s / Windows` tricks cannot smuggle a protected
 * target past a lexical check. Returns the real path when the final component
 * or any ancestor resolves differently, otherwise undefined.
 *
 * @param {string} absolute
 * @param {{ path: typeof import('node:path'), insensitive: boolean }} ctx
 * @param {typeof import('node:fs')} fsx
 * @returns {string | undefined}
 */
export function resolveReal(absolute, ctx, fsx) {
  try {
    const link = fsx.lstatSync(absolute)
    if (!link.isSymbolicLink() && !fsx.realpathSync) return undefined
    const real = fsx.realpathSync(absolute)
    if (pathKey(real, ctx) === pathKey(absolute, ctx)) return undefined
    return real
  }
  catch {
    return undefined
  }
}

/**
 * True for a bare wildcard operand (`*`, `.*`, `**`, `C:\*`, `/usr/*`).
 * The trailing glob is removed by the caller before classification, so this
 * only reports that the model asked for "everything here".
 *
 * @param {string} raw
 * @returns {boolean}
 */
export function isWildcardOperand(raw) {
  return /(?:^|[/\\])(?:\*{1,2}|\*\*)$/.test(String(raw).replace(/["']/g, '').trim())
}

/**
 * True when the operand targets a whole volume or the filesystem root.
 * @param {string} key result of {@link pathKey}
 * @param {{ insensitive: boolean, path: typeof import('node:path') }} ctx
 * @returns {boolean}
 */
export function isVolumeOrRoot(key, ctx) {
  if (ctx.insensitive) return /^[a-z]:[\\]?$/.test(key) || /^[\\]{2}[^\\]+[\\][^\\]+$/.test(key)
  return key === '/'
}
