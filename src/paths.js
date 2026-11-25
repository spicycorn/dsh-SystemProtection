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
/** Windows extended-length prefix: `\\?\C:\Windows`. */
const EXTENDED_RE = /^\\\\[?.]\\/
/** A volume-GUID component, as `\\?\Volume{…}` becomes after the prefix is stripped. */
const VOLUME_GUID_RE = /^volume\{[0-9a-f-]+\}$/i
/** An 8.3 short name such as `PROGRA~1`. */
const SHORT_NAME_RE = /(?:^|\\)[^\\]*~\d[^\\]*/

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
 * A UNC path keeps its double backslash: collapsing it to one would turn
 * `\\server\share\x` into a relative-looking `\server\share\x` and, worse, let a
 * path on this machine's own administrative share drift out of every rule.
 *
 * @param {string} absolute
 * @param {{ insensitive: boolean, path: typeof import('node:path') }} ctx
 * @returns {string}
 */
export function pathKey(absolute, ctx) {
  let text = String(absolute)
  const p = impl(ctx)
  text = text.replace(/\\/g, p.sep)
  if (EXTENDED_RE.test(text)) {
    text = text.replace(/^\\\\[?.]\\/, '')
    // `\\?\UNC\server\share` is a UNC path spelled the extended way.
    if (ctx.insensitive && /^UNC\\/i.test(text)) text = `\\\\${text.slice(4)}`
  }
  // The UNC prefix is the one run of separators that must survive the collapse below.
  let unc = false
  if (ctx.insensitive && /^\\\\[^\\]/.test(text)) {
    unc = true
    text = text.slice(2)
  }
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
  if (unc) text = `\\\\${text.replace(/^\\+/, '')}`
  if (!ctx.insensitive && text === '') return '/'
  return text
}

/**
 * Where an administrative share of *this* machine points, if it is one.
 *
 * `\\localhost\C$\Windows` is the same file as `C:\Windows`, and `\\host\ADMIN$`
 * is `%SystemRoot%`. Both are reachable without any extra privilege by a process
 * running as an administrator, so a delete tool that names them must land in the
 * same rules as the drive-letter spelling.
 *
 * @param {string} key result of {@link pathKey}
 * @param {{ win: boolean, hostNames?: string[], roots: { systemRoot?: string } }} ctx
 * @returns {string | undefined} the local path key, or undefined when this is another machine
 */
export function uncLocalAlias(key, ctx) {
  if (ctx.win !== true) return undefined
  const match = /^\\\\([^\\]+)\\([^\\]+)(?:\\|$)/.exec(key)
  if (match === null) return undefined
  const host = match[1].toLowerCase()
  const share = match[2].toLowerCase()
  const local = ctx.hostNames ?? []
  if (!local.includes(host) && !local.includes(host.split('.')[0])) return undefined
  const rest = key.slice(match[0].length)
  if (/^[a-z]\$$/.test(share)) return `${share[0]}:\\${rest}`
  if (share === 'admin$' && typeof ctx.roots?.systemRoot === 'string') return `${ctx.roots.systemRoot}\\${rest}`
  return undefined
}

/**
 * Node's plain `realpathSync` is a JavaScript implementation that leaves an 8.3
 * short name (`C:\PROGRA~1`) exactly as written; the native one asks the OS, which
 * expands it. The alias resolver below needs the native form.
 *
 * @param {Partial<typeof import('node:fs')> | undefined} fsx
 * @returns {((p: string) => string) | undefined}
 */
function nativeRealpath(fsx) {
  const realpath = fsx?.realpathSync
  if (typeof realpath !== 'function') return undefined
  const native = typeof realpath.native === 'function' ? realpath.native : realpath
  return target => native.call(fsx, target)
}

/** Per-context memo for the drive-root lookups (a syscall per new drive letter, not per call). */
const ALIAS_CACHE = new WeakMap()

function aliasCacheOf(ctx) {
  let cache = ALIAS_CACHE.get(ctx)
  if (cache === undefined) {
    cache = new Map()
    ALIAS_CACHE.set(ctx, cache)
  }
  return cache
}

/**
 * The real path behind a spelling that can hide one: a drive letter produced by
 * `subst` or by mounting a volume (`mountvol S: /S`), and an 8.3 short name.
 *
 * Only ever reached with the `fs` module the caller injected, and every lookup is
 * cached per context — one `realpath` per drive letter and one per short-name
 * path, never a directory walk.
 *
 * @param {string} key result of {@link pathKey}
 * @param {{ family: string, path: typeof import('node:path'), insensitive: boolean }} ctx
 * @param {Partial<typeof import('node:fs')> | undefined} fsx
 * @returns {string | undefined} a second key worth classifying, when it differs
 */
export function canonicalAlias(key, ctx, fsx) {
  if (ctx.family !== 'win32' || fsx === undefined || fsx === null) return undefined
  if (typeof key !== 'string' || !/^[a-z]:/.test(key)) return undefined
  const realpath = nativeRealpath(fsx)
  if (realpath === undefined) return undefined
  const cache = aliasCacheOf(ctx)

  // 1. A drive letter that points at another directory or volume.
  const drive = key.slice(0, 2)
  const root = `${drive}${ctx.path.sep}`
  const cached = cache.get(`drive:${drive}`)
  let real = cached
  if (real === undefined) {
    try {
      const value = realpath(root)
      real = typeof value === 'string' && value !== '' ? pathKey(value, ctx) : ''
      // A failure is not cached: the drive may be mapped later in the same session.
      if (real !== '') cache.set(`drive:${drive}`, real)
    }
    catch {
      real = ''
    }
  }
  if (real !== '' && real !== root) {
    const rest = key.slice(drive.length).replace(/^\\+/, '')
    const base = real.endsWith(ctx.path.sep) ? real : `${real}${ctx.path.sep}`
    return rest === '' ? real : `${base}${rest}`
  }

  // 2. An 8.3 short name: resolve the deepest ancestor that exists, keep the rest.
  if (SHORT_NAME_RE.test(key) && typeof fsx.existsSync === 'function') {
    const cacheKey = `short:${key}`
    const memo = cache.get(cacheKey)
    if (memo !== undefined) return memo === '' ? undefined : memo
    let resolved
    const parts = key.split('\\')
    for (let cut = parts.length; cut > 1; cut--) {
      const candidate = parts.slice(0, cut).join('\\')
      let exists = false
      try {
        exists = fsx.existsSync(candidate) === true
      }
      catch {
        exists = false
      }
      if (!exists) continue
      try {
        const target = pathKey(realpath(candidate), ctx)
        if (target !== candidate) {
          resolved = parts.length > cut ? `${target}\\${parts.slice(cut).join('\\')}` : target
        }
      }
      catch { /* an unstattable ancestor is judged lexically */ }
      if (resolved !== undefined) break
    }
    if (cache.size < 4096) cache.set(cacheKey, resolved ?? '')
    return resolved
  }

  return undefined
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
 * Resolve the deepest ancestor of a path that exists, then re-append the rest.
 *
 * A target that does not exist yet (a new file, a probe) is still reached
 * *through* whatever the existing part of its path is: a junction inside the
 * workspace pointing at the Harness install must not turn "write a new file in
 * the workspace" into "write a new file in `resources`".
 *
 * @param {string} absolute
 * @param {{ path: typeof import('node:path'), insensitive: boolean }} ctx
 * @param {Partial<typeof import('node:fs')> | undefined} fsx
 * @returns {string | undefined} the real path, only when it differs from the spelling
 */
export function resolveExistingAncestor(absolute, ctx, fsx) {
  const realpath = nativeRealpath(fsx)
  if (realpath === undefined || typeof fsx?.existsSync !== 'function') return undefined
  const original = String(absolute)
  if (original === '') return undefined
  let cursor = original
  const remainder = []
  for (let guard = 0; guard < 64; guard++) {
    let exists = false
    try {
      exists = fsx.existsSync(cursor) === true
    }
    catch {
      exists = false
    }
    if (exists) {
      try {
        const real = realpath(cursor)
        if (typeof real !== 'string' || real === '') return undefined
        const target = remainder.length === 0 ? real : joinRaw(real, remainder.join(ctx.path.sep))
        return pathKey(target, ctx) === pathKey(original, ctx) ? undefined : target
      }
      catch {
        return undefined
      }
    }
    const parent = ctx.path.dirname(cursor)
    if (parent === cursor || parent === '' || parent === '.' || parent === ctx.path.sep) return undefined
    remainder.unshift(ctx.path.basename(cursor))
    cursor = parent
  }
  return undefined
}

/**
 * Resolve an *existing* path through the OS, including junctions, mount points
 * and 8.3 short names, and report it only when it differs from the spelling.
 *
 * A `subst` drive, a volume mounted at a directory, or a junction to
 * `C:\Windows` makes a second spelling of a protected path. `lstat` alone only
 * sees a symlink in the *final* component, which is not how a directory link is
 * usually reached.
 *
 * @param {string} absolute
 * @param {{ path: typeof import('node:path'), insensitive: boolean }} ctx
 * @param {Partial<typeof import('node:fs')> | undefined} fsx
 * @returns {string | undefined}
 */
export function resolveExistingPath(absolute, ctx, fsx) {
  const realpath = nativeRealpath(fsx)
  if (realpath === undefined || typeof fsx?.existsSync !== 'function') return undefined
  let exists = false
  try {
    exists = fsx.existsSync(absolute) === true
  }
  catch {
    return undefined
  }
  if (!exists) return undefined
  try {
    const real = realpath(absolute)
    if (typeof real !== 'string' || real === '') return undefined
    return pathKey(real, ctx) === pathKey(absolute, ctx) ? undefined : real
  }
  catch {
    return undefined
  }
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
  return resolveExistingPath(absolute, ctx, fsx)
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
  if (ctx.insensitive) {
    return /^[a-z]:[\\]?$/.test(key) || /^\\\\[^\\]+\\[^\\]+$/.test(key) || VOLUME_GUID_RE.test(key)
  }
  return key === '/'
}
