/**
 * Shell-layer scanning: read a model-authored shell command and report every
 * path it would destroy, plus the commands that are catastrophic on their own.
 *
 * This is deliberately a heuristic reader, not an executor and not a parser
 * with grammar guarantees. It recognises the shapes models actually write
 * (`rm -rf`, `Remove-Item -Recurse -Force`, `find -delete`, `git clean`,
 * `xargs rm`, `bash -c "…"`, `powershell -EncodedCommand …`) and hands the
 * resulting paths to the same rule tables that guard the file tools, so one
 * answer for "is this protected" holds wherever the path arrives from.
 *
 * A command that hides its target (a compiled helper, a variable the scanner
 * cannot expand, a script written moments earlier and then run) is a known gap:
 * the file-system-layer guard and the OS sandbox are what remain. The plugin
 * detail document states this plainly.
 *
 * @module system-protection/shell-scan
 */

import { escapesNext, expandVariables, isWildcardOperand, isWithin, normalizeAbsolute, pathKey, resolveExistingPath, stripQuotes } from './paths.js'
import { classifyKey, TIER_RANK } from './rules.js'

/** Prefix commands that only change how the real command runs. */
const WRAPPERS = new Set(['sudo', 'doas', 'su', 'env', 'nohup', 'time', 'times', 'nice', 'ionice', 'setsid', 'command', 'builtin', 'exec', 'busybox', 'stdbuf', 'timeout', 'runuser', 'start'])

/** POSIX deletion verbs. */
const POSIX_DELETE = new Set(['rm', 'rmdir', 'unlink', 'srm', 'shred', 'sdelete', 'erase'])
/** POSIX verbs that destroy the source, or zero a file. */
const POSIX_MOVE = new Set(['mv', 'move'])
const POSIX_TRUNCATE = new Set(['truncate'])
/** Shells whose `-c` payload must be scanned too. */
const POSIX_SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'csh', 'tcsh', 'fish', 'yash'])
const POSIX_CODE = new Map([['python', '-c'], ['python2', '-c'], ['python3', '-c'], ['node', '-e'], ['nodejs', '-e'], ['deno', 'eval'], ['perl', '-e'], ['ruby', '-e'], ['php', '-r'], ['awk', ''], ['expect', '-c']])

/** PowerShell / cmd deletion verbs (compared lower-cased). */
const WIN_DELETE = new Set(['del', 'erase', 'rd', 'rmdir', 'rm', 'ri', 'remove-item', 'remove-psdrive', 'del.exe', 'rd.exe', 'rm.exe', 'erase.exe', 'remove-item.exe'])
const WIN_MOVE = new Set(['move-item', 'move', 'mv', 'mi', 'ren', 'rename-item', 'rn', 'move-item.exe'])
const WIN_WRITE = new Set(['set-content', 'sc', 'out-file', 'add-content', 'ac', 'new-item', 'ni'])
const WIN_CODE = new Map([['pwsh', ['-command', '-c', '-e']], ['powershell', ['-command', '-c', '-e']], ['powershell_ise', []], ['pwsh.exe', ['-command', '-c', '-e']], ['powershell.exe', ['-command', '-c', '-e']]])
/** `-EncodedCommand` aliases, and the script-block forms. */
const ENCODED_FLAGS = new Set(['-encodedcommand', '-enc'])
/** A `.ps1`/`.bat` run through a shell needs no extra work: the file is data. */
const CMD_WRAPPERS = new Set(['cmd', 'cmd.exe'])

/** Commands that damage the machine whatever their arguments name. */
const BLANKET = [
  { verb: 'diskpart', tier: 'system', id: 'shell:diskpart', note: 'diskpart can repartition or wipe a disk' },
  { verb: 'fdisk', tier: 'system', id: 'shell:fdisk', note: 'fdisk modifies the partition table' },
  { verb: 'parted', tier: 'system', id: 'shell:parted', note: 'parted modifies the partition table' },
  { verb: 'mkfs', tier: 'system', id: 'shell:mkfs', note: 'mkfs re-creates a filesystem' },
  { verb: 'mkswap', tier: 'system', id: 'shell:mkswap', note: 'mkswap overwrites a partition' },
  { verb: 'wipefs', tier: 'system', id: 'shell:wipefs', note: 'wipefs erases filesystem signatures' },
  { verb: 'format', tier: 'system', id: 'shell:format', note: 'format erases a volume' },
  { verb: 'format-volume', tier: 'system', id: 'shell:format-volume', note: 'Format-Volume erases a volume' },
  { verb: 'clear-disk', tier: 'system', id: 'shell:clear-disk', note: 'Clear-Disk wipes a disk' },
  { verb: 'remove-partition', tier: 'system', id: 'shell:remove-partition', note: 'Remove-Partition deletes a partition' },
  { verb: 'vssadmin', tier: 'trash', id: 'shell:vssadmin', note: 'vssadmin deletes volume shadow copies (the last undo path)' },
  { verb: 'wbadmin', tier: 'trash', id: 'shell:wbadmin', note: 'wbadmin deletes system backups' },
  { verb: 'clear-recyclebin', tier: 'trash', id: 'shell:clear-recyclebin', note: 'Clear-RecycleBin destroys the only copy of deleted files' },
  { verb: 'cipher', tier: 'trash', id: 'shell:cipher-w', note: 'cipher /w overwrites free space, destroying recovery of deleted files' },
  { verb: 'reg', tier: 'system', id: 'shell:reg-delete', note: 'reg delete removes registry keys' },
]

/** `dd of=/dev/sda`, `> /dev/sda`, `cat x > /dev/nvme0n1`: a device write is a wipe. */
const DEVICE_WRITE_RE = /^\/dev\/(?:sd[a-z]|nvme\d+n\d+|mmcblk\d+|disk\d+|hd[a-z])$/

/**
 * Windows commands that damage the boot chain or a volume without naming a file
 * to delete. They are judged by *form*: `bcdedit /enum` only prints and stays
 * allowed, `bcdedit /delete {current} /f` is a machine that will not boot.
 *
 * Every entry answers one question — is this invocation destructive? — from the
 * lower-cased argument text. The switches are matched as words in the joined
 * line rather than as exact tokens, so a launcher that packs them into one
 * quoted argument (`Start-Process bcdedit -ArgumentList "/delete {current} /f"`)
 * is read the same way. A shell this scanner cannot be sure about is treated as
 * destructive: being told to use a different command is recoverable, a rewritten
 * boot sector is not.
 */
function commandLine(args) {
  return args.join(' ')
}

const SYSTEM_COMMANDS = [
  {
    verb: 'bcdedit',
    id: 'shell:bcdedit',
    note: 'bcdedit rewrites the boot configuration; a wrong value means the machine will not start',
    danger: args => /(?:^|\s)[/-](?:set|delete|deletevalue|create|copy|import|cleanup|setidentifier|bootsequence|displayorder|toolsdisplayorder|timeout|default|dbgsettings|hypervisorsettings|setbootmgr|bootems)(?:\s|$)/.test(commandLine(args)),
  },
  {
    verb: 'bootrec',
    id: 'shell:bootrec',
    note: 'bootrec rewrites the boot sector or the boot configuration',
    danger: args => /(?:^|\s)\/?(?:fixmbr|fixboot|rebuildbcd)(?:\s|$)/.test(commandLine(args)),
  },
  { verb: 'bcdboot', id: 'shell:bcdboot', note: 'bcdboot rewrites the boot files of a volume', danger: () => true },
  { verb: 'bootsect', id: 'shell:bootsect', note: 'bootsect rewrites the boot sector', danger: () => true },
  { verb: 'mbr2gpt', id: 'shell:mbr2gpt', note: 'mbr2gpt converts the partition table; a failure leaves the machine unbootable', danger: () => true },
  {
    verb: 'reagentc',
    id: 'shell:reagentc',
    note: 'reagentc changes or removes the Windows Recovery Environment',
    danger: args => /(?:^|\s)[/-](?:disable|enable|setreimage|setosimage|boottore|setreimageinfo)(?:\s|$)/.test(commandLine(args)),
  },
  {
    verb: 'mountvol',
    id: 'shell:mountvol',
    note: 'mountvol mounts an EFI system partition (or removes a volume mount) so its boot files become ordinary files',
    danger: args => /(?:^|\s)[/-](?:s|d|p|r|n)(?:\s|$)|\\\\[?.]\\volume\{/i.test(commandLine(args)),
  },
  {
    verb: 'fsutil',
    id: 'shell:fsutil',
    note: 'fsutil can overwrite the contents of a file or damage a volume\'s metadata',
    danger: args => /(?:^|\s)(?:setzerodata|setvaliddata|deletejournal|dismount)(?:\s|$)/.test(commandLine(args))
      || /(?:^|\s)dirty\s+set(?:\s|$)/.test(commandLine(args)),
    classifyPaths: true,
  },
]

/** Commands whose destination operand is overwritten or mirrored over. */
const COPY_VERBS = new Set(['cp', 'copy', 'copy-item', 'cpi', 'xcopy', 'robocopy', 'install'])

/** Script files this scanner is willing to read, and the dialect to read them in. */
const SCRIPT_EXTS = new Map([
  ['.ps1', 'ps'], ['.psm1', 'ps'], ['.psd1', 'ps'],
  ['.bat', 'cmd'], ['.cmd', 'cmd'],
  ['.sh', 'sh'], ['.bash', 'sh'], ['.zsh', 'sh'], ['.ksh', 'sh'], ['.dash', 'sh'],
  ['.py', 'code'], ['.pyw', 'code'], ['.js', 'code'], ['.mjs', 'code'], ['.cjs', 'code'],
  ['.rb', 'code'], ['.pl', 'code'], ['.vbs', 'code'], ['.wsf', 'code'],
])

/** Interpreters that run the script named after them. */
const SCRIPT_HOSTS = new Set([
  ...POSIX_SHELLS, ...CMD_WRAPPERS,
  'pwsh', 'powershell', 'powershell_ise', 'pwsh.exe', 'powershell.exe',
  'python', 'python2', 'python3', 'py', 'node', 'nodejs', 'deno', 'bun', 'perl', 'ruby', 'php', 'wscript', 'cscript',
])

/** A switch whose *next* token is the script to run. */
const SCRIPT_RUNNER_FLAGS = new Set(['-file', '-f', '/c', '/k', '-command', '-c', '-e', 'source', 'call', '.'])

/** Bounds: reading a script must never become a way to read a whole disk. */
const MAX_SCRIPT_BYTES = 256 * 1024
const MAX_SCRIPT_FILES = 8
const MAX_SCAN_TEXTS = 40
/** Depth of nested shell commands extracted from code payloads. */
const MAX_CODE_DEPTH = 2
/** A cheap pre-test before tokenizing a segment for script references. */
const SCRIPT_EXT_HINT = /\.(?:ps1|psm1|psd1|bat|cmd|sh|bash|zsh|ksh|dash|py|pyw|js|mjs|cjs|rb|pl|vbs|wsf)\b/i

/** Direct file-API calls inside embedded code payloads. */
const CODE_DELETE_RE = /(?:fs\.(?:rm|rmSync|unlink|unlinkSync|remove|rmdir|rmdirSync|rimraf)(?:Sync)?|fs\.promises\.(?:rm|unlink|rmdir)|os\.(?:remove|unlink|rmdir)|shutil\.rmtree|send2trash\.send2trash|pathlib\.rmtree|Path\([^)]*\)\.unlink)\s*\(\s*(['"`])([^'"`]+)\1/g

/** A literal command handed to a process API inside a code payload. */
const CODE_EXEC_RE = /(?:execSync|exec|spawnSync|spawn|execFileSync|execFile|system|popen|check_output|run)\s*\(\s*(['"`])([^'"`\n]{2,400})\1/g


/**
 * Flags whose value is a separate token that must not be read as a path.
 *
 * Keep this list small and one-directional: a wrong entry here makes a real
 * delete target invisible, which is far worse than a phantom finding. So only
 * switches whose value can never name a file belong here — numbers, durations,
 * owner names, regexes, enumerations, PowerShell preference and formatting
 * switches. Anything that can carry a path (`-Path`, `-Destination`, `-f`,
 * `-C`, `-o`, `-n`, `-d`, `-l`, `-p`) must stay out of it.
 */
const VALUE_FLAGS = new Set([
  // find-style predicates and counters: the value is a number, a name pattern or an enum.
  '-maxdepth', '-mindepth', '-mtime', '-mmin', '-atime', '-ctime', '-size', '-perm',
  '-user', '-group', '-uid', '-gid', '-newer', '-anewer', '-cnewer', '-links', '-ilinks',
  '-context', '-fstype', '-printf', '-format', '-type', '-name', '-iname', '-regex',
  // PowerShell: preference, redirection targets, encoding, colour, progress.
  '-itemtype', '-contenttype', '-erroraction', '-warningaction', '-informationaction',
  '-debugaction', '-progressaction', '-errorvariable', '-warningvariable',
  '-informationvariable', '-debugvariable', '-outvariable', '-outbuffer', '-variable',
  '-encoding', '-delimiter', '-pattern', '-style', '-mode', '-attributes',
  '-foregroundcolor', '-backgroundcolor', '-windowstyle', '-executionpolicy', '-notypeinfo',
])

/** Non-path operands that should never be classified. */
function isNoise(token) {
  if (token === undefined || token === null) return true
  const text = String(token)
  if (text === '' || text === '--' || text === ';' || text === '\\;' || text === '+' || text === '(' || text === ')') return true
  if (text === '!' || text === '{}' || text === '{};' || text === ';&' || text === ';;') return true
  if (/^\d+$/.test(text)) return true
  if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(text)) return true
  if (/^&[<>]?/.test(text)) return true
  return false
}

/**
 * Split a command line into command segments at unquoted control operators.
 * @param {string} text
 * @param {string} dialect `sh` | `ps` | `cmd`
 * @returns {string[]}
 */
export function splitSegments(text, dialect) {
  const segments = []
  let current = ''
  let quote = ''
  const chars = [...text]
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]
    const next = chars[index + 1]
    if (quote !== '') {
      current += char
      // Only POSIX treats a backslash inside quotes as an escape: in cmd and
      // PowerShell it is an ordinary path character, and consuming the next
      // character turned `"\\?\Volume{…}\EFI"` into a path with one backslash.
      if (char === '\\' && quote === '"' && dialect === 'sh' && next !== undefined) {
        current += next
        index++
        continue
      }
      if (char === '`' && quote === '"' && next !== undefined) {
        current += next
        index++
        continue
      }
      if (char === quote) quote = ''
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      current += char
      continue
    }
    // Same rule as in `tokenize`: only POSIX escapes with backslash. PowerShell
    // escapes with the backtick (handled below) and cmd with `^`. Letting `\`
    // escape here glued `$d = C:\; Remove-Item $d` into one segment, so the
    // assignment was never seen and the wipe of a whole drive passed.
    if (char === '\\' && next !== undefined && dialect !== 'cmd' && dialect !== 'ps') {
      current += char + next
      index++
      continue
    }
    if (char === '`' && dialect === 'ps' && next !== undefined) {
      current += char + next
      index++
      continue
    }
    const pair = `${char}${next ?? ''}`
    if (pair === '&&' || pair === '||' || (dialect === 'sh' && pair === '|&')) {
      segments.push(current)
      current = ''
      index++
      continue
    }
    if (char === ';' || char === '\n' || char === '|' || (dialect !== 'ps' && char === '&') || char === '\r') {
      segments.push(current)
      current = ''
      continue
    }
    current += char
  }
  segments.push(current)
  return segments.map(segment => segment.trim()).filter(segment => segment !== '')
}

/**
 * Tokenize one command segment, keeping the quoting information the callers
 * need (a quoted `"$HOME"` must still be expanded, an unquoted `*` is a glob).
 * @param {string} segment
 * @param {string} dialect
 * @returns {Array<{ text: string, raw: string, quoted: boolean }>}
 */
export function tokenize(segment, dialect) {
  const tokens = []
  let buffer = ''
  let raw = ''
  let quote = ''
  let quoted = false
  const flush = () => {
    if (buffer !== '' || raw !== '') tokens.push({ text: buffer, raw, quoted })
    buffer = ''
    raw = ''
    quoted = false
  }
  const chars = [...segment]
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]
    const next = chars[index + 1]
    if (char === ' ' || char === '\t') {
      if (quote === '' ) flush()
      else { buffer += char; raw += char }
      continue
    }
    if (quote !== '') {
      raw += char
      if (char === '\\' && quote === '"' && dialect === 'sh' && escapesNext(next)) {
        buffer += next
        raw += next
        index++
        continue
      }
      if (char === '\\' && quote === '"' && dialect === 'sh') {
        // `C:\Windows` inside quotes: a backslash before an ordinary character
        // is part of the path, not an escape of it.
        buffer += char
        continue
      }
      if (char === '`' && dialect === 'ps' && next !== undefined) {
        buffer += next
        raw += next
        index++
        continue
      }
      if (char === quote) quote = ''
      else buffer += char
      continue
    }
    if (char === '"' || char === "'") {
      quote = char
      quoted = true
      raw += char
      continue
    }
    // Only POSIX uses backslash as an escape character when unquoted. PowerShell
    // escapes with the backtick and cmd with `^`, so treating `\` as an escape in
    // those dialects swallowed the space after `Remove-Item -LiteralPath C:\` and
    // left a path with a trailing space — which no rule could then recognise.
    if (char === '\\' && dialect !== 'cmd' && dialect !== 'ps' && escapesNext(next)) {
      buffer += next
      raw += char + next
      index++
      continue
    }
    if (char === '\\' && dialect !== 'cmd') {
      // `C:\Windows\System32`: an ordinary character after a backslash means the
      // backslash is a path separator, so keep it instead of eating the next letter.
      buffer += char
      raw += char
      continue
    }
    if (char === '`' && dialect === 'ps' && next !== undefined) {
      buffer += next
      raw += char + next
      index++
      continue
    }
    if (char === '>' || char === '<' || char === '@' && dialect === 'cmd') {
      // Redirections become their own token so the caller can read their target.
      flush()
      let operator = char
      while (chars[index + 1] !== undefined && /[&>|12]/.test(chars[index + 1])) {
        operator += chars[index + 1]
        index++
      }
      tokens.push({ text: operator, raw: operator, quoted: false, redirection: true })
      continue
    }
    buffer += char
    raw += char
  }
  flush()
  return tokens
}

/** Decode a PowerShell `-EncodedCommand` payload (UTF-16LE base64, UTF-8 fallback). */
function decodeEncoded(value) {
  const text = String(value).trim()
  if (!/^[A-Za-z0-9+/=\s]+$/.test(text) || text.length < 8) return undefined
  try {
    const base64 = text.replace(/\s+/g, '')
    const bytes = Buffer.from(base64, 'base64')
    if (bytes.length % 2 === 0) {
      const utf16 = bytes.toString('utf16le')
      // UTF-16LE text has no NULs in the ASCII range other than the high byte of each char.
      if (utf16.length > 0 && !utf16.includes('\0')) return { text: utf16, encoding: 'utf16le' }
    }
    const utf8 = bytes.toString('utf8')
    if (utf8.length > 0 && !utf8.includes('\uFFFD')) return { text: utf8, encoding: 'utf8' }
    return undefined
  }
  catch {
    return undefined
  }
}

/** Derive the shell dialect from a tool or shell name. */
export function dialectFor(name) {
  const lower = String(name ?? '').toLowerCase()
  if (lower.includes('pwsh') || lower.includes('powershell')) return 'ps'
  if (lower === 'cmd' || lower === 'shell' || lower.includes('terminal') || lower.includes('console')) return 'ps'
  return 'sh'
}

/**
 * Collect the texts worth scanning: the command itself, then every nested
 * payload (`bash -c "…"`, `pwsh -Command "…"`, `-EncodedCommand …`, `xargs …`).
 */
function gatherTexts(command, dialect, limit = 24) {
  const out = [{ text: command, dialect, via: 'command' }]
  const queue = [...out]
  const seen = new Set([command])
  while (queue.length > 0 && out.length < limit) {
    const entry = queue.shift()
    for (const segment of splitSegments(entry.text, entry.dialect)) {
      for (const nested of nestedPayloads(segment, entry.dialect)) {
        if (seen.has(nested.text)) continue
        seen.add(nested.text)
        const item = { ...nested, via: `${entry.via}>${nested.via}` }
        out.push(item)
        queue.push(item)
      }
    }
  }
  return out
}

/** Nested payloads of one command segment. */
function nestedPayloads(segment, dialect) {
  const tokens = tokenize(segment, dialect)
  let index = 0
  while (index < tokens.length && isWrapper(tokens[index].text, dialect)) index++
  const verbRaw = tokens[index]?.text
  const verb = verbRaw === undefined ? '' : normalizeVerb(verbRaw, dialect)
  const payloads = []

  const pushPayload = (value, payloadDialect, via) => {
    const text = stripQuotes(String(value))
    if (text === '') return
    payloads.push({ text, dialect: payloadDialect, via })
  }

  // `-c "…"`, `-Command "…"`, `/c "…"`, `-e "…"` and the code interpreters.
  const codeFlags = POSIX_CODE.get(verb)
  if (verb === 'find' || verb === 'xargs' || verb === 'ssh') return payloads
  if (POSIX_SHELLS.has(verb) || CMD_WRAPPERS.has(verb)) {
    for (let i = index + 1; i < tokens.length; i++) {
      const token = tokens[i]
      const flag = token.text.toLowerCase()
      if (flag === '-c' || flag === '/c' || flag === '/k' || flag === '-command') {
        const value = tokens[i + 1]
        if (value !== undefined && !value.redirection) pushPayload(value.raw, verb === 'cmd' || verb === 'cmd.exe' ? 'cmd' : 'sh', flag)
      }
    }
  }
  const winFlags = WIN_CODE.get(verb)
  if (winFlags !== undefined) {
    for (let i = index + 1; i < tokens.length; i++) {
      const token = tokens[i]
      const flag = token.text.toLowerCase()
      if (winFlags.includes(flag)) {
        // PowerShell keeps a quoted -Command as one token; an unquoted one spreads,
        // so join the remainder as best effort.
        const value = tokens[i + 1]
        const rest = tokens.slice(i + 1).map(item => item.raw).join(' ')
        const candidate = value !== undefined && !value.redirection ? (value.quoted ? value.raw : rest) : rest
        pushPayload(candidate, 'ps', flag)
      }
      else if (ENCODED_FLAGS.has(flag)) {
        const decoded = decodeEncoded(tokens[i + 1]?.raw ?? '')
        if (decoded !== undefined) payloads.push({ text: decoded.text, dialect: 'ps', via: `${flag}:${decoded.encoding}` })
      }
    }
  }
  if (codeFlags !== undefined && codeFlags !== '') {
    for (let i = index + 1; i < tokens.length; i++) {
      if (tokens[i].text.toLowerCase() === codeFlags) pushPayload(tokens[i + 1]?.raw ?? '', 'sh', codeFlags)
    }
  }
  return payloads
}

function isWrapper(token, dialect) {
  const text = normalizeVerb(token, dialect)
  if (WRAPPERS.has(text)) return true
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(token)
}

/** Basename of a command word, lower-cased, without a `.exe` suffix. */
function normalizeVerb(word, dialect) {
  let text = String(word ?? '').trim()
  if (text === '') return ''
  text = text.replace(/^['"]+|['"]+$/g, '')
  const index = Math.max(text.lastIndexOf('/'), text.lastIndexOf('\\'))
  if (index >= 0) text = text.slice(index + 1)
  text = text.toLowerCase()
  if (dialect === 'ps' || dialect === 'cmd') text = text.replace(/\.(exe|cmd|bat|ps1)$/, '')
  else text = text.replace(/\.exe$/, '')
  return text
}

/**
 * Scan one shell command.
 *
 * @param {{
 *   command: string,
 *   cwd: string,
 *   dialect?: string,
 *   ctx: object,
 *   sessionRoot?: string,
 *   fs?: typeof import('node:fs'),
 *   resolveSymlinksInsideWorkspace?: boolean,
 *   protectWrites?: boolean,
 * }} options
 * @returns {{ findings: object[], notes: string[] }}
 */
export function scanCommand(options) {
  const { command, cwd, ctx, sessionRoot } = options
  const dialect = options.dialect ?? 'sh'
  const protectWrites = options.protectWrites !== false
  const scanScripts = options.scanScripts !== false
  const depth = Number.isFinite(options.depth) ? options.depth : 0
  const findings = []
  const notes = []
  if (typeof command !== 'string' || command.trim() === '') return { findings, notes }

  const texts = gatherTexts(command, dialect)
  const seenScripts = new Set()
  let scriptFiles = 0
  // `stop` lets the caller bail out as soon as the verdict cannot get any
  // stricter. A guard that denies is already at maximum severity, so a huge
  // command that hits a protected path early costs microseconds, not
  // milliseconds — which matters because this runs on the tool pipeline.
  const stopped = () => {
    if (options.stop === undefined) return false
    if (!options.stop(findings)) return false
    notes.push('stopped early: the verdict could not get stricter')
    return true
  }

  /**
   * Read one local script the command itself would run, and scan its text.
   *
   * This is the one place the plugin reads a file, and it stays narrow: a file
   * the call named, a regular file, at most 256 KiB, at most eight per command.
   * A shell script is scanned as a command line; a program file is scanned for
   * direct file-API calls and literal `exec("…")` strings. A script that cannot
   * be read is reported in the notes and is not guessed at.
   */
  const loadScript = (reference, baseCwd) => {
    if (!scanScripts || options.fs === undefined) return
    if (scriptFiles >= MAX_SCRIPT_FILES || texts.length >= MAX_SCAN_TEXTS) return
    if (typeof options.fs.readFileSync !== 'function' || typeof options.fs.statSync !== 'function') return
    const expanded = expandVariables(stripQuotes(reference), ctx)
    if (expanded.unresolved.length > 0) return
    const absolute = normalizeAbsolute(expanded.text, ctx, baseCwd)
    if (absolute === undefined || isWildcardOperand(absolute)) return
    const key = pathKey(absolute, ctx)
    if (seenScripts.has(key)) return
    const scriptDialect = SCRIPT_EXTS.get(extensionOf(key))
    if (scriptDialect === undefined) return
    let size
    try {
      const stat = options.fs.statSync(absolute)
      if (stat.isFile?.() === false) return
      size = Number(stat.size)
    }
    catch {
      return
    }
    if (!Number.isFinite(size) || size <= 0) return
    if (size > MAX_SCRIPT_BYTES) {
      seenScripts.add(key)
      notes.push(`script not read: ${absolute} is ${size} bytes (limit ${MAX_SCRIPT_BYTES})`)
      return
    }
    let text
    try {
      text = String(options.fs.readFileSync(absolute, 'utf8'))
    }
    catch {
      return
    }
    seenScripts.add(key)
    scriptFiles += 1
    notes.push(`scanned script ${absolute}`)
    if (scriptDialect === 'code') {
      findings.push(...scanCodePayload({
        code: text,
        cwd: baseCwd,
        ctx,
        sessionRoot,
        fs: options.fs,
        resolveSymlinksInsideWorkspace: options.resolveSymlinksInsideWorkspace,
        protectWrites,
        depth: depth + 1,
      }))
      return
    }
    if (texts.length < MAX_SCAN_TEXTS) texts.push({ text, dialect: scriptDialect, via: `script:${absolute}` })
  }

  for (let entryIndex = 0; entryIndex < texts.length; entryIndex++) {
    const entry = texts[entryIndex]
    if (!entry.via.startsWith('script:') && texts.length > 1) notes.push(`decoded ${entry.via}`)
    let runningCwd = cwd
    /** Literals this command assigned to its own variables, in source order. */
    const vars = new Map()
    for (const source of splitSegments(entry.text, entry.dialect)) {
      const segment = expandAssigned(source, vars, entry.dialect, notes)
      recordAssignment(segment, vars, entry.dialect)
      scanSegment({ segment, dialect: entry.dialect, cwd: runningCwd, ctx, sessionRoot, findings, notes, fs: options.fs, resolveSymlinksInsideWorkspace: options.resolveSymlinksInsideWorkspace, protectWrites })
      for (const reference of scriptReferences(segment, entry.dialect)) loadScript(reference, runningCwd)
      // `cd /etc && rm passwd` — relative operands after a cd are resolved there.
      const moved = cdTarget(segment, entry.dialect, runningCwd, ctx)
      if (moved !== undefined) runningCwd = moved
      if (stopped()) return { findings: dedupe(findings), notes }
    }
    // Direct file APIs and literal process-exec strings inside a code payload.
    findings.push(...scanCodePayload({
      code: entry.text,
      cwd: runningCwd,
      ctx,
      sessionRoot,
      fs: options.fs,
      resolveSymlinksInsideWorkspace: options.resolveSymlinksInsideWorkspace,
      protectWrites,
      depth,
    }))
    if (stopped()) return { findings: dedupe(findings), notes }
  }
  return { findings: dedupe(findings), notes }
}

/** The lower-cased extension of a path or command word. */
function extensionOf(value) {
  const text = String(value ?? '').replace(/["']/g, '')
  const dot = text.lastIndexOf('.')
  if (dot < 0 || dot < Math.max(text.lastIndexOf('/'), text.lastIndexOf('\\'))) return ''
  return text.slice(dot).toLowerCase()
}

/**
 * The script files one segment would *run* (not merely name).
 *
 * `pwsh -File .\cleanup.ps1`, `bash ./build.sh`, `python tools/release.py`,
 * `cmd /c x.bat`, `. .\profile.ps1` and `.\cleanup.ps1` all execute the file,
 * and a script written moments earlier is the cheapest way around a command-line
 * scanner. A delete, a move or a read-only command that happens to name a
 * script does not execute it, so those are left alone.
 *
 * @param {string} segment
 * @param {string} dialect
 * @returns {string[]} script references, unresolved
 */
function scriptReferences(segment, dialect) {
  // Tokenizing a megabyte-long segment only to discover it names no script at
  // all is the slowest thing this scanner could do, so look for the extension
  // first with a plain substring test.
  if (!SCRIPT_EXT_HINT.test(segment)) return []
  const tokens = tokenize(segment, dialect)
  if (tokens.length === 0) return []
  let index = 0
  while (index < tokens.length && isWrapper(tokens[index].text, dialect)) index++
  const leadToken = tokens[index]
  if (leadToken === undefined) return []
  const lead = normalizeVerb(leadToken.text, dialect)
  if (READ_ONLY_VERBS.has(lead) || isMutationVerb(lead)) return []

  const references = []
  const add = token => {
    if (token === undefined || token.redirection === true || token.text.startsWith('-')) return
    if (!SCRIPT_EXTS.has(extensionOf(token.text))) return
    if (!references.includes(token.text)) references.push(token.text)
  }
  // The command itself is a script: `.\cleanup.ps1`, `.\build.sh`.
  add(leadToken)

  if (SCRIPT_HOSTS.has(lead) || lead === '&' || lead === 'source' || lead === '.') {
    for (let i = index + 1; i < tokens.length; i++) {
      const token = tokens[i]
      const flag = token.text.toLowerCase()
      if (SCRIPT_RUNNER_FLAGS.has(flag)) {
        add(tokens[i + 1])
        i += 1
        continue
      }
      if (isSwitchToken(token.text, dialect)) continue
      // The interpreter runs the first operand that *is* a script file; the rest
      // are that script's arguments, not scripts of their own.
      if (SCRIPT_EXTS.has(extensionOf(token.text))) {
        add(token)
        break
      }
    }
  }
  return references
}

/**
 * Scan the source of a `run_code`-style call (or a program file a shell ran)
 * for file APIs and literal commands.
 *
 * A code tool is a shell in disguise: `shutil.rmtree("C:\\Windows")` never
 * reaches the shell scanner, and the generic path sweep only reads arguments
 * that look like paths. This reads the code as code — the API call pattern and a
 * literal `exec("…")` string — never as a shell word list, because `format(x)`
 * in a source file is a function call, not a volume format.
 *
 * @param {{
 *   code: string, cwd: string, ctx: object, sessionRoot?: string,
 *   fs?: Partial<typeof import('node:fs')>, resolveSymlinksInsideWorkspace?: boolean,
 *   protectWrites?: boolean, depth?: number,
 * }} options
 * @returns {object[]} findings, one per protected target
 */
export function scanCodePayload(options) {
  const { code, cwd, ctx, sessionRoot } = options
  const findings = []
  if (typeof code !== 'string' || code === '') return findings
  const depth = Number.isFinite(options.depth) ? options.depth : 0
  const shared = {
    cwd,
    ctx,
    sessionRoot,
    fs: options.fs,
    resolveSymlinksInsideWorkspace: options.resolveSymlinksInsideWorkspace,
    op: 'delete',
  }
  for (const match of code.matchAll(CODE_DELETE_RE)) {
    findings.push(...classifyOperand({ ...shared, raw: match[2], verb: match[1], via: 'code-api' }))
  }
  if (depth < MAX_CODE_DEPTH) {
    // A cheap linear pre-test: a megabyte of ordinary command text must not pay
    // for a second full regex pass that cannot match.
    if (/\b(?:exec|spawn|system|popen|check_output|run)\s*\(/.test(code)) {
      for (const match of code.matchAll(CODE_EXEC_RE)) {
        const command = match[2]
        if (command === undefined || command.trim() === '') continue
        const scanned = scanCommand({
          command,
          cwd,
          ctx,
          sessionRoot,
          dialect: 'sh',
          fs: options.fs,
          resolveSymlinksInsideWorkspace: options.resolveSymlinksInsideWorkspace,
          protectWrites: options.protectWrites !== false,
          scanScripts: false,
          depth: depth + 1,
        })
        findings.push(...scanned.findings)
      }
    }
  }
  return findings
}

/**
 * A switch token, spelled the way this dialect spells switches.
 *
 * `cd /d C:\Windows\System32` is the cmd form the field test used: the old
 * reader took `/d` for the target, moved the running directory to `C:\d`, and
 * then resolved the relative `del` against it — so a delete of a system file
 * became a delete inside a harmless directory.
 *
 * @param {string} text
 * @param {string} dialect
 */
function isSwitchToken(text, dialect) {
  if (text === '') return false
  if (text.startsWith('-')) return true
  if (dialect === 'sh') return false
  // `cmd` and PowerShell accept `/s`, `/MIR`, `/c:`; a path has another
  // separator in it, so it is never mistaken for a switch.
  return /^\/[A-Za-z][\w:.,+\-]*$/.test(text) && !text.includes('\\')
}

/**
 * Where a `cd …` / `chdir` / `pushd` segment lands, so the rest of the line
 * resolves against it.
 * @returns {string | undefined}
 */
function cdTarget(segment, dialect, cwd, ctx) {
  const tokens = tokenize(segment, dialect)
  if (tokens.length === 0) return undefined
  let index = 0
  while (index < tokens.length && isWrapper(tokens[index].text, dialect)) index++
  const verb = normalizeVerb(tokens[index]?.text ?? '', dialect)
  if (verb !== 'cd' && verb !== 'chdir' && verb !== 'pushd') return undefined
  const target = tokens.slice(index + 1).find(token => !isSwitchToken(token.text, dialect) && token.text !== '' && token.text !== '-')
  if (target === undefined) return undefined
  const expanded = expandVariables(stripQuotes(target.text), ctx)
  if (expanded.unresolved.length > 0) return undefined
  return normalizeAbsolute(expanded.text, ctx, cwd)
}

function dedupe(findings) {
  const seen = new Map()
  for (const finding of findings) {
    const key = `${finding.tier}|${finding.path}|${finding.verb}`
    if (!seen.has(key)) seen.set(key, finding)
  }
  return [...seen.values()]
}

/**
 * Verbs that only read or print. When one of these leads a segment, the rest of
 * the line is not re-searched for a mutation verb, so `echo rm -rf /etc` stays
 * an echo instead of a denial.
 */
const READ_ONLY_VERBS = new Set([
  'echo', 'printf', 'print', 'cat', 'tac', 'less', 'more', 'most', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'rg', 'ag',
  'ls', 'dir', 'll', 'tree', 'stat', 'file', 'du', 'df', 'wc', 'sort', 'uniq', 'cut', 'tr', 'md5sum', 'sha1sum', 'sha256sum',
  'which', 'whereis', 'where', 'type', 'man', 'help', 'history', 'ps', 'top', 'htop', 'free', 'uptime', 'id', 'whoami',
  'pwd', 'cd', 'set', 'export', 'alias', 'test', 'true', 'false', 'sleep', 'comment', 'date', 'hostname', 'env', 'printenv',
])

/**
 * A command that damages the machine whatever its arguments name.
 *
 * Matched **exactly**. The hyphen-prefix form was there to catch PowerShell
 * cmdlets, but every cmdlet worth naming is spelled out in `BLANKET`, and the
 * prefix rule also matched `Format-Table` against `format` — so
 * `Get-Date | Format-Table` was denied as if it erased a volume. Measured, not
 * theorised. `mkfs` is the one family with a legitimate suffix spelling
 * (`mkfs.ext4`, `mkfs.btrfs`).
 */
function blanketHit(verb) {
  return BLANKET.find(candidate => candidate.verb === verb
    || (candidate.verb === 'mkfs' && verb.startsWith('mkfs.')))
}

/** Is this verb one that can change or remove files? */
function isMutationVerb(verb) {
  if (verb === '') return false
  if (verb === 'git' || verb === 'forfiles') return true
  return POSIX_DELETE.has(verb) || WIN_DELETE.has(verb) || POSIX_MOVE.has(verb) || WIN_MOVE.has(verb)
    || WIN_WRITE.has(verb) || POSIX_TRUNCATE.has(verb) || COPY_VERBS.has(verb)
    || blanketHit(verb) !== undefined || SYSTEM_COMMANDS.some(candidate => candidate.verb === verb)
}

/**
 * A path built one step away from the command text used to pass:
 * `$p = 'C:\…\.git\config'; Remove-Item -LiteralPath $p`. Only a path written
 * out in the text was judged, so this resolves what the command *it itself*
 * assigned as a literal string.
 *
 * What it deliberately does not claim: `iex $a`, `& $p`, a value from
 * `Read-Host`, a payload fetched at runtime, or a variable set by an earlier
 * call. Text cannot be evaluated the way a shell evaluates it, and pretending
 * otherwise would be a false promise. What closes those is the file-system seam
 * for tools that go through the Host, and the sandbox for everything else.
 */
const ASSIGN_PS = /^\s*\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?\s*\+?=\s*(.*)$/
const ASSIGN_SH = /^(?:export\s+|local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/
const QUOTED_RE = /'([^'\n]*)'|"([^"\n]*)"/g
const BAREWORD_PATH_RE = /^(?:[A-Za-z]:[\\/]|[/\\])[^\s;|&`]*$|^(?:~|\.{1,2})[/\\][^\s;|&`]*$|^~$/
/** Not a value yet: composition, substitution, a prompt, a pipeline. */
const DYNAMIC_RE = /[$`|(]/

const literalValues = value => {
  const trimmed = value.trim()
  if (trimmed === '' || DYNAMIC_RE.test(trimmed)) return []
  const quoted = [...trimmed.matchAll(QUOTED_RE)]
  if (quoted.length > 0) {
    // `Read-Host 'path'` and `Join-Path $a 'b'` are calls with a quoted argument,
    // not an assignment of that string — a cmdlet name left over after stripping
    // the quotes means this right-hand side is not nothing-but-literals.
    if (trimmed.replace(QUOTED_RE, '').trim() !== '') return []
    const parts = quoted.map(match => match[1] ?? match[2] ?? '').filter(entry => entry !== '')
    return parts.length > 0 && parts.length <= 3 ? parts : []
  }
  return BAREWORD_PATH_RE.test(trimmed) ? [trimmed] : []
}

/** Note the literal a command assigns to its own variable, for later segments. */
function recordAssignment(segment, vars, dialect) {
  const match = (dialect === 'ps' ? ASSIGN_PS : ASSIGN_SH).exec(segment)
  if (match === null) return
  const values = literalValues(match[2])
  if (values.length !== 1) return
  const name = dialect === 'ps' ? match[1].toLowerCase() : match[1]
  vars.set(name, values[0])
}

/**
 * Re-quote a resolved value so the tokenizer still sees one operand.
 * Single quotes are literal in both shells. Double quotes are never used here:
 * a value ending in `\` would escape the closing quote and merge every later
 * token into one.
 */
const quoteFor = value => {
  if (!/['"]/.test(value)) return `'${value}'` // literal in both shells
  if (!/\s/.test(value)) return value // a bareword path needs no quoting
  return undefined // cannot be rebuilt safely: leave it unresolved and say so
}

/** Replace `$name` with the literal assigned earlier in the same command. */
function expandAssigned(segment, vars, dialect, notes) {
  if (vars.size === 0) return segment
  const fold = dialect === 'ps' ? (/** @param {string} name */ name) => name.toLowerCase() : (/** @param {string} name */ name) => name
  // Single quotes are literal in both shells, so `rm '$p'` names a file called `$p`.
  return segment.split(/('[^']*')/g).map((part, index) => {
    if (index % 2 === 1 || !part.includes('$')) return part
    return part.replace(/\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?/g, (whole, name) => {
      const value = vars.get(fold(name))
      if (value === undefined) return whole
      const note = `resolved $${name} = ${value} from the same command`
      if (!notes.includes(note)) notes.push(note)
      const quoted = quoteFor(value)
      return quoted ?? whole
    })
  }).join('')
}

/** One `verb …operands` command segment. */
function scanSegment({ segment, dialect, cwd, ctx, sessionRoot, findings, notes, fs, resolveSymlinksInsideWorkspace, protectWrites }) {
  const tokens = tokenize(segment, dialect)
  if (tokens.length === 0) return
  let index = 0
  while (index < tokens.length && isWrapper(tokens[index].text, dialect)) index++
  let verbToken = tokens[index]
  if (verbToken === undefined) return
  let verb = normalizeVerb(verbToken.text, dialect)
  // `sudo -u bob rm -rf /usr`: the mutation verb hides behind wrapper arguments,
  // so look further along the line unless the leader only reads.
  if (!isMutationVerb(verb) && !READ_ONLY_VERBS.has(verb)) {
    for (let j = index + 1; j < tokens.length; j++) {
      if (tokens[j].quoted === true || tokens[j].redirection === true) continue
      const candidate = normalizeVerb(tokens[j].text, dialect)
      if (isMutationVerb(candidate)) {
        const behind = normalizeVerb(tokens[index].text, dialect)
        index = j
        verbToken = tokens[j]
        verb = candidate
        notes.push(`mutation verb "${candidate}" found behind "${behind}"`)
        break
      }
    }
  }
  const args = tokens.slice(index + 1)
  const argTexts = args.map(token => token.text.toLowerCase())
  // A user may name a command as allowed (`allowCommands: [mountvol]`) because a
  // form-only finding has no path for `allowExtra` to match.
  const verbAllowed = Array.isArray(ctx.allowCommands) && ctx.allowCommands.includes(verb)

  const blanket = blanketHit(verb)
  if (blanket !== undefined && !verbAllowed) {
    findings.push({ tier: blanket.tier, id: blanket.id, verb, path: undefined, raw: verbToken.text, note: blanket.note })
  }

  // Commands that damage the boot chain or a volume's metadata without naming a
  // file to delete. They are judged by form, because the same tool is harmless
  // in its read-only form: `bcdedit /enum` prints, `bcdedit /delete` is a machine
  // that will not start.
  const systemCommand = SYSTEM_COMMANDS.find(candidate => candidate.verb === verb)
  if (systemCommand !== undefined && !verbAllowed && systemCommand.danger(argTexts)) {
    findings.push({ tier: 'system', id: systemCommand.id, verb, path: undefined, raw: verbToken.text, note: systemCommand.note })
    if (systemCommand.classifyPaths === true) {
      // The paths such a command names are being *written*, not deleted, and they
      // are named in the message like any other operand.
      for (const token of args) {
        if (token.redirection === true || isSwitchToken(token.text, dialect) || isNoise(token.text) || token.text.includes('=')) continue
        findings.push(...classifyOperand({ raw: token.text, alt: token.raw, cwd, ctx, sessionRoot, verb, via: 'operand', fs, resolveSymlinksInsideWorkspace, op: 'overwrite' }))
      }
    }
    return
  }

  const isDeleteVerb = POSIX_DELETE.has(verb) || WIN_DELETE.has(verb)
  const isMoveVerb = POSIX_MOVE.has(verb) || WIN_MOVE.has(verb)
  const isWriteVerb = protectWrites && (WIN_WRITE.has(verb) || verb === 'tee')
  const isTruncateVerb = POSIX_TRUNCATE.has(verb)

  const classify = (raw, extra = {}) => classifyOperand({ raw, cwd, ctx, sessionRoot, verb, via: extra.via ?? 'operand', fs, resolveSymlinksInsideWorkspace, ...extra })

  // Devices: `dd of=/dev/sda`, `> /dev/sda`.
  for (const token of args) {
    if (/^of=/.test(token.text)) {
      const target = token.text.slice(3)
      if (DEVICE_WRITE_RE.test(target)) findings.push({ tier: 'system', id: 'shell:device-write', verb, path: target, raw: token.raw, note: 'dd writes straight to a block device' })
      else findings.push(...classify(target, { via: 'dd of=' }))
    }
  }

  // Redirection targets are overwrites.
  if (protectWrites) {
    for (let i = 0; i < args.length; i++) {
      const token = args[i]
      if (token.redirection === true && /^[0-9]*>{1,2}/.test(token.text) && !token.text.includes('&') && !token.text.includes('|')) {
        const glued = token.text.replace(/^[0-9]*>{1,2}/, '')
        const target = glued !== '' ? glued : args[i + 1]?.text
        if (target === undefined) continue
        const lower = String(target).replace(/["']/g, '').toLowerCase()
        if (lower === '/dev/null' || lower === 'nul' || lower === '$null' || lower === 'none') continue
        if (DEVICE_WRITE_RE.test(lower)) findings.push({ tier: 'system', id: 'shell:device-write', verb, path: lower, raw: String(target), note: 'a redirect writes over a block device' })
        else findings.push(...classify(target, { via: 'redirect', op: 'overwrite' }))
      }
    }
  }

  if (verb === 'find') {
    const flags = args.map(token => token.text.toLowerCase())
    const destructive = flags.includes('-delete') || flags.some(flag => flag === '-exec' || flag === '-execdir')
    if (!destructive) return
    const deletes = flags.includes('-delete')
    const paths = []
    for (const token of args) {
      const text = token.text
      if (token.redirection === true) break
      if (text.startsWith('-') || text === '(' || text === ')' || text === '!') break
      paths.push(text)
    }
    if (paths.length === 0) paths.push('.')
    for (const value of paths) {
      findings.push(...classify(value, { via: deletes ? 'find -delete' : 'find -exec', recursive: true }))
    }
    return
  }

  if (verb === 'xargs') {
    // `xargs -0 rm -rf` — the inner command is the real verb.
    let inner = index + 1
    while (inner < tokens.length && tokens[inner].text.startsWith('-')) inner++
    if (inner >= tokens.length) return
    const innerVerb = normalizeVerb(tokens[inner].text, dialect)
    const innerSegment = `${innerVerb} ${tokens.slice(inner + 1).map(token => token.raw).join(' ')}`
    scanSegment({ segment: innerSegment, dialect, cwd, ctx, sessionRoot, findings, notes, fs, resolveSymlinksInsideWorkspace, protectWrites })
    return
  }

  if (verb === 'git') {
    const sub = normalizeVerb(args[0]?.text ?? '', dialect)
    const flags = args.map(token => token.text.toLowerCase())
    // Rewriting history or pruning the object store destroys work the user
    // cannot get back without a backup: the strict tier.
    const rewritesHistory = sub === 'filter-branch' || sub === 'filter-repo'
      || (sub === 'gc' && flags.includes('--prune=now'))
      || (sub === 'reflog' && flags.includes('--expire=now'))
      || (sub === 'prune' && flags.includes('--expire-objects'))
    if (rewritesHistory) {
      findings.push({ tier: 'versionControl', id: `shell:git-${sub}`, verb: `git ${sub}`, path: cwd, raw: `git ${sub}`, note: `git ${sub} rewrites or prunes repository history` })
      return
    }
    // Discarding the working tree loses uncommitted edits: worth a confirmation,
    // not a block, because it is a normal thing to ask an agent to do.
    const discardsWork = sub === 'clean' || sub === 'stash' && flags.includes('clear')
      || (sub === 'reset' && flags.includes('--hard'))
      || (sub === 'checkout' && (flags.includes('--') || args.some(token => token.text === '.')))
      || (sub === 'restore' && (flags.includes('--worktree') || flags.includes('.')))
    if (discardsWork) {
      findings.push({ tier: 'uncommittedWork', id: `shell:git-${sub}`, verb: `git ${sub}`, path: cwd, raw: `git ${sub}`, note: `git ${sub} discards uncommitted files` })
    }
    return
  }

  // Copy-like commands do not delete, but they do overwrite their destination.
  // `robocopy /MIR` is the dangerous one: it mirrors a source over a destination
  // and removes everything the source does not have.
  if (COPY_VERBS.has(verb)) {
    const { operands } = collectOperands(args, dialect)
    if (verb === 'robocopy') {
      const mirror = argTexts.includes('/mir') || argTexts.includes('/purge')
      const moves = argTexts.includes('/mov') || argTexts.includes('/move')
      const [source, destination] = operands
      if (mirror && destination !== undefined) {
        findings.push(...classify(destination.text, { via: 'robocopy /MIR', recursive: true, op: 'delete' }))
      }
      else if (protectWrites && destination !== undefined) {
        findings.push(...classify(destination.text, { via: 'robocopy destination', op: 'overwrite' }))
      }
      if (moves && source !== undefined) findings.push(...classify(source.text, { via: 'robocopy /MOVE source', recursive: true, op: 'delete' }))
      return
    }
    const destinationFlag = args.findIndex(token => /^-destination$/i.test(token.text))
    const destinationToken = destinationFlag >= 0 ? args[destinationFlag + 1] : operands[operands.length - 1]
    if (protectWrites && destinationToken !== undefined) {
      findings.push(...classify(destinationToken.text, { via: 'copy destination', op: 'overwrite' }))
    }
    return
  }

  if (verb === 'forfiles') {
    // `forfiles /p <dir> /c "cmd /c del @path"` runs a delete over a directory
    // that the command line never spells out as a delete operand.
    const dirIndex = argTexts.indexOf('/p')
    const base = dirIndex >= 0 && args[dirIndex + 1] !== undefined ? args[dirIndex + 1].text : '.'
    const cmdIndex = argTexts.indexOf('/c')
    const payload = cmdIndex >= 0 ? args.slice(cmdIndex + 1).map(token => token.raw).join(' ') : ''
    if (payload !== '' && /\b(?:del|erase|rd|rmdir|remove-item|rm)\b/i.test(payload)) {
      findings.push(...classify(base, { via: 'forfiles /c delete', recursive: argTexts.includes('/s'), op: 'delete' }))
    }
    if (payload !== '') {
      const nested = scanCommand({ command: payload, cwd, dialect: 'cmd', ctx, sessionRoot, fs, resolveSymlinksInsideWorkspace, protectWrites, scanScripts: false })
      findings.push(...nested.findings)
    }
    return
  }

  if (!(isDeleteVerb || isMoveVerb || isWriteVerb || isTruncateVerb)) return

  // Operand pass: skip flags, honour `--`, read the truncate/force shape.
  const { operands, recursive } = collectOperands(args, dialect)
  for (const operand of operands) {
    if (isTruncateVerb) {
      // `truncate -s 0 file` empties the file; any other size is ordinary work.
      const empty = args.some(candidate => /(^|\D)0[bskmg]?$/.test(candidate.text.toLowerCase())) || args.some(candidate => candidate.text.toLowerCase() === '--empty')
      if (!empty) continue
    }
    findings.push(...classify(operand.text, { alt: operand.raw, via: isMoveVerb ? 'move-source' : 'operand', recursive, op: isWriteVerb ? 'overwrite' : 'delete' }))
  }
}

/**
 * The non-switch operands of a segment, in source order.
 *
 * A `cmd` / PowerShell switch may be spelled `/s`, `/MIR` or `/c:`; a path is
 * never mistaken for one because it carries a second separator. Value-taking
 * switches consume their value so `New-Item -ItemType Directory` cannot conjure
 * an operand out of the word `Directory`.
 *
 * @param {Array<{ text: string, raw: string, redirection?: boolean }>} args
 * @param {string} dialect
 * @returns {{ operands: Array<{ text: string, raw: string }>, recursive: boolean }}
 */
function collectOperands(args, dialect) {
  const operands = []
  const recursiveFlags = new Set(['-r', '-rf', '-fr', '--recursive', '-recurse', '-s', '/s'])
  let afterDoubleDash = false
  let recursive = false
  for (let i = 0; i < args.length; i++) {
    const token = args[i]
    const text = token.text
    const lower = text.toLowerCase()
    if (token.redirection === true) continue
    if (!afterDoubleDash && text === '--') { afterDoubleDash = true; continue }
    if (!afterDoubleDash) {
      if (recursiveFlags.has(lower) || lower.startsWith('-r=')) recursive = true
      // Value-taking switches first: the blanket flag skip below would make this
      // check unreachable, which is how `New-Item -ItemType Directory` once
      // produced a phantom operand out of the word `Directory`.
      if (VALUE_FLAGS.has(lower)) { i += 1; continue }
      if (isSwitchToken(text, dialect)) continue
    }
    if (isNoise(text)) continue
    operands.push({ text, raw: token.raw })
  }
  return { operands, recursive }
}

/**
 * Expand, absolutize, and classify one operand string.
 * @returns {object[]} zero or one finding, plus an `indeterminate` note when a
 *   variable could not be expanded.
 */
function classifyOperand({ raw, alt, cwd, ctx, sessionRoot, verb, via, fs, resolveSymlinksInsideWorkspace, recursive, op }) {
  // Two spellings of the same operand are judged: the shell-interpreted text and
  // the verbatim source. `"\\?\C:\Windows"` unescapes to `\?\C:\Windows`, which
  // looks relative, while the source is the real extended-length path. The
  // stricter verdict wins.
  const spellings = []
  for (const value of [raw, alt]) {
    const text = String(value ?? '')
    if (text !== '' && !spellings.includes(text)) spellings.push(text)
  }

  const judged = []
  for (const spelling of spellings) {
    const original = stripQuotes(spelling)
    if (original === '' || isNoise(original)) continue
    const expanded = expandVariables(original, ctx)
    const absolute = normalizeAbsolute(expanded.text, ctx, cwd)
    if (absolute === undefined) continue

    const wildcard = isWildcardOperand(expanded.text)
    const trimmed = absolute.replace(/[/\\](?:\*{1,2}|\*\*)$/, '')
    // `rm -rf /*` deletes the contents of the root, so it must be judged *as* the
    // root: a glob is not an ancestor of any rule, so falling back to the
    // untrimmed `/*` let the widest possible wipe through. A relative `*` is left
    // as it is, resolved inside the workspace where it lives.
    let probe = trimmed
    if (probe === '') {
      const rooted = /^([A-Za-z]:[/\\]|[/\\])/.test(absolute)
      probe = !rooted ? absolute : (ctx.win ? `${absolute.slice(0, 1)}:\\` : ctx.path.sep)
    }

    let real
    if (fs !== undefined) {
      // The real target is resolved before judging, so a link, junction or mount
      // point cannot smuggle a protected path past the lexical rules. Inside the
      // workspace this is opt-in: it costs a syscall per operand.
      const insideWorkspace = sessionRoot !== undefined && isWithin(pathKey(sessionRoot, ctx), pathKey(probe, ctx), ctx)
      const wantReal = insideWorkspace ? resolveSymlinksInsideWorkspace === true : true
      if (wantReal) real = resolveExistingPath(probe, ctx, fs)
    }

    const verdict = classifyKey(probe, ctx, { sessionRoot, real, fs })
    if (verdict === undefined || verdict.tier === 'allow') continue
    judged.push({ verdict, probe, wildcard, unresolved: expanded.unresolved, original, real })
  }

  if (judged.length === 0) return []
  judged.sort((left, right) => (TIER_RANK[right.verdict.tier] ?? 0) - (TIER_RANK[left.verdict.tier] ?? 0))
  const best = judged[0]
  return [{
    tier: best.verdict.tier,
    id: best.verdict.id,
    verb,
    via,
    op: op ?? 'delete',
    raw: best.original,
    path: best.probe,
    ...(best.real === undefined ? {} : { real: best.real }),
    recursive: recursive === true || best.wildcard,
    wildcard: best.wildcard,
    unresolved: best.unresolved,
  }]
}
