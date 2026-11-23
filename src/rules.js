/**
 * What counts as a file whose deletion breaks something.
 *
 * Three families of tables (win32 / linux / darwin) resolve to comparable path
 * keys through {@link classifyPath}, which answers one question per target:
 * which protection *tier* it belongs to, or none.
 *
 * A tier carries no policy here. The plugin config maps each tier to
 * `deny`, `ask`, or `off`, so the tables stay a description of the machine and
 * the row's `config` stays the user's decision.
 *
 * @module system-protection/rules
 */

import { depthBelow, isVolumeOrRoot, isWithin, pathKey } from './paths.js'

/** Every tier the plugin can enforce, in the order the manual lists them. */
export const TIERS = Object.freeze([
  'system',
  'harness',
  'credentials',
  'versionControl',
  'trash',
  'homeRoot',
  'workspaceRoot',
  'userData',
  'appData',
  'secrets',
  'lockfiles',
  'uncommittedWork',
])

/** Human-readable tier names, keyed for message assembly. */
export const TIER_LABEL = Object.freeze({
  system: { en: 'operating-system file', zh: '操作系统文件' },
  harness: { en: 'DeepSeek Harness installation, profile, or session data', zh: 'DeepSeek Harness 安装目录、配置档或会话数据' },
  credentials: { en: 'credential or private-key store', zh: '凭据 / 私钥存储' },
  versionControl: { en: 'version-control history', zh: '版本控制历史（.git 等）' },
  trash: { en: 'recycle bin / shadow-copy store', zh: '回收站 / 卷影副本存储' },
  homeRoot: { en: 'user home directory root', zh: '用户主目录本身' },
  workspaceRoot: { en: 'the session workspace root or one of its ancestors', zh: '会话工作区根目录或其祖先目录' },
  userData: { en: 'user data folder (Documents, Desktop, …)', zh: '用户数据目录（文档、桌面等）' },
  appData: { en: 'application data folder', zh: '应用程序数据目录' },
  secrets: { en: 'secret file (.env, *.key, id_rsa, …)', zh: '机密文件（.env、*.key、id_rsa 等）' },
  lockfiles: { en: 'dependency lockfile', zh: '依赖锁文件' },
  uncommittedWork: { en: 'uncommitted working files', zh: '未提交的工作区改动' },
  allow: { en: 'allowlisted path', zh: '白名单路径' },
})

/** Directory names that hold version-control history. */
const VCS_DIRS = ['.git', '.svn', '.hg', '_darcs', '.bzr']
/** Directories whose whole content is a credential or a key; matched on any path segment. */
const CREDENTIAL_DIRS = ['.ssh', '.gnupg', '.aws', '.azure', '.gcloud', '.oci', '.ossutilconfig', '.aliyun']

/**
 * How much a tier is worth protecting, used only to pick the stricter of two
 * candidate verdicts for one operand. Not the enforcement order.
 */
export const TIER_RANK = Object.freeze({
  system: 9,
  harness: 8,
  credentials: 8,
  versionControl: 7,
  trash: 7,
  homeRoot: 7,
  workspaceRoot: 7,
  userData: 5,
  appData: 5,
  secrets: 5,
  uncommittedWork: 4,
  lockfiles: 2,
  allow: 0,
})

/** File names and extensions that hold secret material wherever they appear. */
const SECRET_EXACT = [
  '.npmrc', '.netrc', '.git-credentials', '.htpasswd', '.pypirc', '.dockercfg', 'authorized_keys',
  'id_rsa', 'id_dsa', 'id_ec', 'id_ecdsa', 'id_ed25519', 'id_xmss', '.pgpass',
  'credentials', 'credentials.json', 'secrets.json', 'service-account.json', 'client_secret.json',
]
const SECRET_EXTS = ['.pem', '.key', '.pfx', '.p12', '.jks', '.keystore', '.kdbx', '.pkcs12', '.asc']
const SECRET_IGNORE = ['.example', '.sample', '.template', '.dist', '.txt', '.md', '.pub']

/** Dependency lockfiles: deleting one is a classic silent regression. */
const LOCKFILES = [
  'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'bun.lock', 'npm-shrinkwrap.json',
  'composer.lock', 'cargo.lock', 'go.sum', 'poetry.lock', 'pipfile.lock', 'uv.lock', 'gemfile.lock',
  'mix.lock', 'deno.lock', 'flake.lock',
]

/** Windows boot / registry / paging files matched by name anywhere. */
const WINDOWS_FILE_NAMES = [
  'ntuser.dat', 'usrclass.dat', 'bootmgr', 'bootsect.bak', 'ntldr', 'ntdetect.com', 'io.sys',
  'msdos.sys', 'pagefile.sys', 'swapfile.sys', 'hiberfil.sys', 'autoexec.bat', 'config.sys',
  'win.ini', 'system.ini',
]

/**
 * Personal folders, registered in both spellings: a case-sensitive filesystem
 * distinguishes `Documents` from `documents`, while Windows folds both to one key.
 */
function userDataFolders(ctx, push, leaves) {
  for (const leaf of leaves) {
    const id = `userdata:${leaf.toLowerCase()}`
    for (const spelling of new Set([leaf, leaf.toLowerCase()])) {
      push('userData', pathKey(ctx.path.join(ctx.roots.home, spelling), ctx), { depth: 1, id })
    }
  }
}

/**
 * Prefix trees per family, ordered most specific first.
 * `depth` limits how far below the base the rule still matches (`undefined` =
 * any depth), which keeps "delete AppData" guarded while "delete one deep file
 * inside AppData" stays unremarkable.
 *
 * @param {ReturnType<import('./system-context.js').createSystemContext>} ctx
 */
function prefixRules(ctx) {
  const fold = value => (value === undefined || value === null ? undefined : pathKey(value, ctx))
  const drive = ctx.roots.systemDrive ?? fold('c:\\')
  const drivePrefix = drive === undefined ? undefined : (drive.endsWith('\\') || drive.endsWith('/') ? drive : `${drive}${ctx.path.sep}`)
  const below = (base, ...parts) => (base === undefined ? undefined : pathKey(parts.reduce((acc, part) => ctx.path.join(acc, part), base), ctx))

  const rules = []
  const push = (tier, key, opts = {}) => {
    if (key === undefined || key === null || key === '') return
    rules.push({ tier, key, depth: opts.depth, except: opts.except, id: opts.id ?? `${tier}:${key}` })
  }

  // The Harness itself: killing it mid-session is the worst self-inflicted wound.
  for (const dir of ctx.roots.installDirs) push('harness', dir, { id: 'harness:install' })
  push('harness', ctx.roots.self, { id: 'harness:self' })
  push('harness', ctx.roots.dshHome, { id: 'harness:home' })
  push('harness', ctx.roots.profileDir, { id: 'harness:profile' })

  if (ctx.family === 'win32') {
    const windows = ctx.roots.systemRoot ?? fold('c:\\windows')
    push('system', windows, { id: 'system:windows', except: [`${windows}\\temp`, `${windows}\\prefetch`] })
    push('system', ctx.roots.programFiles, { id: 'system:programfiles' })
    push('system', ctx.roots.programFilesX86, { id: 'system:programfilesx86' })
    push('system', ctx.roots.commonProgramFiles, { id: 'system:commonfiles' })
    push('system', ctx.roots.programData, { id: 'system:programdata', depth: 2 })
    push('system', below(ctx.roots.systemRoot, 'System32', 'config'), { id: 'system:registry' })
    for (const leaf of ['boot', 'perflogs', 'msocache', '$winreagent', 'recovery', 'efi', 'system volume information', 'documents and settings', 'inetpub']) {
      push('system', drivePrefix === undefined ? undefined : `${drivePrefix}${leaf}`, { id: `system:${leaf}` })
    }
    for (const leaf of ['default', 'default user', 'all users']) push('system', below(ctx.roots.userProfiles, leaf), { id: `system:profile-${leaf}` })
    push('trash', drivePrefix === undefined ? undefined : `${drivePrefix}$recycle.bin`, { id: 'trash:recyclebin' })
    push('system', below(ctx.roots.localAppData, 'microsoft', 'credentials'), { id: 'credentials:lsad' })
    push('system', below(ctx.roots.appData, 'microsoft', 'credentials'), { id: 'credentials:roaming' })
    push('system', below(ctx.roots.appData, 'microsoft', 'protect'), { id: 'credentials:protect' })
    push('userData', ctx.roots.publicDir, { depth: 1, id: 'userdata:public' })
    for (const leaf of ['documents', 'desktop', 'downloads', 'pictures', 'music', 'videos', 'favorites', 'links', 'saved games', 'searches', 'contacts', 'appdata']) {
      push('userData', below(ctx.roots.home, leaf), { depth: 1, id: `userdata:${leaf}` })
    }
    for (const leaf of ['onedrive', 'onedrivetemp', 'dropbox', 'google drive']) {
      push('userData', below(ctx.roots.home, leaf), { depth: 1, id: `userdata:${leaf}` })
    }
    // Depth 1 guards the folder and an application's subtree inside it; one
    // specific setting file deeper down is ordinary work and stays unremarkable.
    const appDataExcept = ctx.roots.temp === undefined ? undefined : [ctx.roots.temp]
    push('appData', ctx.roots.appData, { depth: 1, id: 'appdata:roaming', except: appDataExcept })
    push('appData', ctx.roots.localAppData, { depth: 1, id: 'appdata:local', except: appDataExcept })
    push('credentials', below(ctx.roots.home, '.ssh'), { id: 'credentials:ssh' })
    push('credentials', below(ctx.roots.home, '.gnupg'), { id: 'credentials:gnupg' })
    push('credentials', below(ctx.roots.home, '.aws'), { id: 'credentials:aws' })
    push('credentials', below(ctx.roots.home, '.azure'), { id: 'credentials:azure' })
    push('credentials', below(ctx.roots.home, '.config', 'gcloud'), { id: 'credentials:gcloud' })
    push('credentials', below(ctx.roots.home, '.docker'), { id: 'credentials:docker' })
    push('credentials', below(ctx.roots.programData, 'microsoft', 'crypto'), { id: 'credentials:crypto' })
  }
  else if (ctx.family === 'darwin') {
    for (const base of ['/system', '/library', '/usr', '/bin', '/sbin', '/private/etc', '/cores', '/dev', '/opt', '/Volumes']) {
      push('system', base, { depth: base === '/volumes' ? 1 : undefined, id: `system:${base.slice(1)}` })
    }
    push('system', below(ctx.roots.home, 'library', 'keychains'), { id: 'credentials:keychains' })
    push('appData', below(ctx.roots.home, 'library'), { depth: 1, id: 'appdata:library' })
    userDataFolders(ctx, push, ['Documents', 'Desktop', 'Downloads', 'Pictures', 'Movies', 'Music', 'Templates'])
    push('trash', below(ctx.roots.home, '.trash'), { id: 'trash:user' })
    push('credentials', below(ctx.roots.home, '.ssh'), { id: 'credentials:ssh' })
    push('credentials', below(ctx.roots.home, '.gnupg'), { id: 'credentials:gnupg' })
    push('credentials', below(ctx.roots.home, '.aws'), { id: 'credentials:aws' })
  }
  else {
    for (const base of ['/bin', '/boot', '/dev', '/etc', '/lib', '/lib32', '/lib64', '/libx32', '/sbin', '/usr', '/srv', '/opt', '/proc', '/sys', '/run']) {
      push('system', base, { id: `system:${base.slice(1)}` })
    }
    if (ctx.homedir === '/root') push('system', '/root', { depth: 0, id: 'system:root-home' })
    push('credentials', below(ctx.roots.home, '.ssh'), { id: 'credentials:ssh' })
    push('credentials', below(ctx.roots.home, '.gnupg'), { id: 'credentials:gnupg' })
    push('credentials', below(ctx.roots.home, '.aws'), { id: 'credentials:aws' })
    push('credentials', below(ctx.roots.home, '.config', 'gcloud'), { id: 'credentials:gcloud' })
    push('credentials', below(ctx.roots.home, '.docker'), { id: 'credentials:docker' })
    for (const [envName, fallback] of [['XDG_CONFIG_HOME', '.config'], ['XDG_DATA_HOME', '.local/share'], ['XDG_CACHE_HOME', '.cache']]) {
      const value = ctx.env[envName]
      push('appData', value ?? below(ctx.roots.home, ...fallback.split('/')), { depth: 1, id: `appdata:${envName}` })
    }
    userDataFolders(ctx, push, ['Documents', 'Desktop', 'Downloads', 'Pictures', 'Videos', 'Movies', 'Music', 'Templates', 'Public'])
    push('trash', below(ctx.roots.home, '.local', 'share', 'trash'), { id: 'trash:xdg' })
  }

  // User-declared prefixes behave like `system` (explicit user intent).
  for (const key of ctx.protectExtra) push('system', key, { id: 'protectExtra' })
  return rules
}

/** Built-once rule tables, keyed by context identity. */
const TABLES = new WeakMap()

/**
 * @param {ReturnType<import('./system-context.js').createSystemContext>} ctx
 * @returns {Array<{ tier: string, key: string, depth?: number, except?: string[], id: string }>}
 */
export function rulesFor(ctx) {
  const cached = TABLES.get(ctx)
  if (cached !== undefined) return cached
  const built = prefixRules(ctx)
  TABLES.set(ctx, built)
  return built
}

/** Basename tests, ordered: version control, then secrets, then lockfiles. */
function nameRules(ctx, basename) {
  const lower = ctx.insensitive ? basename.toLowerCase() : basename
  const extOf = name => {
    const dot = name.lastIndexOf('.')
    return dot <= 0 ? '' : name.slice(dot)
  }
  if (VCS_DIRS.includes(lower)) return { tier: 'versionControl', id: `vcs:${lower}` }
  if (WINDOWS_FILE_NAMES.includes(lower)) return { tier: 'system', id: `systemfile:${lower}` }
  if (LOCKFILES.includes(lower)) return { tier: 'lockfiles', id: 'lockfile' }
  if (SECRET_EXACT.includes(lower)) return { tier: 'secrets', id: `secret:${lower}` }
  const ext = extOf(lower)
  if (SECRET_EXTS.includes(ext) && !SECRET_IGNORE.some(candidate => lower.endsWith(candidate))) return { tier: 'secrets', id: `secret:${ext}` }
  if (lower === '.env' || (lower.startsWith('.env.') && !SECRET_IGNORE.some(candidate => lower.endsWith(candidate)))) return { tier: 'secrets', id: 'secret:.env' }
  if (lower.startsWith('.trash') || lower === '#recycle.bin') return { tier: 'trash', id: 'trash:name' }
  return undefined
}

/**
 * Classify one already-expanded operand.
 *
 * @param {string} absolute lexical absolute path for the target platform
 * @param {ReturnType<import('./system-context.js').createSystemContext>} ctx
 * @param {{ sessionRoot?: string, real?: string }} [extra] `sessionRoot` is the
 *   calling session's workspace root; `real` is the symlink-resolved target.
 * @returns {{ tier: string, id: string, key: string } | undefined}
 */
export function classifyPath(absolute, ctx, extra = {}) {
  const key = pathKey(absolute, ctx)
  return classifyKey(key, ctx, extra)
}

/**
 * @param {string} key comparable path key
 * @param {ReturnType<import('./system-context.js').createSystemContext>} ctx
 * @param {{ sessionRoot?: string, real?: string, allowOverride?: boolean }} [extra]
 */
export function classifyKey(input, ctx, extra = {}) {
  if (input === undefined || input === null || input === '') return undefined
  // Callers hand over a path *or* an already folded key; folding again is a
  // no-op, so neither side can silently compare mixed-case Windows paths.
  const key = pathKey(input, ctx)

  for (const allow of ctx.allowExtra) {
    if (allow !== '' && (key === allow || isWithin(allow, key, ctx))) return { tier: 'allow', id: 'allowExtra', key }
  }

  // The resolved target of a symlink is judged too, so a link cannot smuggle a
  // protected path past the lexical check.
  const realKey = extra.real === undefined ? undefined : pathKey(extra.real, ctx)
  const table = rulesFor(ctx)

  const hit = candidate => (candidate === undefined ? undefined : { ...candidate, key })
  const checkKey = (probe) => {
    if (probe === undefined) return undefined
    if (ctx.allowExtra.some(allow => allow !== '' && (probe === allow || isWithin(allow, probe, ctx)))) return { tier: 'allow', id: 'allowExtra', key: probe }

    if (isVolumeOrRoot(probe, ctx)) return { tier: 'system', id: 'system:volume-root', key: probe }
    if (ctx.roots.home !== '' && (probe === ctx.roots.home || probe === `${ctx.roots.home}${ctx.win ? '\\' : '/'}`)) {
      return { tier: 'homeRoot', id: 'home:root', key: probe }
    }
    if (ctx.family !== 'win32' && probe === '/home') return { tier: 'homeRoot', id: 'home:all', key: probe }

    const sessionRoot = extra.sessionRoot === undefined ? undefined : pathKey(extra.sessionRoot, ctx)
    if (sessionRoot !== undefined && (probe === sessionRoot || isWithin(probe, sessionRoot, ctx))) {
      return { tier: 'workspaceRoot', id: 'workspace:root-or-ancestor', key: probe }
    }

    // A tree rule outranks a name rule: `C:\Windows\System32\ntuser.dat` is the
    // system first, and `~/.ssh/id_ed25519` is the credential tree, not merely
    // a file that happens to be named like one.
    for (const rule of table) {
      // `harness:self` exists so a model cannot delete the protection plugin to
      // switch itself off. When the plugin *is* inside the session workspace — a
      // `link:` install someone is developing — that same rule would deny every
      // ordinary edit in the tree, so the developer's own tree wins. Real
      // installs stay protected: they live under the profile, covered by
      // `harness:profile`, and a plugin cannot be installed without a person.
      if (rule.id === 'harness:self' && sessionRoot !== undefined && isWithin(sessionRoot, rule.key, ctx)) continue
      if (rule.except !== undefined && rule.except.some(exceptKey => isWithin(exceptKey, probe, ctx))) continue
      const depth = depthBelow(rule.key, probe, ctx)
      if (depth < 0) continue
      if (rule.depth !== undefined && depth > rule.depth) continue
      return { tier: rule.tier, id: rule.id, key: probe }
    }

    // A history or key directory anywhere in the path protects everything below
    // it: `.git/objects/pack`, `.ssh/id_ed25519`, `.aws/config`.
    const segments = probe.split(ctx.win ? /[\\/]/ : '/').filter(part => part !== '')
    for (const segment of segments) {
      const folded = ctx.insensitive ? segment.toLowerCase() : segment
      if (VCS_DIRS.includes(folded)) return { tier: 'versionControl', id: `vcs:${folded}`, key: probe }
      if (CREDENTIAL_DIRS.includes(folded)) return { tier: 'credentials', id: `credential:${folded}`, key: probe }
    }
    const basename = segments.pop() ?? probe
    const byName = nameRules(ctx, basename)
    if (byName !== undefined) return { ...byName, key: probe }

    return undefined
  }

  const lexical = checkKey(key)
  if (lexical === undefined && realKey !== undefined) {
    const resolved = checkKey(realKey)
    return resolved === undefined ? undefined : { ...resolved, viaSymlink: true }
  }
  return hit(lexical)
}

/**
 * Is this tier one the model may never touch, whatever the config says?
 * `allowExtra` is the only escape hatch, and it is a user-authored setting.
 * @param {string} tier
 */
export function isCoreTier(tier) {
  return tier === 'system' || tier === 'harness' || tier === 'credentials'
}
