/**
 * The platform facts the protection rules are derived from: environment,
 * well-known Windows/POSIX/macOS roots, and the Harness's own directories.
 *
 * The context is a plain object built by {@link createSystemContext} and is
 * injectable, so the rule tables can be unit-tested for a platform the test
 * process is not running on.
 *
 * @module system-protection/system-context
 */

import os from 'node:os'
import path from 'node:path'

import { isWithin, pathKey, readEnv } from './paths.js'

/** @param {string} platform */
export function platformFamily(platform) {
  if (platform === 'win32') return 'win32'
  if (platform === 'darwin') return 'darwin'
  return 'linux'
}

/** @param {string | undefined} value @returns {string | undefined} */
function nonEmpty(value) {
  if (typeof value !== 'string') return undefined
  const text = value.trim()
  return text === '' ? undefined : text
}

/**
 * `~` and environment-variable spellings resolved once, for a configured prefix.
 * @param {string} value @param {object} seed
 * @returns {string}
 */
function expandForCompare(value, seed) {
  let text = String(value).trim()
  if (text === '~' || text.startsWith('~/') || text.startsWith('~\\')) {
    return seed.path.join(seed.homedir, text.slice(1).replace(/^[/\\]+/, ''))
  }
  const pattern = /%([A-Za-z_][A-Za-z0-9_ ]*)%|\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g
  for (const match of text.matchAll(pattern)) {
    const name = match[1] ?? match[2] ?? match[3]
    const replacement = readEnv(seed.env, name, seed.insensitive)
    if (replacement !== undefined && replacement !== '') text = text.split(match[0]).join(replacement)
  }
  return text
}

/**
 * Build the protection context.
 *
 * @param {{
 *   platform?: string,
 *   env?: Record<string, string | undefined>,
 *   homedir?: string,
 *   cwd?: string,
 *   path?: typeof import('node:path'),
 *   harness?: { installDir?: string, profileDir?: string, homeDir?: string },
 *   selfDir?: string,
 *   protectExtra?: string[],
 *   allowExtra?: string[],
 * }} [options]
 */
export function createSystemContext(options = {}) {
  const platform = options.platform ?? process.platform
  const family = platformFamily(platform)
  const env = options.env ?? process.env
  /** Injectable for tests: the process facts this module reads about itself. */
  const runtime = options.runtime ?? process
  const homedir = options.homedir ?? os.homedir()
  // Every rule, key and join below must follow the *target* platform's rules,
  // not the host's: a Linux workspace inspected from Windows still uses `/`.
  const pathModule = options.path ?? (family === 'win32' ? path.win32 : path.posix)
  const insensitive = family === 'win32'
  const cwd = nonEmpty(options.cwd) ?? process.cwd()
  const harness = options.harness ?? {}
  const win = family === 'win32'

  const fold = value => (nonEmpty(value) === undefined ? undefined : pathKey(nonEmpty(value), { insensitive, path: pathModule }))
  const seed = { insensitive, path: pathModule, env, homedir }

  const systemRoot = fold(readEnv(env, 'SystemRoot', insensitive)) ?? (win ? fold('C:\\Windows') : undefined)
  const windir = fold(readEnv(env, 'windir', insensitive)) ?? systemRoot
  const systemDrive = win && systemRoot !== undefined ? fold(`${systemRoot.slice(0, 1)}:\\`) : undefined

  const installCandidates = [
    harness.installDir,
    nonEmpty(env.DSH_INSTALL_DIR),
    // `<install>/DeepSeek Harness.exe` (Windows) or `<app>/Contents/MacOS/<exe>` (macOS).
    nonEmpty(env.DSH_NODE_EXECUTABLE) !== undefined ? pathModule.dirname(nonEmpty(env.DSH_NODE_EXECUTABLE)) : undefined,
    // The two variables above are a favour from a launcher that knows itself. A
    // packaged desktop app needs no favour: its own executable and Electron's
    // resources directory name the install from inside the very process running
    // this plugin. Without this fallback, a machine with a clean environment had
    // no rule at all for its own application directory — measured, not theorised.
    ...runtimeAppDirs(runtime, pathModule),
  ].filter(Boolean)
  const installDirs = [...new Set(installCandidates.map(dir => pathKey(dir, { insensitive, path: pathModule })))]

  const dshHome = harness.homeDir ?? nonEmpty(env.DSH_HOME) ?? pathModule.join(homedir, '.dsh')
  const dshProfile = harness.profileDir ?? nonEmpty(env.DSH_PROFILE_DIR)
    ?? (nonEmpty(env.DSH_PROFILE) !== undefined ? pathModule.join(dshHome, 'profiles', nonEmpty(env.DSH_PROFILE)) : undefined)

  const homeKey = pathKey(homedir, { insensitive, path: pathModule })
  const parentOfHome = pathModule.dirname(homedir)

  const ctx = {
    platform,
    family,
    insensitive,
    path: pathModule,
    env,
    homedir,
    cwd,
    win,
    /** Well-known roots in comparable {@link pathKey} form; undefined when unknown. */
    roots: {
      home: homeKey,
      cwd: pathKey(cwd, { insensitive, path: pathModule }),
      dshHome: pathKey(dshHome, { insensitive, path: pathModule }),
      profileDir: fold(dshProfile),
      installDirs,
      self: fold(options.selfDir),
      systemRoot,
      windir,
      systemDrive,
      programFiles: fold(readEnv(env, 'ProgramFiles', insensitive)),
      programFilesX86: fold(readEnv(env, 'ProgramFiles(x86)', insensitive)),
      commonProgramFiles: fold(readEnv(env, 'CommonProgramFiles', insensitive)),
      programData: fold(readEnv(env, 'ProgramData', insensitive)),
      publicDir: fold(readEnv(env, 'PUBLIC', insensitive)),
      appData: fold(readEnv(env, 'APPDATA', insensitive)),
      localAppData: fold(readEnv(env, 'LOCALAPPDATA', insensitive)),
      temp: fold(readEnv(env, 'TMPDIR', insensitive) ?? readEnv(env, 'TEMP', insensitive) ?? readEnv(env, 'TMP', insensitive)) ?? fold(os.tmpdir()),
      // `C:\Users` on Windows; undefined elsewhere.
      userProfiles: win && parentOfHome !== homedir && parentOfHome !== pathModule.sep ? pathKey(parentOfHome, { insensitive, path: pathModule }) : undefined,
    },
    /** User-declared prefixes, already comparable. */
    protectExtra: (options.protectExtra ?? []).map(value => pathKey(expandForCompare(value, seed), { insensitive, path: pathModule })),
    allowExtra: (options.allowExtra ?? []).map(value => pathKey(expandForCompare(value, seed), { insensitive, path: pathModule })),
  }

  // Not a classification decision — only the plugin noticing its own situation,
  // so the startup log can say it out loud. The actual yielding lives in
  // rules.js, which lets `harness:self` step aside for the session workspace.
  const selfKey = ctx.roots.self
  ctx.selfInsideWorkspace = typeof selfKey === 'string' && selfKey !== '' && typeof ctx.roots.cwd === 'string'
    && isWithin(ctx.roots.cwd, selfKey, ctx)

  return ctx
}

/**
 * The application directory of a packaged desktop app, read from the running
 * process rather than from a launcher's kindness.
 *
 * `process.versions.electron` is what makes this safe to act on: without it,
 * `process.execPath` is whichever `node` happened to start us, and treating
 * `C:\Program Files\nodejs` or an nvm tree as "the Harness install" would turn
 * every `npm install` under it into a denial. A CLI binary carrying the
 * product's own name is the only other case worth trusting.
 *
 * @param {{ execPath?: string, resourcesPath?: string, versions?: { electron?: string } }} runtime
 * @returns {string[]} zero or more candidate install directories
 */
function runtimeAppDirs(runtime, pathModule) {
  const exec = nonEmpty(runtime?.execPath)
  if (exec === undefined) return []
  const packaged = runtime?.versions?.electron !== undefined
  if (!packaged && !/deepseek|dsh/i.test(pathModule.basename(exec))) return []
  const dirs = [pathModule.dirname(exec)]
  const resources = nonEmpty(runtime?.resourcesPath)
  if (resources !== undefined) dirs.push(resources)
  // A drive root or `/` as the "install" would protect an entire volume, which
  // is a false positive of a different class than the miss this rule closes.
  return [...new Set(dirs.map(dir => appRootOf(dir, pathModule)))]
    .filter(dir => dir !== undefined && dir !== pathModule.sep && !/^[A-Za-z]:[/\\]?$/.test(dir))
}

/** Climb from an executable or a `resources` directory to the directory that *is* the install. */
function appRootOf(dir, pathModule) {
  let at = dir
  if (at === undefined || at === '') return undefined
  // Electron:   <install>/resources            → <install>
  // macOS app:  <App>.app/Contents/Resources   → <App>.app
  //             <App>.app/Contents/MacOS/<exe> → <App>.app
  if (/^(resources|macos)$/i.test(pathModule.basename(at))) at = pathModule.dirname(at)
  if (/^contents$/i.test(pathModule.basename(at))) at = pathModule.dirname(at)
  // Climb no further: a root has no meaningful install boundary.
  return at
}
