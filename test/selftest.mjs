/**
 * Self-test for the protection engine. No Harness, no network, no install:
 * `node test/selftest.mjs`
 *
 * Every case states the command or tool call, the tier it must land in, and the
 * action the default configuration must produce. A pass means the decision
 * layer agrees with the intent; it says nothing about a real session, which
 * `/system-protection test` and a live denial cover.
 *
 * Two simulated machines are used so the Windows tables are exercised on any
 * host: a Windows desktop and a Linux box.
 */

import assert from 'node:assert/strict'

import { DEFAULT_TIERS, normalizeConfig } from '../index.js'
import { decideToolCall, parsePatchTargets } from '../src/policy.js'
import { scanCommand } from '../src/shell-scan.js'
import { createSystemContext } from '../src/system-context.js'

const WIN_CWD = 'C:\\projects\\demo'
const win = createSystemContext({
  platform: 'win32',
  homedir: 'C:\\Users\\spicy',
  cwd: WIN_CWD,
  env: {
    SystemRoot: 'C:\\Windows',
    windir: 'C:\\Windows',
    USERPROFILE: 'C:\\Users\\spicy',
    HOMEDRIVE: 'C:',
    HOMEPATH: '\\Users\\spicy',
    ProgramFiles: 'C:\\Program Files',
    'ProgramFiles(x86)': 'C:\\Program Files (x86)',
    CommonProgramFiles: 'C:\\Program Files\\Common Files',
    ProgramData: 'C:\\ProgramData',
    PUBLIC: 'C:\\Users\\Public',
    APPDATA: 'C:\\Users\\spicy\\AppData\\Roaming',
    LOCALAPPDATA: 'C:\\Users\\spicy\\AppData\\Local',
    TEMP: 'C:\\Users\\spicy\\AppData\\Local\\Temp',
    TMP: 'C:\\Users\\spicy\\AppData\\Local\\Temp',
    DSH_INSTALL_DIR: 'C:\\software\\DSH\\resources\\app.asar\\dsh',
    DSH_PROFILE_DIR: 'C:\\Users\\spicy\\.dsh\\profiles\\desktop',
    DSH_NODE_EXECUTABLE: 'C:\\software\\DSH\\DeepSeek Harness.exe',
  },
})

const NIX_CWD = '/home/dev/work/app'
const nix = createSystemContext({
  platform: 'linux',
  homedir: '/home/dev',
  cwd: NIX_CWD,
  env: { HOME: '/home/dev', USER: 'dev', TMPDIR: '/tmp' },
})

let passed = 0
const failures = []

/** @param {{ platform: 'win32'|'linux', name: string, args: object, action: string, tier?: string, ctx?: object, tiers?: object, allowExtra?: string[], fs?: object, scanScripts?: boolean }} testCase */
function toolCall(testCase) {
  const base = testCase.ctx ?? (testCase.platform === 'win32' ? win : nix)
  const context = testCase.allowExtra === undefined
    ? base
    : createSystemContext({ ...snapshotOf(base), allowExtra: testCase.allowExtra })
  const decision = decideToolCall({
    name: testCase.name,
    args: testCase.args,
    ctx: context,
    sessionRoot: testCase.sessionRoot ?? base.cwd,
    fs: testCase.fs,
    tierActions: testCase.tiers ?? DEFAULT_TIERS,
    protectWrites: true,
    scanShell: true,
    scanScripts: testCase.scanScripts ?? true,
    genericPathSweep: true,
    resolveSymlinksInsideWorkspace: false,
  })
  const label = `${testCase.platform} ${testCase.name}: ${preview(testCase.args)}`
  if (decision.action !== testCase.action) {
    failures.push(`${label}\n   expected ${testCase.action}, got ${decision.action} ${JSON.stringify(decision.hits, null, 0)}`)
    return
  }
  if (testCase.tier !== undefined) {
    const hit = decision.hits.find(candidate => candidate.tier === testCase.tier)
    if (hit === undefined) {
      failures.push(`${label}\n   expected a hit in tier ${testCase.tier}, got ${decision.hits.map(hit => hit.tier).join(', ') || 'none'}`)
      return
    }
  }
  passed += 1
}

/** Rebuild a context from a live one, so allowExtra cases share the same machine. */
function snapshotOf(base) {
  return {
    platform: base.platform,
    homedir: base.homedir,
    cwd: base.cwd,
    env: base.env,
    selfDir: undefined,
    protectExtra: [],
  }
}

function preview(args) {
  const text = JSON.stringify(args)
  return text.length > 90 ? `${text.slice(0, 90)}…` : text
}

const shell = (command, extra = {}) => ({ command, ...extra })

// ── Windows: the operating system itself ────────────────────────────────────
toolCall({ platform: 'win32', name: 'bash', args: shell('rm -rf C:\\Windows\\System32'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('Remove-Item -Recurse -Force C:\\Windows'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'bash', args: shell('rm -rf "C:/Program Files/MyApp"'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'bash', args: shell('del /s /q C:\\Windows\\System32\\drivers\\etc\\hosts'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('rd /s /q C:\\Users\\Default'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'bash', args: shell('rm -rf C:\\'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('Format-Volume -DriveLetter C'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'bash', args: shell('del /q C:\\Users\\spicy\\ntuser.dat'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'bash', args: shell('vssadmin delete shadows /all'), action: 'deny', tier: 'trash' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('Clear-RecycleBin -Force'), action: 'deny', tier: 'trash' })

// ── Windows: nested payloads and code payloads ──────────────────────────────
const encoded = Buffer.from('Remove-Item -Recurse -Force C:\\Windows\\System32\\config', 'utf16le').toString('base64')
toolCall({ platform: 'win32', name: 'pwsh', args: shell(`powershell.exe -EncodedCommand ${encoded}`), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'bash', args: shell('bash -c "rm -rf C:\\\\Windows\\\\System32"'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('python -c "import shutil; shutil.rmtree(\'C:\\\\Windows\\\\System32\')"'), action: 'deny', tier: 'system' })

// ── Windows: the Harness must survive its own session ───────────────────────
toolCall({ platform: 'win32', name: 'bash', args: shell('rm -rf C:\\Users\\spicy\\.dsh\\profiles\\desktop\\sessions'), action: 'deny', tier: 'harness' })
toolCall({ platform: 'win32', name: 'bash', args: shell('rm -rf "C:\\software\\DSH"'), action: 'deny', tier: 'harness' })

// ── Linux ───────────────────────────────────────────────────────────────────
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf /etc'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf /usr/local'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf /'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('find /var/log -name "*.gz" -delete'), action: 'allow' })
toolCall({ platform: 'linux', name: 'bash', args: shell('find /usr -name "*.log" -delete'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf $HOME'), action: 'deny', tier: 'homeRoot' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf /home'), action: 'deny', tier: 'homeRoot' })
toolCall({ platform: 'linux', name: 'bash', args: shell('dd if=/dev/zero of=/dev/sda bs=1M'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf ~/.ssh'), action: 'deny', tier: 'credentials' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf /tmp/scratch'), action: 'allow' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf ./node_modules'), action: 'allow' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf .'), action: 'deny', tier: 'workspaceRoot' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf ..'), action: 'deny', tier: 'workspaceRoot' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf ../'), action: 'deny', tier: 'workspaceRoot' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf ./src'), action: 'allow' })

// ── Version control and uncommitted work ────────────────────────────────────
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf .git'), action: 'deny', tier: 'versionControl' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf /home/dev/work/app/.git/objects'), action: 'deny', tier: 'versionControl' })
toolCall({ platform: 'linux', name: 'bash', args: shell('git clean -fdx'), action: 'ask', tier: 'uncommittedWork' })
toolCall({ platform: 'linux', name: 'bash', args: shell('git reset --hard HEAD'), action: 'ask', tier: 'uncommittedWork' })

// ── Ask-tier things ────────────────────────────────────────────────────────
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -f .env'), action: 'ask', tier: 'secrets' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -f ~/.config/app/settings.json'), action: 'allow' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf ~/Documents'), action: 'ask', tier: 'userData' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('Remove-Item -Recurse -Force $env:USERPROFILE\\Documents'), action: 'ask', tier: 'userData' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('Remove-Item -Recurse -Force $env:LOCALAPPDATA\\Packages'), action: 'ask', tier: 'appData' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('Remove-Item -Recurse -Force $env:TEMP\\build'), action: 'allow' })
toolCall({ platform: 'win32', name: 'bash', args: shell('rm -rf C:\\Windows\\Temp\\logs'), action: 'allow' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -f package-lock.json'), action: 'allow' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -f secrets.pem'), action: 'ask', tier: 'secrets' })

// ── File tools, not just shells ────────────────────────────────────────────
toolCall({ platform: 'win32', name: 'write', args: { file_path: 'C:\\Windows\\System32\\drivers\\etc\\hosts', content: 'x' }, action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'write', args: { file_path: '/etc/hosts', content: 'x' }, action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'write', args: { file_path: 'src/index.js', content: 'x' }, action: 'allow' })
toolCall({ platform: 'linux', name: 'edit', args: { file_path: '~/.ssh/id_ed25519', old_string: 'a', new_string: '' }, action: 'deny', tier: 'credentials' })
toolCall({ platform: 'linux', name: 'apply_patch', args: { input: '*** Begin Patch\n*** Delete File: ../secrets/id_rsa\n*** End Patch' }, action: 'ask', tier: 'secrets' })
toolCall({ platform: 'linux', name: 'apply_patch', args: { input: '*** Begin Patch\n*** Delete File: src/index.js\n*** End Patch' }, action: 'allow' })
toolCall({ platform: 'linux', name: 'apply_patch', args: { input: '*** Begin Patch\n*** Update File: /etc/nginx/nginx.conf\n*** End Patch' }, action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'delete_file', args: { path: '/usr/bin/python3' }, action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'move', args: { source: '/etc/hosts', destination: '/tmp/hosts' }, action: 'deny', tier: 'system' })

// ── The generic sweep for tools this plugin has never seen ─────────────────
toolCall({ platform: 'linux', name: 'mcp__files__remove_path', args: { target: '/etc/passwd' }, action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'read', args: { file_path: '/etc/passwd' }, action: 'allow' })
toolCall({ platform: 'linux', name: 'grep', args: { path: '/etc', pattern: 'root' }, action: 'allow' })
toolCall({ platform: 'linux', name: 'mcp__files__write', args: { file_path: '/home/dev/docs/a.md', content: 'x' }, action: 'allow' })
toolCall({ platform: 'linux', name: 'working_directory', args: { cd: '/etc' }, action: 'allow' })

// ── Escapes the user owns ───────────────────────────────────────────────────
toolCall({ platform: 'win32', name: 'bash', args: shell('rm -rf "C:\\Program Files\\MyApp"'), action: 'allow', allowExtra: ['C:\\Program Files\\MyApp'] })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf ~/Documents'), action: 'allow', tiers: { ...DEFAULT_TIERS, userData: 'off' } })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm -rf /etc'), action: 'allow', tiers: { ...DEFAULT_TIERS, system: 'off' } })

// ── Privilege wrappers, flag forms, and nesting ────────────────────────────
toolCall({ platform: 'linux', name: 'bash', args: shell('sudo rm -rf /usr'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('sudo -u bob rm -rf /etc'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('sudo -n env FOO=1 nice -n 5 rm -rf /bin'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('echo rm -rf /etc'), action: 'allow' })
toolCall({ platform: 'linux', name: 'bash', args: shell('rm --recursive --force /etc/ssl'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('powershell -Command "Remove-Item -Recurse -Force C:\\Windows"'), action: 'deny', tier: 'system', ctx: win })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('Remove-Item -Path "C:\\Windows" -Recurse -Force'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('Remove-Item -Recurse -Force $env:SystemRoot\\System32'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'pwsh', args: shell('rm -rf -- C:\\Windows'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'bash', args: shell('del /f /s /q "\\\\?\\C:\\Windows"'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('cd /etc && rm passwd shadow'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', name: 'bash', args: shell('cmd /c "del /q C:\\Windows\\System32\\config\\SAM"'), action: 'deny', tier: 'system' })
toolCall({ platform: 'linux', name: 'bash', args: shell('git filter-branch --prune-empty'), action: 'deny', tier: 'versionControl' })
toolCall({ platform: 'linux', name: 'bash', args: shell('mv /etc/hosts /tmp/hosts'), action: 'deny', tier: 'system' })

// ── Parser units ────────────────────────────────────────────────────────────
const patch = parsePatchTargets('*** Begin Patch\n*** Add File: a.txt\n*** Update File: /etc/hosts\n*** Move to: /tmp/hosts\n*** Delete File: .git\n*** End Patch')
assert.deepEqual(
  patch.map(hit => `${hit.op}:${hit.path}`),
  // Add File is not destructive; a Move rewrites the destination and removes the source.
  ['overwrite:/etc/hosts', 'overwrite:/tmp/hosts', 'delete:/etc/hosts', 'delete:.git'],
  'patch parsing',
)
passed += 1

const scanned = scanCommand({ command: 'echo hi && rm -rf ./out; ls', cwd: NIX_CWD, ctx: nix, sessionRoot: NIX_CWD, dialect: 'sh' })
assert.deepEqual(scanned.findings, [], 'an ordinary workspace cleanup yields no findings')
passed += 1

// A symlink outside the workspace is resolved before judging.
const fakeFs = {
  existsSync: target => target === '/home/dev/mirror',
  lstatSync: () => ({ isSymbolicLink: () => true }),
  realpathSync: () => '/usr',
}
const linked = decideToolCall({
  name: 'bash',
  args: shell('rm -rf /home/dev/mirror'),
  ctx: nix,
  sessionRoot: NIX_CWD,
  fs: fakeFs,
  tierActions: DEFAULT_TIERS,
  protectWrites: true,
  scanShell: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
})
assert.equal(linked.action, 'deny')
assert.equal(linked.hits.some(hit => hit.tier === 'system'), true, 'symlinked target resolved to /usr')
passed += 1

// ── The live incident: the plugin *is* the session workspace ────────────────
// A `link:` install under development puts the plugin's own directory inside the
// workspace it protects. `harness:self` must then step aside, and a PowerShell
// switch value must never be mistaken for a path operand.
const dev = createSystemContext({ ...snapshotOf(win), selfDir: WIN_CWD })
const devDecide = command => decideToolCall({
  name: 'pwsh',
  args: { command },
  ctx: dev,
  sessionRoot: WIN_CWD,
  tierActions: DEFAULT_TIERS,
  protectWrites: true,
  scanShell: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
})

const workspaceWork = devDecide(
  'New-Item -ItemType Directory -Path .\\__dsh_allow_probe__ | Out-Null; '
  + 'Set-Content -Path .\\__dsh_allow_probe__\\f.txt -Value x -Encoding UTF8; '
  + 'Remove-Item -LiteralPath .\\__dsh_allow_probe__ -Recurse -Force',
)
assert.equal(workspaceWork.action, 'allow', `ordinary work in the workspace must pass, got ${JSON.stringify(workspaceWork.hits)}`)
assert.equal(workspaceWork.hits.some(hit => /\\directory$/i.test(String(hit.path))), false, 'the word "Directory" is not a path')
passed += 1

// ...and the protection still cannot be switched off from inside the tree.
const selfElsewhere = createSystemContext({ ...snapshotOf(win), selfDir: 'C:\\tools\\dsh-system-protection' })
for (const command of ['rm -rf "C:\\tools\\dsh-system-protection"', 'del /f /s /q C:\\tools\\dsh-system-protection\\src\\rules.js']) {
  const verdict = decideToolCall({
    name: 'pwsh',
    args: { command },
    ctx: selfElsewhere,
    sessionRoot: WIN_CWD,
    tierActions: DEFAULT_TIERS,
    protectWrites: true,
    scanShell: true,
    genericPathSweep: true,
    resolveSymlinksInsideWorkspace: false,
  })
  assert.equal(verdict.action, 'deny', `deleting the protection plugin must stay denied: ${command}`)
  passed += 1
}

// A switch value must never hide a real target. These four are the dangerous
// direction of the fix above, so each one is its own check.
for (const command of [
  'Remove-Item -LiteralPath C:\\Windows\\System32\\config -Force -Recurse',
  'Remove-Item -Path "C:\\Windows\\System32\\drivers\\etc\\hosts" -Force',
  'Set-Content -Encoding UTF8 -Path C:\\Windows\\System32\\drivers\\etc\\hosts -Value x',
  'New-Item -Type File -Path C:\\Windows\\System32\\drivers\\etc\\hosts -Force',
]) {
  const verdict = decideToolCall({
    name: 'pwsh',
    args: { command },
    ctx: win,
    sessionRoot: WIN_CWD,
    tierActions: DEFAULT_TIERS,
    protectWrites: true,
    scanShell: true,
    genericPathSweep: true,
    resolveSymlinksInsideWorkspace: false,
  })
  assert.equal(verdict.action, 'deny', `${command} must be denied`)
  passed += 1
}

// Value-taking must not be guessed for short flags: `rm -n /etc/passwd` carries
// no value, so swallowing the next token would hide a real target.
for (const command of ['rm -n /etc/passwd', 'rm -r /usr/lib', 'rm -f /etc/shadow', 'rm -v -r /usr/bin']) {
  const verdict = decideToolCall({
    name: 'bash',
    args: shell(command),
    ctx: nix,
    sessionRoot: NIX_CWD,
    tierActions: DEFAULT_TIERS,
    protectWrites: true,
    scanShell: true,
    genericPathSweep: true,
    resolveSymlinksInsideWorkspace: false,
  })
  assert.equal(verdict.action, 'deny', `${command} must be denied`)
  passed += 1
}

// ── The three field findings (2026-11-23, second machine, clean environment) ─
// Every probe below is one the tester ran against the installed plugin. They are
// pinned here so none of them can come back silently.
const decideWin = (command, context = win) => decideToolCall({
  name: 'pwsh',
  args: { command },
  ctx: context,
  sessionRoot: WIN_CWD,
  tierActions: DEFAULT_TIERS,
  protectWrites: true,
  scanShell: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
})
const decideNix = command => decideToolCall({
  name: 'bash',
  args: shell(command),
  ctx: nix,
  sessionRoot: NIX_CWD,
  tierActions: DEFAULT_TIERS,
  protectWrites: true,
  scanShell: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
})

// Finding 1 — the application directory was unprotected whenever the launcher
// exported nothing. A packaged desktop app names its own install from inside the
// process, so a clean environment can no longer mean "no rule for the app".
const cleanEnv = Object.fromEntries(Object.entries(win.env).filter(([key]) => !key.startsWith('DSH_')))
const packaged = createSystemContext({
  ...snapshotOf(win),
  env: cleanEnv,
  runtime: {
    execPath: 'D:\\DeepSeek Harness\\DeepSeek Harness.exe',
    resourcesPath: 'D:\\DeepSeek Harness\\resources',
    versions: { electron: '33.4.5' },
  },
})
assert.equal(packaged.roots.installDirs.includes('d:\\deepseek harness'), true, `installDirs: ${JSON.stringify(packaged.roots.installDirs)}`)
passed += 1
for (const command of [
  'Remove-Item \'D:\\DeepSeek Harness\\DeepSeek Harness.exe\'',
  'Remove-Item -LiteralPath "D:\\DeepSeek Harness\\resources\\app.asar"',
  'del /f /s /q "D:\\DeepSeek Harness\\resources"',
]) {
  assert.equal(decideWin(command, packaged).action, 'deny', `${command} must be denied without any DSH_* env`)
  passed += 1
}

// ...and the same inference must not fire for a plain `node`: an install dir
// inferred from the wrong executable would deny every write under it.
const cliNode = createSystemContext({
  ...snapshotOf(win),
  env: cleanEnv,
  runtime: { execPath: 'D:\\tools\\node\\node.exe', versions: {} },
})
assert.equal(decideWin('Remove-Item -Recurse -Force D:\\tools\\node\\node_modules\\npm', cliNode).action, 'allow', 'a plain node.exe must not make its whole tree the Harness install')
passed += 1

const macApp = createSystemContext({
  platform: 'darwin',
  homedir: '/Users/tester',
  cwd: '/tmp/work',
  env: { HOME: '/Users/tester' },
  runtime: {
    execPath: '/Applications/DeepSeek Harness.app/Contents/MacOS/DeepSeek Harness',
    resourcesPath: '/Applications/DeepSeek Harness.app/Contents/Resources',
    versions: { electron: '33.4.5' },
  },
})
assert.equal(decideNix('rm -rf "/Applications/DeepSeek Harness.app"').action === 'allow'
  && decideToolCall({
    name: 'bash',
    args: shell('rm -rf "/Applications/DeepSeek Harness.app"'),
    ctx: macApp,
    sessionRoot: '/tmp/work',
    tierActions: DEFAULT_TIERS,
    protectWrites: true,
    scanShell: true,
    genericPathSweep: true,
    resolveSymlinksInsideWorkspace: false,
  }).action, 'deny', 'the .app bundle, not its Contents/MacOS directory, is the install')
passed += 1

// Finding 3 — `Get-Date | Format-Table` was denied as if it erased a volume,
// because `format-table` starts with `format-`. Read-only formatters are allowed;
// the cmdlets that actually destroy a volume are still matched by full name.
for (const command of [
  'Get-Date | Format-Table',
  'Get-Process | Format-List Name',
  'Get-Service | Format-Wide',
  'Get-ChildItem . | Format-Custom',
  'Get-Date | Out-String',
]) {
  assert.equal(decideWin(command).action, 'allow', `${command} only prints`)
  passed += 1
}
assert.equal(decideWin('Format-Volume -DriveLetter D').action, 'deny', 'Format-Volume erases a volume')
passed += 1
assert.equal(decideNix('mkfs.ext4 /dev/sdb').action, 'deny', 'mkfs keeps its suffix spellings')
passed += 1

// Finding 2 — a path one assignment away from the text passed, because only a
// literal path was judged. Literals the command assigns to its own variables are
// now resolved; what a shell can build and text cannot is pinned as allowed so a
// future change to it is a decision, not a surprise.
for (const command of [
  '$p = \'C:\\Users\\spicy\\.git\\config\'; Remove-Item -LiteralPath $p',
  '$target = C:\\Windows\\System32\\drivers\\etc\\hosts; Remove-Item $target',
  '$x = "C:\\Windows\\System32\\config"; Remove-Item -Recurse -Force $x',
  '${dir} = \'C:\\Users\\spicy\\.ssh\'; Remove-Item -Recurse -Force $dir',
]) {
  assert.equal(decideWin(command).action, 'deny', `${command} hides a protected path behind a variable`)
  passed += 1
}
assert.equal(decideNix('p=/etc/passwd; rm -f $p').action, 'deny', 'a sh assignment is a literal too')
passed += 1
assert.equal(decideWin('Remove-Item -LiteralPath \'$p\'').action, 'allow', "single quotes are literal: '$p' is a file named $p")
passed += 1
// The honest gap, pinned so it stays visible in the test output.
const runtimeBuilt = decideWin('$p = Read-Host \'path\'; Remove-Item -Recurse -Force $p')
assert.equal(runtimeBuilt.action, 'allow', 'a value built at runtime cannot be read from text (documented gap)')
passed += 1
// ...and the prompt text of `Read-Host` is not the variable's value: inventing a
// resolution is worse than admitting one, because it manufactures false denials.
for (const [command, label] of [
  ['$p = Read-Host \'C:\\Windows\'; Remove-Item -Recurse -Force $p', 'Read-Host prompt text is not a value'],
  ['$f = Get-ChildItem \'C:\\Windows\\System32\\config\'; Remove-Item $f', 'a cmdlet argument is not an assignment'],
]) {
  const verdict = decideWin(command)
  assert.equal(verdict.notes?.some(note => String(note).startsWith('resolved $')), false, `${label}: ${JSON.stringify(verdict.notes)}`)
  passed += 1
}

// An app sitting directly on a drive root would otherwise make the whole volume
// "the install" — a false positive far worse than the miss it trades for.
const driveRoot = createSystemContext({
  ...snapshotOf(win),
  env: cleanEnv,
  runtime: { execPath: 'D:\\DeepSeek Harness.exe', resourcesPath: 'D:\\resources', versions: { electron: '33.4.5' } },
})
assert.equal(driveRoot.roots.installDirs.some(dir => /^d:\\?$/.test(dir)), false, `installDirs: ${JSON.stringify(driveRoot.roots.installDirs)}`)
assert.equal(decideWin('Remove-Item -Recurse -Force D:\\work\\project\\src\\index.js', driveRoot).action, 'allow', 'a drive root is never inferred as the install')
passed += 2

// The widest wipe of all, and the same shape on Windows. Both were found only by
// attacking the fixed build: `/*` used to fall back to judging the glob itself,
// and `-LiteralPath C:\` lost its operand to a backslash that PowerShell does not
// even treat as an escape.
for (const [command, decide, label] of [
  ['rm -rf /*', decideNix, 'the contents of the root are the root'],
  ['rm -rf ~/*', decideNix, 'the contents of home are home'],
  ['rm -rf /', decideNix, 'the root itself'],
  ['Remove-Item -LiteralPath C:\\ -Recurse -Force', decideWin, 'a whole volume, spelled the PowerShell way'],
  ['$d = C:\\; Remove-Item -Recurse -Force $d', decideWin, 'a volume in a variable, unquoted'],
  ['$d = \'C:\\\'; Remove-Item -Recurse -Force $d', decideWin, 'a volume in a variable, quoted'],
]) {
  assert.equal(decide(command).action, 'deny', `${label}: ${command}`)
  passed += 1
}
// The fallback above must not over-reach: a glob in the workspace is still a glob.
for (const command of ['rm -rf ./out/*', 'rm -rf build/*']) {
  assert.equal(decideNix(command).action, 'allow', `${command} is workspace cleanup`)
  passed += 1
}
for (const command of ['Remove-Item .\\dist\\*', 'Remove-Item -Recurse -Force .\\node_modules\\*']) {
  assert.equal(decideWin(command).action, 'allow', `${command} is workspace cleanup`)
  passed += 1
}

// ── The 2026-11-25 evaluation report: every finding pinned ──────────────────
// The report was written against 1.0.0 by attacking the *installed* plugin on a
// UEFI machine. Each probe below is one of its findings; a pass means the finding
// cannot come back without a test failing.

/** A tiny in-memory file system: enough for 8.3 names, drive aliases and scripts. */
function virtualFs(entries) {
  const files = new Map(Object.entries(entries).map(([key, value]) => [key.toLowerCase(), value]))
  const exists = (target) => {
    const lower = String(target).toLowerCase()
    if (files.has(lower)) return true
    const head = lower.endsWith('\\') ? lower : `${lower}\\`
    return [...files.keys()].some(key => key.startsWith(head))
  }
  const real = (target) => {
    const entry = files.get(String(target).toLowerCase())
    return entry?.alias ?? String(target)
  }
  const fsx = {
    existsSync: exists,
    statSync: (target) => {
      const entry = files.get(String(target).toLowerCase())
      if (entry === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return { isFile: () => entry.text !== undefined, size: entry.text === undefined ? 0 : Buffer.byteLength(entry.text) }
    },
    readFileSync: (target) => {
      const entry = files.get(String(target).toLowerCase())
      if (entry === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return entry.text ?? ''
    },
    lstatSync: () => ({ isSymbolicLink: () => false }),
  }
  fsx.realpathSync = Object.assign(real, { native: real })
  return fsx
}

const reportCtx = createSystemContext({ ...snapshotOf(win), hostname: 'testpc' })
const reportFs = virtualFs({
  'c:\\': { dir: true },
  'c:\\windows': { dir: true },
  'c:\\windows\\system32': { dir: true },
  'c:\\program files': { dir: true },
  'c:\\progra~1': { alias: 'C:\\Program Files' },
  'c:\\x': { dir: true },
  'c:\\x\\system32\\drivers\\etc\\hosts': { text: 'x', alias: 'C:\\Windows\\System32\\drivers\\etc\\hosts' },
  'x:\\': { alias: 'C:\\Windows' },
  'c:\\work': { dir: true },
  'c:\\work\\cleanup.ps1': { text: 'Remove-Item -Recurse -Force C:\\Windows\\System32\\config\n' },
  'c:\\work\\build.ps1': { text: 'Write-Host "building"\nRemove-Item -Recurse -Force .\\dist\n' },
  'c:\\work\\cleanup.bat': { text: 'del /f /s /q C:\\Windows\\System32\\drivers\\etc\\hosts\n' },
})

const decideReport = (name, args) => decideToolCall({
  name,
  args: typeof args === 'string' ? { command: args } : args,
  ctx: reportCtx,
  sessionRoot: WIN_CWD,
  fs: reportFs,
  tierActions: DEFAULT_TIERS,
  protectWrites: true,
  scanShell: true,
  scanScripts: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
})

for (const [label, command] of [
  // P1: boot configuration and partition commands name no file to delete.
  ['bcdedit /delete', 'bcdedit /delete {current} /f'],
  ['bcdedit /set device', 'bcdedit /set {default} device unknown'],
  ['bcdedit /set path', 'bcdedit /set {default} path \\nonexistent'],
  ['mbr2gpt', 'mbr2gpt /convert /allowFullOS'],
  ['bootrec /fixmbr', 'bootrec /fixmbr'],
  ['bootrec /fixboot', 'bootrec /fixboot'],
  ['reagentc /disable', 'reagentc /disable'],
  ['bcdboot', 'bcdboot C:\\Windows /s S: /f UEFI'],
  ['bootsect', 'bootsect /nt60 SYS'],
  ['mountvol /S', 'mountvol S: /S'],
  ['mountvol volume spec', 'mountvol S: \\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\'],
  ['switches packed into one argument', "Start-Process bcdedit -ArgumentList '/delete {current} /f'"],
  ['mountvol behind Start-Process', "Start-Process mountvol -ArgumentList 'S: /S'"],
]) {
  const verdict = decideReport('pwsh', command)
  if (verdict.action !== 'deny' || !verdict.hits.some(hit => hit.tier === 'system')) failures.push(`report P1 ${label}: ${verdict.action} ${JSON.stringify(verdict.hits)}`)
  else passed += 1
}

// P2: `fsutil file setzerodata` rewrites a system file's contents.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('fsutil file setzerodata offset=0 length=4096 C:\\Windows\\System32\\ntoskrnl.exe'), action: 'deny', tier: 'system' })

// P3: an EFI system partition reached through its volume GUID.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('del /f /q "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\EFI\\Microsoft\\Boot\\BCD"'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('rm -rf "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\EFI"'), action: 'deny', tier: 'system' })

// P4: the same partition after `mountvol S: /S` gives it the letter S:.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'bash', args: shell('del /f /q S:\\EFI\\Microsoft\\Boot\\BCD'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'bash', args: shell('rm -rf S:\\EFI'), action: 'deny', tier: 'system' })

// P5: `cd /d … && del <relative>` inside cmd /c.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('cmd /c "cd /d C:\\Windows\\System32 && del __dsh_probe_nonexistent_7f3a__.dll & echo BYPASS_CONFIRMED"'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'bash', args: shell('cmd /c "cd /d C:\\Windows\\System32 && del __dsh_probe_nonexistent_7f3a__.dll"'), action: 'deny', tier: 'system' })

// P6: an 8.3 short name is the same directory as its long name.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('cmd /c "del C:\\PROGRA~1\\__dsh_probe_nonexistent_7f3a__.txt & echo BYPASS_SHORTNAME"'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'write', args: { file_path: 'C:\\PROGRA~1\\__dsh_probe_nonexistent_7f3a__.txt', content: 'x' }, action: 'deny', tier: 'system' })

// P7: this machine's administrative shares are the local volumes.
for (const command of [
  'del /f /q \\\\localhost\\C$\\Windows\\System32\\drivers\\etc\\hosts',
  'del /f /q \\\\TESTPC\\C$\\Windows\\System32\\drivers\\etc\\hosts',
  'del /f /q \\\\localhost\\ADMIN$\\System32\\drivers\\etc\\hosts',
  'del /f /q \\\\?\\UNC\\localhost\\C$\\Windows\\System32\\drivers\\etc\\hosts',
]) {
  toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell(command), action: 'deny', tier: 'system' })
}
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'write', args: { file_path: '\\\\localhost\\C$\\Windows\\__probe__.txt', content: 'x' }, action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('del /f /q \\\\other-pc\\C$\\Windows\\System32\\drivers\\etc\\hosts'), action: 'allow' })

// P8: a `subst` drive letter — and a junction — point at the same volume.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('del X:\\System32\\drivers\\etc\\hosts'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'write', args: { file_path: 'C:\\x\\System32\\drivers\\etc\\hosts', content: 'x' }, action: 'deny', tier: 'system' })

// P9: a script is read (bounded) and scanned before it runs.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('pwsh -File C:\\work\\cleanup.ps1'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('. C:\\work\\cleanup.ps1'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('cmd /c C:\\work\\cleanup.bat'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('pwsh -File C:\\work\\build.ps1'), action: 'allow' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('pwsh -File C:\\work\\cleanup.ps1'), action: 'allow', scanScripts: false })

// P10: mirroring and batch deletion are deletes even though the verb is not `del`.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('robocopy C:\\empty C:\\Windows /MIR /NFL /NDL'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('forfiles /p C:\\Windows\\System32\\drivers\\etc /c "cmd /c del @path"'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('robocopy C:\\src D:\\backup /MIR'), action: 'allow' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('forfiles /p .\\out /c "cmd /c echo @file"'), action: 'allow' })

// P12: a protection component that cannot make up its mind must say no.
const quietLog = { warn: () => {}, info: () => {} }
assert.equal(normalizeConfig({}, quietLog).onInternalError, 'closed', 'onInternalError must default to closed')
passed += 1
assert.equal(normalizeConfig({ onInternalError: 'nonsense' }, quietLog).onInternalError, 'closed', 'a bad value must keep the strict default')
passed += 1

// The fixes above must not turn ordinary work into a denial.
for (const [label, command] of [
  ['bcdedit /enum', 'bcdedit /enum'],
  ['bootrec /scanos', 'bootrec /scanos'],
  ['reagentc /info', 'reagentc /info'],
  ['mountvol list', 'mountvol'],
  ['mountvol drive list', 'mountvol C: /L'],
  ['fsutil volume diskfree', 'fsutil volume diskfree C:'],
  ['robocopy without mirror', 'robocopy C:\\empty D:\\backup /E'],
  ['cp into dist', 'cp .\\app.exe .\\dist\\'],
  ['cd /d workspace', 'cmd /c "cd /d C:\\projects\\demo && del out.txt"'],
  ['delete a script', 'rm -f C:\\work\\cleanup.ps1'],
  ['list a script', 'ls C:\\work\\cleanup.ps1'],
]) {
  const verdict = decideReport('pwsh', command)
  if (verdict.action !== 'allow') failures.push(`report control ${label}: expected allow, got ${verdict.action} ${JSON.stringify(verdict.hits)}`)
  else passed += 1
}

// A form-only denial has no path for `allowExtra` to match, so the user gets one
// explicit switch for the command itself.
const allowMountvol = createSystemContext({ ...snapshotOf(reportCtx), allowCommands: ['mountvol'] })
const mountvolAllowed = decideToolCall({
  name: 'pwsh',
  args: shell('mountvol S: /S'),
  ctx: allowMountvol,
  sessionRoot: WIN_CWD,
  fs: reportFs,
  tierActions: DEFAULT_TIERS,
  protectWrites: true,
  scanShell: true,
  scanScripts: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
})
assert.equal(mountvolAllowed.action, 'allow', `allowCommands: ${JSON.stringify(mountvolAllowed.hits)}`)
passed += 1

// ── 1.2.0: the second evaluation (workspace inside the install root) ────────
// The portable layout puts `workspace` next to the application executable. Every
// write there used to be judged `harness:install` — the plugin refused to produce
// any file at all, which is breakage, not protection.
const nestedCtx = createSystemContext({
  platform: 'win32',
  homedir: 'C:\\Users\\tester',
  cwd: 'D:\\DeepSeek Harness\\workspace',
  env: {
    SystemRoot: 'C:\\Windows',
    USERPROFILE: 'C:\\Users\\tester',
    DSH_INSTALL_DIR: 'D:\\DeepSeek Harness',
    DSH_NODE_EXECUTABLE: 'D:\\DeepSeek Harness\\DeepSeek Harness.exe',
    DSH_PROFILE_DIR: 'C:\\Users\\tester\\.dsh\\profiles\\desktop',
  },
})
const nestedFs = virtualFs({
  'd:\\': { dir: true },
  'd:\\deepseek harness': { dir: true },
  'd:\\deepseek harness\\workspace': { dir: true },
  'd:\\deepseek harness\\resources': { dir: true },
  // A junction planted inside the workspace, pointing at the install tree.
  'd:\\deepseek harness\\workspace\\link': { dir: true, alias: 'D:\\DeepSeek Harness\\resources' },
})
const decideNested = (name, args) => decideToolCall({
  name,
  args: typeof args === 'string' ? { command: args } : args,
  ctx: nestedCtx,
  sessionRoot: nestedCtx.cwd,
  fs: nestedFs,
  tierActions: DEFAULT_TIERS,
  protectWrites: true,
  scanShell: true,
  scanScripts: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
})

for (const [label, name, args, expect, tier] of [
  ['write inside the portable workspace', 'write', { file_path: 'D:\\DeepSeek Harness\\workspace\\probe.txt', content: 'x' }, 'allow'],
  ['delete inside the portable workspace', 'pwsh', "Remove-Item -Recurse -Force 'D:\\DeepSeek Harness\\workspace\\probe'", 'allow'],
  ['write the application executable', 'write', { file_path: 'D:\\DeepSeek Harness\\DeepSeek Harness.exe', content: 'x' }, 'deny', 'harness'],
  ['write resources', 'write', { file_path: 'D:\\DeepSeek Harness\\resources\\app.asar', content: 'x' }, 'deny', 'harness'],
  ['delete the workspace root itself', 'pwsh', "Remove-Item -Recurse -Force 'D:\\DeepSeek Harness\\workspace'", 'deny', 'workspaceRoot'],
  ['delete the install root', 'pwsh', "Remove-Item -Recurse -Force 'D:\\DeepSeek Harness'", 'deny'],
  ['junction out of the workspace', 'write', { file_path: 'D:\\DeepSeek Harness\\workspace\\link\\new.txt', content: 'x' }, 'deny', 'harness'],
]) {
  const verdict = decideNested(name, args)
  if (verdict.action !== expect || (tier !== undefined && !verdict.hits.some(hit => hit.tier === tier))) {
    failures.push(`nested layout ${label}: expected ${expect}${tier === undefined ? '' : ` ${tier}`}, got ${verdict.action} ${JSON.stringify(verdict.hits)}`)
  }
  else passed += 1
}

// A context that merely *simulates* another platform must not inherit the host
// executable: doing so turned the simulated Linux install root into `/` and made
// the bundled suites fail on a Desktop runtime. An explicit runtime still wins.
const simulatedNix = createSystemContext({ platform: 'linux', homedir: '/home/dev', cwd: '/home/dev/work/app', env: { HOME: '/home/dev' } })
if (process.platform === 'win32') assert.deepEqual(simulatedNix.roots.installDirs, [], `simulated linux installDirs: ${JSON.stringify(simulatedNix.roots.installDirs)}`)
assert.deepEqual(createSystemContext({ platform: 'linux', homedir: '/home/dev', cwd: '/home/dev/work/app', env: { HOME: '/home/dev' }, runtime: { execPath: '/opt/DeepSeek Harness/resources/app', resourcesPath: '/opt/DeepSeek Harness/resources', versions: { electron: '33' } } }).roots.installDirs.includes('/opt/DeepSeek Harness'), true)
passed += 2

// ── 1.2.0: false positives found while producing that report ────────────────
// PowerShell expressions are not paths. These all delete or read workspace
// content and must run; none of them hides a protected target.
for (const [label, command] of [
  ['pipeline variable', "Get-ChildItem -Recurse | Where-Object { $_.Name -like '*.tmp' } | Remove-Item"],
  ['array literal', "Remove-Item -Recurse -Force @('build','dist')"],
  ['parenthesised expression', 'Remove-Item (Get-Item .\\build).FullName'],
  ['computed path with a variable', 'Get-ChildItem .\\out | Remove-Item -Force'],
  ['a code snippet that is only printed', 'echo "fs.rmSync(\'C:/Windows/System32/x.dll\')"'],
  ['a -WhatIf preview of a delete', 'Remove-Item -Recurse -Force C:\\Windows -WhatIf'],
  ['a -WhatIf preview of a pipeline', 'Get-ChildItem C:\\Windows -Recurse | Remove-Item -WhatIf'],
]) {
  const verdict = decideReport('pwsh', command)
  if (verdict.action !== 'allow') failures.push(`false positive ${label}: expected allow, got ${verdict.action} ${JSON.stringify(verdict.hits)}`)
  else passed += 1
}

// A harmless .ps1 whose body only *names* things must not be denied.
const harmlessFs = virtualFs({
  'c:\\': { dir: true },
  'c:\\windows': { dir: true },
  'c:\\windows\\system32': { dir: true },
  'c:\\projects\\demo': { dir: true },
  'c:\\projects\\demo\\cleanup.ps1': {
    text: "# rm -rf C:\\Windows\\System32\n# del C:\\Windows\\System32\\config\nWrite-Output 'workspace file'\nCopy-Item 'workspace file' 'copy of workspace file'\n",
  },
})
toolCall({ platform: 'win32', ctx: reportCtx, fs: harmlessFs, name: 'pwsh', args: shell('pwsh -File C:\\projects\\demo\\cleanup.ps1'), action: 'allow' })

// ── 1.2.0: bypasses from the second report ─────────────────────────────────
for (const [label, command, expect, tier] of [
  // .NET file APIs are shell verbs in disguise.
  ['dotnet delete', "[System.IO.File]::Delete('C:\\Windows\\System32\\__dsh_sp_probe_nonexistent__.dll')", 'deny', 'system'],
  ['dotnet directory delete', "[System.IO.Directory]::Delete('C:\\Windows\\System32', $true)", 'deny', 'system'],
  ['dotnet write', "[System.IO.File]::WriteAllText('C:\\Windows\\__dsh_sp_probe_nonexistent__.txt', 'x')", 'deny', 'system'],
  ['dotnet short class name', "[IO.File]::Delete('C:\\Windows\\System32\\__dsh_sp_probe_nonexistent__.dll')", 'deny', 'system'],
  // The same call in a documentation string is not a call.
  ['dotnet documented in a string', "Write-Host '[System.IO.File]::Delete(\"C:\\Windows\\x.dll\")'", 'allow'],
  // Clear-Content empties a file without deleting it.
  ['clear-content system file', 'Clear-Content C:\\Windows\\System32\\drivers\\etc\\hosts', 'deny', 'system'],
  ['clear-content workspace file', 'Clear-Content .\\out\\notes.txt', 'allow'],
  // Start-Process hides the real command in -ArgumentList.
  ['start-process cmd', "Start-Process cmd -ArgumentList '/c del C:\\Windows\\System32\\__dsh_sp_probe_nonexistent__.dll'", 'deny', 'system'],
  ['start-process harmless', "Start-Process notepad -ArgumentList 'C:\\Windows\\win.ini'", 'allow'],
  // Raw-string prefixes and require('fs') hid the target from the code scanner.
  ['python raw string', "python -c \"import shutil; shutil.rmtree(r'C:/Windows/System32/config')\"", 'deny', 'system'],
  ['node require fs', "node -e \"require('fs').rmSync('C:/Windows/System32/__dsh_sp_probe_nonexistent__.dll')\"", 'deny', 'system'],
  ['fsutil createnew', 'fsutil file createnew C:\\Windows\\System32\\__dsh_sp_probe_nonexistent__ 1024', 'deny', 'system'],
  ['fsutil createnew workspace', 'fsutil file createnew .\\out\\data.bin 1024', 'allow'],
]) {
  const verdict = decideReport('pwsh', command)
  if (verdict.action !== expect || (tier !== undefined && !verdict.hits.some(hit => hit.tier === tier))) {
    failures.push(`${label}: expected ${expect}${tier === undefined ? '' : ` ${tier}`}, got ${verdict.action} ${JSON.stringify(verdict.hits)}`)
  }
  else passed += 1
}

// A .py whose content uses a raw string is still a deletion.
const evilPy = virtualFs({
  'c:\\': { dir: true },
  'c:\\windows': { dir: true },
  'c:\\windows\\system32': { dir: true },
  'c:\\projects\\demo': { dir: true },
  'c:\\projects\\demo\\evil.py': { text: "import shutil\nshutil.rmtree(r'C:/Windows/System32/config')\n" },
})
toolCall({ platform: 'win32', ctx: reportCtx, fs: evilPy, name: 'python', args: { code: 'print(1)' }, action: 'allow' })
const pyScript = decideToolCall({
  name: 'pwsh',
  args: shell('python C:\\projects\\demo\\evil.py'),
  ctx: reportCtx,
  sessionRoot: WIN_CWD,
  fs: evilPy,
  tierActions: DEFAULT_TIERS,
  protectWrites: true,
  scanShell: true,
  scanScripts: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
})
assert.equal(pyScript.action, 'deny', `raw-string script target: ${JSON.stringify(pyScript.hits)}`)
passed += 1

// `git -C <repo> …` names the repository before the subcommand.
for (const [command, expect, tier] of [
  ['git -C D:\\projects\\app checkout .', 'ask', 'uncommittedWork'],
  ['git -C D:\\projects\\app reset --hard', 'ask', 'uncommittedWork'],
  ['git -C D:\\projects\\app filter-branch --prune-empty', 'deny', 'versionControl'],
  ['git -C D:\\projects\\app status', 'allow'],
]) {
  const verdict = decideReport('pwsh', command)
  if (verdict.action !== expect || (tier !== undefined && !verdict.hits.some(hit => hit.tier === tier))) {
    failures.push(`git -C ${command}: expected ${expect}, got ${verdict.action} ${JSON.stringify(verdict.hits)}`)
  }
  else passed += 1
}

// A command that decodes base64 and evaluates it is a shell in two steps.
const hidden = Buffer.from('Remove-Item -Recurse -Force C:\\Windows\\System32\\config', 'utf8').toString('base64')
toolCall({
  platform: 'win32',
  ctx: reportCtx,
  fs: reportFs,
  name: 'pwsh',
  args: shell(`$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${hidden}')); Invoke-Expression $c`),
  action: 'deny',
  tier: 'system',
})
// …but decoding data without evaluating it stays ordinary work.
assert.equal(decideReport('pwsh', `$bytes = [Convert]::FromBase64String('${hidden}')`).action, 'allow')
passed += 1

// …but the switch is not a bypass: cmd's own del.exe has no -WhatIf.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('del.exe C:\\Windows\\System32\\config\\SAM -WhatIf'), action: 'deny', tier: 'system' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('cmd /c "del C:\\Windows\\System32\\config\\SAM -WhatIf"'), action: 'deny', tier: 'system' })

// A delete with no operand removes what the previous segment listed.
for (const [label, command, expect, tier] of [
  ['pipeline wipe of the system tree', 'Get-ChildItem C:\\Windows -Recurse | Remove-Item -Force', 'deny', 'system'],
  ['pipeline wipe of a workspace folder', 'Get-ChildItem .\\out -Recurse | Remove-Item -Force', 'allow'],
  ['pipeline into a formatter', 'Get-ChildItem C:\\Windows | Select-Object Name', 'allow'],
  ['adjacent but unrelated commands', 'dir C:\\Windows; Remove-Item $later', 'allow'],
]) {
  const verdict = decideReport('pwsh', command)
  if (verdict.action !== expect || (tier !== undefined && !verdict.hits.some(hit => hit.tier === tier))) {
    failures.push(`${label}: expected ${expect}, got ${verdict.action} ${JSON.stringify(verdict.hits)}`)
  }
  else passed += 1
}

// ── 1.3.0: raw device namespace, format.com, schtasks, and one false positive ─
// R1: `\\?\GLOBALROOT\Device\HarddiskVolumeN\…` addresses the same bytes as a
// drive letter, without one.
for (const [label, name, args] of [
  ['globalroot delete', 'pwsh', shell('del "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\Windows\\System32\\drivers\\etc\\hosts"')],
  ['globalroot write', 'write', { file_path: '\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\Windows\\__dsh_sp_probe_nonexistent__.txt', content: 'x' }],
  ['device delete', 'pwsh', shell('del \\Device\\HarddiskVolume2\\Windows\\System32\\config\\SAM')],
  ['drive-device delete', 'pwsh', shell('del \\\\.\\HarddiskVolume1\\Windows\\System32\\config\\SAM')],
  ['shadow copy delete', 'pwsh', shell('del "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM"')],
]) {
  const decision = decideToolCall({
    name,
    args,
    ctx: reportCtx,
    sessionRoot: WIN_CWD,
    fs: reportFs,
    tierActions: DEFAULT_TIERS,
    protectWrites: true,
    scanShell: true,
    scanScripts: true,
    genericPathSweep: true,
    resolveSymlinksInsideWorkspace: false,
  })
  if (decision.action !== 'deny' || !decision.hits.some(hit => hit.tier === 'system')) {
    failures.push(`R1 ${label}: expected deny system, got ${decision.action} ${JSON.stringify(decision.hits)}`)
  }
  else passed += 1
}

// R2: format.com is the real format program.
for (const [label, command] of [
  ['format.com', 'format.com C:'],
  ['format.exe', 'format.exe C:'],
  ['system32 format.com', 'C:\\Windows\\System32\\format.com C:'],
  ['format.com behind Start-Process', 'Start-Process format.com C:'],
]) {
  const decision = decideReport('pwsh', command)
  if (decision.action !== 'deny' || !decision.hits.some(hit => hit.tier === 'system')) {
    failures.push(`R2 ${label}: expected deny system, got ${decision.action} ${JSON.stringify(decision.hits)}`)
  }
  else passed += 1
}

// R3: the action of a scheduled task runs later, so its payload is scanned now.
for (const [label, command, expect, tier] of [
  ['schtasks quoted action', 'schtasks /create /tn probe /tr "cmd /c del C:\\Windows\\System32\\drivers\\etc\\hosts" /sc once /st 23:59', 'deny', 'system'],
  ['schtasks unquoted action', 'schtasks /create /tn probe /tr cmd /c del C:\\Windows\\System32\\config\\SAM /sc once', 'deny', 'system'],
  ['schtasks benign query', 'schtasks /query /tn probe', 'allow'],
  ['schtasks benign action', 'schtasks /create /tn backup /tr "cmd /c robocopy C:\\src D:\\backup /MIR" /sc daily', 'allow'],
  ['schtasks action is a hostile script', 'schtasks /create /tn probe /tr "C:\\work\\cleanup.ps1" /sc once', 'deny', 'system'],
]) {
  const decision = decideReport('pwsh', command)
  if (decision.action !== expect || (tier !== undefined && !decision.hits.some(hit => hit.tier === tier))) {
    failures.push(`R3 ${label}: expected ${expect}${tier === undefined ? '' : ` ${tier}`}, got ${decision.action} ${JSON.stringify(decision.hits)}`)
  }
  else passed += 1
}

// False positive: a dangerous command *named* in output or in a file is not run.
for (const [label, command] of [
  ['bcdedit named in Write-Output', 'Write-Output "bcdedit /delete {current} /f"'],
  ['bcdedit named in a file value', "Set-Content -Path .\\notes.txt -Value 'bcdedit /delete {current} /f'"],
  ['bcdedit named in cmd /c echo', 'cmd /c echo bcdedit /set foo'],
]) {
  const decision = decideReport('pwsh', command)
  if (decision.action !== 'allow') failures.push(`false positive ${label}: expected allow, got ${decision.action} ${JSON.stringify(decision.hits)}`)
  else passed += 1
}
// …while an actual bcdedit call is still denied.
toolCall({ platform: 'win32', ctx: reportCtx, fs: reportFs, name: 'pwsh', args: shell('cmd /c bcdedit /delete {current} /f'), action: 'deny', tier: 'system' })
// A launched program that merely mentions a protected file is not a deletion.
assert.equal(decideReport('pwsh', 'Start-Process notepad C:\\Windows\\win.ini').action, 'allow')
passed += 1

// A test fixture that contains those strings is data, not a call.
const fixtureFs = virtualFs({
  'c:\\': { dir: true },
  'c:\\windows': { dir: true },
  'c:\\windows\\system32': { dir: true },
  'c:\\projects\\demo': { dir: true },
  'c:\\projects\\demo\\fixture.mjs': {
    text: [
      "const sample = \"shutil.rmtree('C:/Windows/System32/config')\"",
      "// never do fs.rmSync('C:/Windows/System32/x.dll')",
      "const execSample = 'exec(\"del C:/Windows/x\")'",
      'export default sample',
    ].join('\n'),
  },
  'c:\\projects\\demo\\real.mjs': { text: "import fs from 'node:fs'\nfs.rmSync('C:/Windows/System32/x.dll')\n" },
})
toolCall({ platform: 'win32', ctx: reportCtx, fs: fixtureFs, name: 'pwsh', args: shell('node C:\\projects\\demo\\fixture.mjs'), action: 'allow' })
toolCall({ platform: 'win32', ctx: reportCtx, fs: fixtureFs, name: 'pwsh', args: shell('node C:\\projects\\demo\\real.mjs'), action: 'deny', tier: 'system' })

console.log(`system-protection selftest: ${passed} checks passed, ${failures.length} failed`)
for (const failure of failures) console.error(`FAIL ${failure}`)
if (failures.length > 0) process.exitCode = 1
