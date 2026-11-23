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

import { DEFAULT_TIERS } from '../index.js'
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

/** @param {{ platform: 'win32'|'linux', name: string, args: object, action: string, tier?: string, ctx?: object, tiers?: object, allowExtra?: string[] }} testCase */
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
    tierActions: testCase.tiers ?? DEFAULT_TIERS,
    protectWrites: true,
    scanShell: true,
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

console.log(`system-protection selftest: ${passed} checks passed, ${failures.length} failed`)
for (const failure of failures) console.error(`FAIL ${failure}`)
if (failures.length > 0) process.exitCode = 1
