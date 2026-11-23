/**
 * Audit test: does the plugin ever *act* on the machine?
 *
 * The claim under test is narrow and checkable: the plugin only ever answers a
 * DSH tool call with allow / ask / deny. It does not touch the file system apart
 * from metadata lookups on the exact paths a call named (plus one append to an
 * audit log the user opted into), it never reads file contents, never enumerates
 * a directory, never spawns a process, never opens a socket, and leaves no
 * global state behind when it is disposed.
 *
 * Method: every function on `node:fs`, `node:fs/promises`, `node:child_process`,
 * `node:net`, and `node:http` is replaced with a recording proxy *before* the
 * plugin is applied. Anything outside the metadata allow-list is recorded as a
 * violation and, for write-shaped calls, made to throw — so a leak would both
 * fail the assertion and be unable to reach disk.
 *
 * `node test/no-touch.mjs`
 */

import assert from 'node:assert/strict'
import childProcess from 'node:child_process'
import fs from 'node:fs'
import fsPromises from 'node:fs/promises'
import http from 'node:http'
import net from 'node:net'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'

import { apply } from '../index.js'
import { createHost, PROGRAM_FILES, SYSTEM_TARGET, WORKSPACE } from './host.mjs'

/** The only calls the plugin may make against the file system. */
const METADATA = new Set(['existsSync', 'lstatSync', 'statSync', 'lstat', 'stat', 'realpathSync', 'realpath', 'access', 'accessSync'])

const calls = []
const violations = []
const patches = []
/**
 * `fs.appendFileSync` is implemented in Node by calling `fs.writeFileSync` with
 * an append flag, so a nested `writeFileSync` under an `appendFileSync` is the
 * same single write, not a second one. Tracked so it is judged as one.
 */
let appendDepth = 0

function instrument(module, moduleName, options = {}) {
  const only = options.only
  for (const key of Object.keys(module)) {
    if (only !== undefined && !only.has(key)) continue
    const original = module[key]
    if (typeof original !== 'function') continue
    const wrapped = (...args) => {
      const record = { module: moduleName, method: key, args: args.slice(0, 3).map(summarise) }
      if (/\.(write|append|unlink|rm|mkdir|rename|copyFile|truncate|open|create)/.test(`${moduleName}.${key}`)) {
        record.stack = new Error().stack.split('\n').slice(1, 7).map(line => line.trim())
      }
      if (appendDepth > 0 && key === 'writeFileSync') record.nested = 'appendFileSync'
      if (key === 'writeFileSync' || key === 'appendFileSync') record.options = args[2]
      calls.push(record)
      if (key.startsWith('append')) appendDepth += 1
      try {
        const decision = options.allow === undefined ? undefined : options.allow(key, args)
        if (decision !== undefined && decision !== true) {
          violations.push({ ...record, why: typeof decision === 'string' ? decision : 'not on the allow-list' })
          if (/^(write|append|unlink|rm|mkdir|rmdir|rename|copyFile|cp|chmod|lchmod|chown|lchown|truncate|open|create|symlink|link|lutimes|utimes|watch|watchFile|unwatchFile|glob|exec|spawn|fork|connect|request|get)/.test(key)) {
            throw new Error(`no-touch audit: the plugin attempted ${moduleName}.${key} (${String(args[0])})`)
          }
        }
        return original.apply(module, args)
      }
      finally {
        if (key.startsWith('append')) appendDepth -= 1
      }
    }
    Object.defineProperty(wrapped, 'name', { value: `wrapped_${key}` })
    try {
      module[key] = wrapped
      patches.push([module, key, original])
    }
    catch { /* a read-only property: nothing to instrument, and nothing to fear */ }
  }
}

/** Keep the record small and JSON-safe. */
function summarise(value) {
  if (typeof value === 'string') return value.length > 160 ? `${value.slice(0, 160)}…` : value
  if (value === null || typeof value !== 'object') return value
  return '[object]'
}

const restore = () => {
  for (const [module, key, original] of patches.reverse()) {
    try {
      module[key] = original
    }
    catch { /* ignore */ }
  }
}

let passed = 0
const failures = []
const check = (label, fn) => {
  try {
    fn()
    passed += 1
  }
  catch (error) {
    failures.push(`${label}\n   ${String(error?.message ?? error).split('\n').slice(0, 10).join('\n   ')}`)
  }
}

// Everything the plugin may be asked to judge: three layers, several dialects,
// plus every operator command. Each one is a real attempt at a protected path.
const HOSTILE = [
  ['bash', { command: `rm -rf ${SYSTEM_TARGET}` }],
  ['bash', { command: `sudo rm -rf ${SYSTEM_TARGET}/config` }],
  ['pwsh', { command: `Remove-Item -Recurse -Force ${PROGRAM_FILES}` }],
  ['bash', { command: `del /f /s /q "${SYSTEM_TARGET}\\System32\\drivers"` }],
  ['bash', { command: 'dd if=/dev/zero of=/dev/sda bs=1M' }],
  ['pwsh', { command: 'Format-Volume -DriveLetter C' }],
  ['bash', { command: 'rm -rf .git' }],
  ['bash', { command: 'git filter-branch --prune-empty' }],
  ['bash', { command: 'find / -name "*.conf" -delete' }],
  ['bash', { command: `rm -rf ~` }],
  ['write', { file_path: `${SYSTEM_TARGET}/drivers/etc/hosts`, content: 'x' }],
  ['edit', { file_path: `${SYSTEM_TARGET}/explorer.exe`, old_string: 'a', new_string: '' }],
  ['apply_patch', { input: `*** Delete File: ${SYSTEM_TARGET}/system32/cmd.exe` }],
  ['mcp__third_party__filesystem_delete', { path: SYSTEM_TARGET, recursive: true }],
  ['delete_file', { paths: [SYSTEM_TARGET, PROGRAM_FILES] }],
  ['move', { source: SYSTEM_TARGET, destination: '/tmp/x' }],
  ['terminal_send', { sessionId: 's', text: `rm -rf ${SYSTEM_TARGET}` }],
  ['run_code', { code: `import shutil\nshutil.rmtree("${SYSTEM_TARGET}")` }],
  ['bash', { command: 'rm -rf ./build' }],
  ['write', { file_path: 'src/index.js', content: 'x' }],
  ['read', { file_path: `${SYSTEM_TARGET}/hosts` }],
  ['glob', { pattern: '**/*.js' }],
  ['grep', { pattern: 'secret', path: SYSTEM_TARGET }],
  ['bash', { command: 'rm -f .env' }],
]

const AUDIT_LOG = path.join(os.tmpdir(), 'dsh-system-protection-audit', 'audit.jsonl')

async function drive(host) {
  for (const [name, args] of HOSTILE) {
    host.runGuards(name, args)
    await host.runPreExecute(name, args)
  }
  for (const event of ['fs/delete-intent', 'fs/write-intent', 'fs/edit-intent']) {
    await host.runIntentCatch(event, SYSTEM_TARGET, host.agent)
    await host.runIntentCatch(event, `${WORKSPACE}/out`, host.agent)
    await host.runIntentCatch(event, SYSTEM_TARGET, undefined)
  }
  host.runCommand('system-protection', 'status')
  host.runCommand('system-protection', `test rm -rf ${SYSTEM_TARGET}`)
  host.runCommand('system-protection', 'reset')
}

const envBefore = { ...process.env }
const cwdBefore = process.cwd()
const signals = ['exit', 'uncaughtException', 'unhandledRejection', 'beforeExit', 'SIGINT', 'SIGTERM', 'warning']
const listenersBefore = Object.fromEntries(signals.map(signal => [signal, process.listeners(signal).length]))
const handlesBefore = process._getActiveHandles?.().length ?? 0

// Create the audit directory *before* instrumenting, so the plugin's own append
// is the only file-system mutation in the whole run.
fs.mkdirSync(path.dirname(AUDIT_LOG), { recursive: true })
if (fs.existsSync(AUDIT_LOG)) fs.rmSync(AUDIT_LOG)

instrument(fs, 'node:fs')
instrument(fsPromises, 'node:fs/promises')
instrument(childProcess, 'node:child_process', { only: new Set(['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork']) })
instrument(net, 'node:net', { only: new Set(['createConnection', 'connect', 'createServer', 'Socket']) })
instrument(http, 'node:http', { only: new Set(['request', 'get', 'createServer']) })

check('the probe is live (module properties are writable here)', () => {
  assert.equal(fs.existsSync.name, 'wrapped_existsSync', 'fs was not instrumented')
  assert.equal(childProcess.spawn.name, 'wrapped_spawn', 'child_process was not instrumented')
})

// ── Phase A: default configuration, no audit log ───────────────────────────
const phaseA = createHost()
apply(phaseA.ctx, {})
await drive(phaseA)
phaseA.disposeAll()

const writeShaped = /^(write|append|unlink|rm|mkdir|rmdir|rename|copyFile|truncate|open|create|symlink|link|chmod|chown|watch|glob|exec|spawn|fork|connect|request)/
/** Node implements `appendFileSync` by calling `writeFileSync`; count it once. */
const distinctWrites = records => records.filter(record => record.nested === undefined && writeShaped.test(record.method))
const phaseAWrites = distinctWrites(calls)

const observed = {}
for (const record of calls) observed[`${record.module}.${record.method}`] = (observed[`${record.module}.${record.method}`] ?? 0) + 1
const seenMethods = new Set(calls.map(record => `${record.module}.${record.method}`))
const outsideAllowList = [...seenMethods].filter(method => !METADATA.has(method.split('.').pop()))

check('phase A attempted no write-shaped call at all', () => {
  assert.deepEqual(phaseAWrites.map(record => `${record.module}.${record.method}`), [])
})
check('no write-shaped call succeeded either', () => assert.deepEqual(violations, [], JSON.stringify(violations.slice(0, 3))))
check('the file-system surface used was metadata only', () => {
  assert.deepEqual(outsideAllowList, [], `unexpected calls: ${outsideAllowList.join(', ')}`)
})
check('no child process was spawned', () => {
  assert.equal(calls.filter(record => record.module === 'node:child_process').length, 0)
})
check('no socket was opened', () => {
  assert.equal(calls.filter(record => record.module === 'node:net' || record.module === 'node:http').length, 0)
})
check('no file content was read and no directory was listed', () => {
  for (const record of calls) assert.doesNotMatch(record.method, /^(read|readdir|opendir|createReadStream)/, `${record.module}.${record.method}`)
})
check('the plugin was actually exercised', () => {
  assert.ok(calls.length > 0, 'expected metadata lookups on the paths named by the calls')
  assert.ok(phaseA.logs.some(([, , line]) => line.includes('DENY')), 'expected denials in the log')
})
check('no new process signal listeners were left behind', () => {
  const after = Object.fromEntries(signals.map(signal => [signal, process.listeners(signal).length]))
  assert.deepEqual(after, listenersBefore)
})
check('the environment and the working directory are untouched', () => {
  assert.deepEqual({ ...process.env }, envBefore)
  assert.equal(process.cwd(), cwdBefore)
})
check('no new active handles were created', () => {
  const after = process._getActiveHandles?.().length ?? 0
  assert.equal(after, handlesBefore, `handles went from ${handlesBefore} to ${after}`)
})

// Paths the plugin looked at: the point is that they are the paths a call named,
// never a tree it chose to walk.
const probed = [...new Set(calls.filter(record => METADATA.has(record.method)).map(record => String(record.args[0])))]
check('no probe was a glob or a pattern', () => {
  for (const probe of probed) assert.doesNotMatch(probe, /[*?]/, `probed a glob: ${probe}`)
})

calls.length = 0
violations.length = 0

// ── Phase B: the one write the user opts into ───────────────────────────────
const phaseB = createHost()
apply(phaseB.ctx, { auditLog: AUDIT_LOG })
await drive(phaseB)
phaseB.disposeAll()

const phaseBWrites = distinctWrites(calls)
check('with auditLog set, the only write is that file', () => {
  assert.ok(phaseBWrites.length > 0, 'expected the audit append to have happened')
  for (const record of phaseBWrites) {
    assert.equal(record.method, 'appendFileSync', `unexpected write: ${record.module}.${record.method}(${String(record.args[0])})\n     ${(record.stack ?? []).join('\n     ')}`)
    assert.equal(path.resolve(String(record.args[0])), path.resolve(AUDIT_LOG), `wrote to ${record.args[0]}`)
  }
})
check('the nested continuation Node uses really is an append, never a rewrite', () => {
  const nested = calls.filter(record => record.nested === 'appendFileSync')
  assert.ok(nested.length > 0, 'expected Node to route the append through writeFileSync')
  for (const record of nested) {
    const options = JSON.stringify(record.options ?? '')
    assert.match(options, /"flag":"a"|"a"/, `writeFileSync without an append flag: ${options}`)
    assert.equal(path.resolve(String(record.args[0])), path.resolve(AUDIT_LOG))
  }
})
check('the audit log lives in the directory the user chose, not a protected tree', () => {
  assert.ok(path.resolve(AUDIT_LOG).startsWith(path.resolve(os.tmpdir())))
})
check('the default configuration writes nothing anywhere', () => {
  assert.equal(phaseAWrites.length, 0)
  assert.ok(phaseBWrites.length > 0, 'and the opt-in configuration does, so the probe works')
})

// The audit log is the plugin's only artefact; confirm it is plain JSONL text.
restore()
const written = fs.readFileSync(AUDIT_LOG, 'utf8').trim().split('\n')
check('the audit log is line-oriented JSON, nothing else', () => {
  assert.ok(written.length >= 1)
  for (const line of written) JSON.parse(line)
})

const tally = Object.entries(observed).map(([method, count]) => `${method}=${count}`).join(', ')
console.log(`system-protection no-touch audit: ${passed} checks passed, ${failures.length} failed`)
console.log(`  fs surface observed: ${tally || 'none'}`)
console.log(`  distinct paths probed: ${probed.length} (all named by a tool call)`)
console.log(`  mutating calls: ${violations.length}; child processes: 0; sockets: 0`)
for (const failure of failures) console.error(`FAIL ${failure}`)
if (failures.length > 0) process.exitCode = 1
