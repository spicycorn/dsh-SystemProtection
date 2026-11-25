/**
 * Wiring test. Runs the real `apply()` against the stub Host in `host.mjs`, so a
 * typo in an event name, a listener signature, or a return shape fails here
 * instead of on someone's machine.
 *
 * It judges the *real* machine it runs on: the system root is taken from the
 * platform, so the same file passes on Windows, Linux, and macOS.
 *
 * `node test/fake-host.mjs`
 */

import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

import { apply, inject, normalizeConfig } from '../index.js'
import { createHost, SYSTEM_TARGET, WORKSPACE } from './host.mjs'

let passed = 0
const failures = []
const check = (label, fn) => {
  try {
    fn()
    passed += 1
  }
  catch (error) {
    failures.push(`${label}\n   ${String(error?.message ?? error).split('\n')[0]}`)
  }
}

// ── Enforce mode ───────────────────────────────────────────────────────────
const host = createHost()
apply(host.ctx, {})

check('a guard is registered', () => assert.equal(host.guards.length, 1))
check('the ask layer and three file-system intents are listening', () => {
  assert.equal(host.listenerCount(), 4)
  assert.ok(host.logs.some(([, , line]) => line.includes('system-protection: enforce')), 'startup summary logged')
})

// The activation bug that motivated these two checks: reading a service as a
// `ctx` property without declaring it in `inject` throws inside the Host, the
// fiber fails, and the machine is left unprotected with only a diagnostic on
// the plugin card to say so.
check('the plugin declares the one service it touches as a property', () => {
  assert.ok(Array.isArray(inject), 'inject must be an array of service keys')
  assert.ok(inject.includes('tools'), 'ctx.tools must be declared in inject')
})
check('activation never reaches for a service it did not declare', () => {
  assert.deepEqual(host.serviceDenials, [], `undeclared service reads: ${host.serviceDenials.join(', ')}`)
})
check('the session workspace is still found without a property read', () => {
  // Only true if `sandboxPolicy` was read through ctx.get: with the fallback the
  // root would be the process cwd, i.e. this repository, and `./build` would be
  // inside a protected tree.
  assert.equal(host.runGuards('bash', { command: 'rm -rf ./build' }), undefined)
})

check('the guard denies a shell delete of the system root', () => {
  const verdict = host.runGuards('bash', { command: `rm -rf ${SYSTEM_TARGET}` })
  assert.ok(verdict !== undefined, 'expected a denial')
  assert.equal(verdict.info.code, 'PROTECTED_PATH')
  assert.match(verdict.reason, /protected path/i)
})

check('the guard denies overwriting a system file with write', () => {
  const verdict = host.runGuards('write', { file_path: `${SYSTEM_TARGET}/hosts`, content: 'x' })
  assert.ok(verdict !== undefined)
  assert.equal(verdict.info.code, 'PROTECTED_PATH')
})

check('ordinary workspace work passes the guard', () => {
  assert.equal(host.runGuards('bash', { command: 'rm -rf ./build' }), undefined)
  assert.equal(host.runGuards('write', { file_path: 'src/index.js', content: 'x' }), undefined)
  assert.equal(host.runGuards('read', { file_path: SYSTEM_TARGET }), undefined)
})

check('plugin_manager stays exempt', () => {
  assert.equal(host.runGuards('plugin_manager', { action: 'remove_bundle', target: 'x@1.0.0' }), undefined)
})

// The exemption is how a person manages bundles; it must not also let a model
// disarm the guard. This is report finding P11.
check('plugin_manager cannot switch this plugin off', () => {
  const verdict = host.runGuards('plugin_manager', { action: 'set_bundle', target: '@local/system-protection', enabled: false })
  assert.ok(verdict !== undefined, 'expected a denial')
  assert.equal(verdict.info.code, 'PROTECTED_SELF')
  assert.match(verdict.reason, /system-protection|protected/i)
})
check('a model cannot uninstall the protection plugin either', () => {
  const verdict = host.runGuards('plugin_manager', { action: 'remove_bundle', target: '@local/system-protection' })
  assert.ok(verdict !== undefined, 'expected a denial')
  assert.equal(verdict.info.code, 'PROTECTED_SELF')
})
check('a plugin_market removal of the plugin is denied too', () => {
  const verdict = host.runGuards('plugin_market', { action: 'uninstall', package: 'system-protection' })
  assert.ok(verdict !== undefined, 'expected a denial')
  assert.equal(verdict.info.code, 'PROTECTED_SELF')
})
check('self-protection is the owner\'s switch, not the model\'s', () => {
  const open = createHost()
  apply(open.ctx, { selfProtect: false })
  assert.equal(open.runGuards('plugin_manager', { action: 'set_bundle', target: '@local/system-protection', enabled: false }), undefined)
  open.disposeAll()
})
check('the default configuration fails closed (report finding P12)', () => {
  const settings = normalizeConfig({}, { warn: () => {}, info: () => {} })
  assert.equal(settings.onInternalError, 'closed')
})
check('an internal error denies the call when the plugin fails closed', () => {
  const broken = { name: 'write', get arguments() { throw new Error('boom') }, agent: host.agent }
  const verdict = host.guards[0](broken)
  assert.ok(verdict !== undefined, 'expected a denial')
  assert.equal(verdict.info.code, 'PROTECTION_UNAVAILABLE')
})
check('...and lets it through only when the owner chose onInternalError: open', () => {
  const open = createHost()
  apply(open.ctx, { onInternalError: 'open' })
  const broken = { name: 'write', get arguments() { throw new Error('boom') }, agent: open.agent }
  assert.equal(open.guards[0](broken), undefined)
  open.disposeAll()
})

const askVerdict = await host.runPreExecute('bash', { command: 'rm -f ~/.npmrc' })
check('pre-execute returns ask for a credential file', () => {
  assert.equal(askVerdict?.kind, 'ask')
  assert.ok(askVerdict.reason.length > 30)
  assert.equal(typeof askVerdict.displayReason.en, 'string')
  assert.equal(typeof askVerdict.displayReason.zh, 'string')
})
const passThrough = await host.runPreExecute('bash', { command: 'rm -rf ./dist' })
check('pre-execute yields allow for workspace cleanup', () => assert.equal(passThrough.kind, 'allow'))

// A confirmation the user cannot tell apart from a routine permission prompt is
// a confirmation they will click through, so the text has to carry the difference.
check('the ask text says plainly that it is not a routine permission prompt', () => {
  assert.match(askVerdict.displayReason.en, /NOT a routine permission request/)
  assert.match(askVerdict.displayReason.zh, /不是普通的权限请求/)
})
check('the ask text tells the user what to demand before approving', () => {
  assert.match(askVerdict.displayReason.zh, /为什么必须动这里/)
  assert.match(askVerdict.displayReason.en, /why this location has to change/)
  assert.match(askVerdict.displayReason.en, /reject/i)
})
check('the ask text still names the tier and the exact path', () => {
  assert.match(askVerdict.displayReason.en, /\.npmrc/)
  assert.match(askVerdict.displayReason.en, /secret file/)
})
check('the audit reason stays factual, without the card markup', () => {
  assert.match(askVerdict.reason, /\.npmrc/)
  assert.equal(askVerdict.reason.includes('⚠'), false)
})

check('the model is told the rules once, statically', () => {
  assert.equal(host.sections.length, 1, `sections: ${host.sections.map(entry => entry.name).join(', ')}`)
  const [section] = host.sections
  assert.equal(section.name, 'system-protection')
  assert.equal(section.interpolate, false, 'prompt variables must not touch this text')
  assert.equal(typeof section.text, 'string', 'static text keeps the assembled prompt cache-stable')
  assert.ok(Number.isFinite(section.order), 'a non-finite order throws in the real service')
  assert.match(section.text, /Never try to route around a block/)
  assert.match(section.text, /why the change is necessary/)
})
check('modelGuidance: false leaves the system prompt alone', () => {
  const quiet = createHost()
  apply(quiet.ctx, { modelGuidance: false })
  assert.deepEqual(quiet.sections, [])
})
check('a profile without the systemPrompt service still enforces, and says so', () => {
  const spartan = createHost({ without: ['systemPrompt'] })
  apply(spartan.ctx, {})
  assert.equal(spartan.guards.length, 1)
  assert.ok(spartan.logs.some(([level, , line]) => level === 'warn' && line.includes('no systemPrompt service')), spartan.logs.map(entry => entry[2]).join(' | '))
})

const deniedIntent = await host.runIntentCatch('fs/delete-intent', SYSTEM_TARGET, host.agent)
check('fs/delete-intent throws for a protected target', () => {
  assert.equal(deniedIntent.threw, true, `outcome was ${JSON.stringify(deniedIntent).slice(0, 300)}`)
  assert.match(deniedIntent.message, /protected path/i)
})
const freeIntent = await host.runIntentCatch('fs/delete-intent', `${WORKSPACE}/tmp-out`, host.agent)
check('fs/delete-intent passes workspace targets to the next listener', () => {
  assert.notEqual(freeIntent.threw, true)
  assert.equal(freeIntent.reached, true)
})
const internalIntent = await host.runIntentCatch('fs/delete-intent', SYSTEM_TARGET, undefined)
check('fs/delete-intent ignores a Host-internal write with no agent', () => {
  assert.notEqual(internalIntent.threw, true)
  assert.equal(internalIntent.reached, true)
})

const status = host.runCommand('system-protection', 'status')
check('/system-protection status reports the tier table', () => {
  assert.equal(status.kind, 'success')
  assert.match(status.text, /system-protection: enabled, enforce/)
  assert.match(status.text, /on internal error: closed/)
  assert.match(status.text, /self-protection: on/)
  assert.match(status.text, /system\s+deny/)
  assert.match(status.text, /denied/)
})
const dryRun = host.runCommand('system-protection', `test rm -rf ${SYSTEM_TARGET}`)
check('/system-protection test reports the verdict without executing', () => {
  assert.equal(dryRun.kind, 'success')
  assert.match(dryRun.text, /DENY/)
})
const freeRun = host.runCommand('system-protection', 'test rm -rf ./build')
check('/system-protection test says no for safe targets', () => assert.match(freeRun.text, /not protected/))

check('denials were counted and logged', () => {
  const warning = host.logs.filter(([level]) => level === 'warn')
  assert.ok(warning.length >= 3, `expected warnings, got ${warning.length}`)
})

host.disposeAll()
check('disposing the plugin removes the guard', () => assert.equal(host.guards.length, 0))

// ── Audit-only mode ────────────────────────────────────────────────────────
const auditor = createHost()
apply(auditor.ctx, { enforcement: 'audit' })
check('audit mode logs but never denies', () => {
  assert.equal(auditor.runGuards('bash', { command: `rm -rf ${SYSTEM_TARGET}` }), undefined)
  assert.ok(auditor.logs.some(([, , line]) => line.includes('audit-only')))
})
const auditAsk = await auditor.runPreExecute('bash', { command: 'rm -f ~/.npmrc' })
check('audit mode pre-execute passes through', () => assert.equal(auditAsk.kind, 'allow'))

// ── Disabled, and a mis-typed config ───────────────────────────────────────
const off = createHost()
apply(off.ctx, { enabled: false })
check('enabled:false registers nothing', () => {
  assert.equal(off.guards.length, 0)
  assert.ok(off.logs.some(([, , line]) => line.includes('disabled by config')))
})

const noisy = createHost()
apply(noisy.ctx, { enabled: 'yes', tiers: { system: 'block', nonsense: 'deny' }, unknownKey: 1 })
check('bad config values are reported, and defaults still protect', () => {
  assert.ok(noisy.logs.some(([, , line]) => line.includes('unknown config key')))
  assert.ok(noisy.logs.some(([, , line]) => line.includes('must be deny, ask or off')))
  assert.ok(noisy.runGuards('bash', { command: `rm -rf ${SYSTEM_TARGET}` }) !== undefined)
})

// ── Narrowing with allowExtra, and a custom tier table ─────────────────────
const tuned = createHost()
apply(tuned.ctx, { tiers: { system: 'ask', secrets: 'off' } })
check('a tier lowered to ask no longer denies', () => {
  assert.equal(tuned.runGuards('bash', { command: `rm -rf ${SYSTEM_TARGET}` }), undefined)
})
const tunedAsk = await tuned.runPreExecute('bash', { command: `rm -rf ${SYSTEM_TARGET}` })
check('the lowered tier asks instead', () => assert.equal(tunedAsk.kind, 'ask'))

// The rule above is only worth something if the stub really enforces it: with
// nothing declared, even `tools` is refused, exactly as the Host refused
// `sandboxPolicy` and reported `fiberPhase: "failed"`.
check('the stub refuses an undeclared service read, so the rule is not vacuous', () => {
  const strict = createHost({ inject: [] })
  assert.throws(() => apply(strict.ctx, {}), /without inject/)
  assert.deepEqual(strict.serviceDenials, ['tools'])
})

// ── A profile that provides no optional service at all ──────────────────────
const bare = createHost({ withoutSandboxPolicy: true })
apply(bare.ctx, {})
check('a missing optional service degrades the root, never the protection', () => {
  assert.equal(bare.guards.length, 1, 'the guard must still register')
  assert.ok(bare.runGuards('bash', { command: `rm -rf ${SYSTEM_TARGET}` }) !== undefined, 'the system root must still be denied')
  assert.deepEqual(bare.serviceDenials, [])
})

// The live incident, through the real guard: a `link:` install under development
// has its own directory as the session workspace. Everything in that tree used to
// be classified `harness` and denied, including the plugin's own source files.
const devHost = createHost({ workspace: path.resolve(fileURLToPath(import.meta.url), '..', '..') })
apply(devHost.ctx, {})
check('a plugin developed inside its own workspace still lets that workspace work', () => {
  assert.equal(devHost.runGuards('pwsh', { command: 'New-Item -ItemType Directory -Path .\\probe | Out-Null' }), undefined)
  assert.equal(devHost.runGuards('pwsh', { command: 'Remove-Item -LiteralPath .\\probe -Recurse -Force' }), undefined)
})
check('...while the system, the credentials and the Harness stay denied', () => {
  assert.ok(devHost.runGuards('bash', { command: `rm -rf ${SYSTEM_TARGET}` }) !== undefined)
  assert.ok(devHost.runGuards('pwsh', { command: 'Remove-Item -LiteralPath C:\\Windows\\System32\\config -Recurse -Force' }) !== undefined)
  assert.ok(devHost.runGuards('pwsh', { command: `Remove-Item -LiteralPath ${path.join(os.homedir(), '.dsh')}\\profiles -Recurse -Force` }) !== undefined)
})
check('and the situation is logged, never silent', () => {
  assert.ok(devHost.logs.some(([level, , line]) => level === 'warn' && line.includes('own files are not self-protected')), devHost.logs.map(entry => entry[2]).join(' | '))
})

console.log(`system-protection wiring test: ${passed} checks passed, ${failures.length} failed`)
for (const failure of failures) console.error(`FAIL ${failure}`)
if (failures.length > 0) process.exitCode = 1
