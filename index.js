/**
 * System file protection 鈥?force a hard floor under destructive model calls.
 *
 * The plugin owns three layers, from strongest to deepest:
 *
 * 1. `ctx.tools.guard()` 鈥?a monotonic, order-independent denial on the tool
 *    pipeline. Nothing a later listener does can undo it, which is what makes
 *    this a *force* rather than a prompt. It sees the model's own tool call
 *    (name + arguments), so it also holds when the user approved a
 *    `danger-full-access` retry and the OS sandbox is therefore wide open.
 * 2. `tools/pre-execute` 鈥?the `ask` tier, which routes an irreversible-looking
 *    delete through the Harness approval flow instead of silently deciding.
 * 3. `fs/delete-intent` / `fs/write-intent` / `fs/edit-intent` 鈥?the deepest
 *    seam any tool can reach. Registered with `{ prepend: true }` so this
 *    plugin owns the single decision slot, and it only judges calls it can
 *    attribute to a tool execution (`actor.agent`), so Host-internal file
 *    writes are never touched.
 *
 * Configuration lives in this row's `config` (see `docs/DETAIL.md`). The plugin
 * declares no `Config` schema on purpose: that keeps the bundle free of any
 * dependency on Harness internals, and every value is validated at activation
 * with a visible Host log line when it is wrong.
 *
 * @module system-protection
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { createAudit } from './src/audit.js'
import { askDisplayReason, MODEL_GUIDANCE } from './src/guidance.js'
import { pathKey } from './src/paths.js'
import { decideToolCall, formatReason } from './src/policy.js'
import { classifyKey, TIERS, TIER_LABEL } from './src/rules.js'
import { scanCommand } from './src/shell-scan.js'
import { createSystemContext } from './src/system-context.js'

/** The plugin only makes sense where a tool pipeline exists. */
export const inject = ['tools']

/** Tier actions a user may choose per tier. */
const ACTIONS = new Set(['deny', 'ask', 'off'])

/** Defaults: what an AI must never touch on its own, versus what it must ask for. */
export const DEFAULT_TIERS = Object.freeze({
  system: 'deny',
  harness: 'deny',
  credentials: 'deny',
  versionControl: 'deny',
  trash: 'deny',
  homeRoot: 'deny',
  workspaceRoot: 'deny',
  userData: 'ask',
  appData: 'ask',
  secrets: 'ask',
  lockfiles: 'off',
  uncommittedWork: 'ask',
})

/** Tools whose own job is to manage the profile and its installed bundles. */
export const DEFAULT_EXEMPT = Object.freeze(['plugin_manager', 'plugin_market'])

const DEFAULT_SETTINGS = Object.freeze({
  enabled: true,
  enforcement: 'enforce',
  tiers: DEFAULT_TIERS,
  protectExtra: [],
  allowExtra: [],
  protectWrites: true,
  scanShell: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
  exemptTools: DEFAULT_EXEMPT,
  sweepTools: [],
  sweepSkipTools: [],
  denyNote: '',
  auditLog: '',
  onInternalError: 'open',
  messageLocale: 'auto',
  modelGuidance: true,
})

const FLAG_KEYS = ['enabled', 'protectWrites', 'scanShell', 'genericPathSweep', 'resolveSymlinksInsideWorkspace', 'modelGuidance']
const LIST_KEYS = ['protectExtra', 'allowExtra', 'exemptTools', 'sweepTools', 'sweepSkipTools']

/**
 * Merge the row's `config` over the defaults, reporting anything unrecognized
 * instead of guessing. A typo in `cordis.patch.yml` should be loud, not silently
 * widening the hole the plugin exists to close.
 *
 * @param {Record<string, unknown> | undefined} raw
 * @param {{ warn: (line: string) => void, info: (line: string) => void }} log
 */
export function normalizeConfig(raw, log) {
  const settings = { ...DEFAULT_SETTINGS }
  const source = raw === null || typeof raw !== 'object' ? {} : raw

  for (const key of Object.keys(source)) {
    if (key === 'tiers') continue
    if (!(key in DEFAULT_SETTINGS)) log.warn(`system-protection: unknown config key "${key}" ignored`)
  }

  for (const key of FLAG_KEYS) {
    if (typeof source[key] === 'boolean') settings[key] = source[key]
    else if (source[key] !== undefined) log.warn(`system-protection: config "${key}" must be true or false; using ${settings[key]}`)
  }
  for (const key of LIST_KEYS) {
    const value = source[key]
    if (Array.isArray(value)) settings[key] = value.map(item => String(item)).filter(item => item !== '')
    else if (value !== undefined) log.warn(`system-protection: config "${key}" must be an array of strings; using the default`)
  }
  for (const key of ['denyNote', 'auditLog']) {
    if (typeof source[key] === 'string') settings[key] = source[key]
    else if (source[key] !== undefined) log.warn(`system-protection: config "${key}" must be a string; using the default`)
  }
  if (typeof source.enforcement === 'string' && (source.enforcement === 'enforce' || source.enforcement === 'audit')) settings.enforcement = source.enforcement
  else if (source.enforcement !== undefined) log.warn('system-protection: config "enforcement" must be "enforce" or "audit"; using enforce')
  if (typeof source.onInternalError === 'string' && (source.onInternalError === 'open' || source.onInternalError === 'closed')) settings.onInternalError = source.onInternalError
  else if (source.onInternalError !== undefined) log.warn('system-protection: config "onInternalError" must be "open" or "closed"; using open')
  if (typeof source.messageLocale === 'string' && ['auto', 'en', 'zh'].includes(source.messageLocale)) settings.messageLocale = source.messageLocale
  else if (source.messageLocale !== undefined) log.warn('system-protection: config "messageLocale" must be "auto", "en" or "zh"; using auto')

  const tiers = { ...DEFAULT_TIERS }
  const rawTiers = source.tiers
  if (rawTiers !== null && typeof rawTiers === 'object') {
    for (const [tier, action] of Object.entries(rawTiers)) {
      if (!TIERS.includes(tier)) { log.warn(`system-protection: config tiers."${tier}" is not a known tier; ignored`); continue }
      if (!ACTIONS.has(action)) { log.warn(`system-protection: config tiers."${tier}"="${action}" must be deny, ask or off; ignored`); continue }
      tiers[tier] = action
    }
  }
  else if (rawTiers !== undefined) log.warn('system-protection: config "tiers" must be an object of tier: action')

  settings.tiers = tiers
  settings.exemptSet = new Set(settings.exemptTools)
  return settings
}

/** The message language: explicit config wins, else follow the Host locale. */
function localeOf(settings, ctx) {
  if (settings.messageLocale === 'en' || settings.messageLocale === 'zh') return settings.messageLocale
  // A service the plugin never declared answers a property access by throwing,
  // so even the locale hint is read defensively.
  let hint = ''
  try {
    hint = String(ctx.locale ?? '')
  }
  catch { /* not injected: fall through to the environment */ }
  const locale = (hint || process.env.LANG || '').toLowerCase()
  return locale.startsWith('zh') ? 'zh' : 'en'
}

/**
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {Record<string, unknown>} [config] this row's `config`
 */
export function apply(ctx, config) {
  const log = ctx.logger('system-protection')
  const settings = normalizeConfig(config, log)
  const audit = createAudit({ logger: log, logPath: settings.auditLog, fs })

  if (!settings.enabled) {
    log.info('system-protection: disabled by config; no guard, no ask, no file-system veto')
    return
  }

  /**
   * Optional service lookup.
   *
   * Only `tools` is declared in `inject`, and Cordis answers a *property*
   * access for any other service by throwing — `cannot get property
   * "sandboxPolicy" without inject`, which fails the plugin's fiber and leaves
   * the machine unprotected. So nothing here may reach for a service as
   * `ctx.someService` unless it is in `inject`: `ctx.get(name)` is the
   * documented way to read a service without that requirement, and it returns
   * `undefined` rather than failing when the profile does not provide it.
   */
  const service = name => {
    try {
      return ctx.get?.(name)
    }
    catch {
      return undefined
    }
  }
  /** Sandbox policy, if this profile provides one; the plugin degrades without it. */
  const policy = () => service('sandboxPolicy')

  const selfDir = path.dirname(fileURLToPath(import.meta.url))
  const sysctx = createSystemContext({
    cwd: policy()?.workspaceRoot ?? process.cwd(),
    selfDir,
    protectExtra: settings.protectExtra,
    allowExtra: settings.allowExtra,
  })

  /** Per-call memo so the ask layer and the guard never scan the same call twice. */
  const memo = new WeakMap()

  /** The session's workspace root, the same boundary the sandbox resolves. */
  const sessionRootOf = (exec) => {
    const session = exec?.agent?.session
    if (session === undefined) return sysctx.cwd
    try {
      const resolved = policy()?.resolve?.({ session })
      if (typeof resolved?.workspaceRoot === 'string' && resolved.workspaceRoot !== '') return resolved.workspaceRoot
    }
    catch { /* fall through to the working-directory service */ }
    try {
      const value = service('workingDirectory')?.get?.(session)
      if (typeof value === 'string' && value !== '') return value
    }
    catch { /* fall through to the plugin-wide default */ }
    return sysctx.cwd
  }

  const parsedArguments = (exec) => {
    const value = exec?.arguments
    if (value === null || typeof value !== 'string') return value
    try {
      return JSON.parse(value)
    }
    catch {
      return { command: value, input: value, text: value, file_path: value, path: value }
    }
  }

  const decide = (exec) => {
    const cached = memo.get(exec)
    if (cached !== undefined) return cached
    const decision = decideToolCall({
      name: String(exec?.name ?? ''),
      args: parsedArguments(exec),
      ctx: sysctx,
      sessionRoot: sessionRootOf(exec),
      fs,
      tierActions: settings.tiers,
      protectWrites: settings.protectWrites,
      scanShell: settings.scanShell,
      genericPathSweep: settings.genericPathSweep,
      sweepTools: settings.sweepTools,
      sweepSkipTools: settings.sweepSkipTools,
      resolveSymlinksInsideWorkspace: settings.resolveSymlinksInsideWorkspace,
    })
    memo.set(exec, decision)
    return decision
  }

  const exempt = (name) => settings.exemptSet.has(name)

  /** Run one decision, containing our own failure according to `onInternalError`. */
  const guarded = (exec, label) => {
    try {
      return { ok: true, decision: decide(exec) }
    }
    catch (error) {
      audit.record({ tool: label, action: 'error', hits: [], message: String(error?.stack ?? error) })
      return { ok: false, decision: { action: 'allow', hits: [], notes: [] } }
    }
  }

  // 鈹€鈹€ Layer 1: the hard floor 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
  ctx.effect(() => ctx.tools.guard((exec) => {
    const name = String(exec?.name ?? '')
    if (exempt(name)) return undefined
    const { ok, decision } = guarded(exec, name)
    if (!ok) return settings.onInternalError === 'closed'
      ? { reason: 'System file protection could not evaluate this call and is configured to fail closed.', info: { name: 'system-protection', code: 'PROTECTION_UNAVAILABLE' } }
      : undefined
    if (decision.action !== 'deny') return undefined
    if (settings.enforcement === 'audit') {
      audit.record({ tool: name, action: 'allow', hits: decision.hits.map(hit => ({ ...hit })) })
      log.warn(`system-protection audit-only: ${name} would be denied for ${decision.hits.map(hit => hit.path ?? hit.raw).join(', ')}`)
      return undefined
    }
    audit.record({ tool: name, action: 'deny', hits: decision.hits })
    return {
      reason: formatReason(decision, { locale: localeOf(settings, ctx), note: settings.denyNote }),
      info: { name: 'system-protection', code: 'PROTECTED_PATH', reason: decision.hits.map(hit => `${hit.tier}:${hit.path ?? hit.raw}`).join(' ') },
    }
  }), 'system-protection tools guard')

  // 鈹€鈹€ Layer 2: the approval route 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
  ctx.on('tools/pre-execute', async (exec, next) => {
    const name = String(exec?.name ?? '')
    if (exempt(name) || settings.enforcement !== 'enforce') return next()
    const { ok, decision } = guarded(exec, name)
    if (!ok || decision.action !== 'ask') return next()
    audit.record({ tool: name, action: 'ask', hits: decision.hits })
    const locale = localeOf(settings, ctx)
    // `reason` is the audit text; `displayReason` is what the person reads.
    // The card has no severity or source field a plugin could set, so the text
    // carries the whole difference between this and a routine permission prompt.
    const reason = formatReason(decision, { locale, note: settings.denyNote })
    return {
      kind: 'ask',
      reason,
      displayReason: {
        en: askDisplayReason(decision, { locale: 'en', note: settings.denyNote }),
        zh: askDisplayReason(decision, { locale: 'zh', note: settings.denyNote }),
        [locale]: askDisplayReason(decision, { locale, note: settings.denyNote }),
      },
    }
  })

  // 鈹€鈹€ Layer 3: the file-system seam 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
  const fsService = service('fs')
  const hostPathOf = (target) => {
    try {
      const value = fsService?.processPath?.(target)
      if (typeof value === 'string' && value !== '') return value
    }
    catch { /* the display path is the best remaining evidence */ }
    return target?.displayPath
  }

  /** The session behind an actor, whatever shape the emitter handed over. */
  const sessionOf = (actor) => actor?.agent?.session ?? actor?.session ?? (actor?.id === undefined ? undefined : actor)

  const veto = (target, actor, op) => {
    // Only judge a call the Host attributes to something (a tool execution), so
    // Host-internal file writes 鈥?attachments, state, compaction 鈥?stay untouched.
    if (actor === undefined || actor === null) return undefined
    const raw = hostPathOf(target)
    if (typeof raw !== 'string' || raw === '') return undefined
    const platform = sysctx.path
    const sessionRoot = sessionRootOf({ agent: { session: sessionOf(actor) } })
    const absolute = platform.isAbsolute(raw) ? raw : platform.resolve(sessionRoot, raw)
    const verdict = classifyKey(pathKey(absolute, sysctx), sysctx, { sessionRoot: pathKey(sessionRoot, sysctx) })
    if (verdict === undefined || verdict.tier === 'allow') return undefined
    const action = settings.tiers[verdict.tier] ?? 'off'
    if (action !== 'deny' || settings.enforcement !== 'enforce') return undefined
    const decision = {
      action: 'deny',
      hits: [{ tier: verdict.tier, id: verdict.id, path: absolute, raw, via: `fs:${op}`, op }],
    }
    audit.record({ tool: `fs:${op}`, action: 'deny', hits: decision.hits })
    return formatReason(decision, { locale: localeOf(settings, ctx), note: settings.denyNote })
  }

  const intentOptions = { prepend: true }
  ctx.on('fs/delete-intent', (target, actor, next) => {
    const reason = veto(target, actor, 'delete')
    if (reason !== undefined) throw new Error(reason)
    return next()
  }, intentOptions)
  ctx.on('fs/write-intent', (target, actor, next) => {
    if (settings.protectWrites === false) return next()
    const reason = veto(target, actor, 'overwrite')
    if (reason !== undefined) throw new Error(reason)
    return next()
  }, intentOptions)
  ctx.on('fs/edit-intent', (target, actor, next) => {
    if (settings.protectWrites === false) return next()
    const reason = veto(target, actor, 'overwrite')
    if (reason !== undefined) throw new Error(reason)
    return next()
  }, intentOptions)

  // 鈹€鈹€ Operator surface 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
  // The model's copy of the rules. Without this the plugin is a wall the model
  // keeps walking into: it gets blocked, tries a variant, and the user pays for
  // both. Placement 3120 sits after the tool sections (TOOL_COMPUTER_USE 3000,
  // MCP_SERVERS 3100) and well before the persona suffix.
  const systemPrompt = service('systemPrompt')
  if (settings.modelGuidance && typeof systemPrompt?.section === 'function') {
    ctx.effect(() => systemPrompt.section({
      name: 'system-protection',
      order: 3120,
      text: MODEL_GUIDANCE,
      interpolate: false,
    }))
  }
  else if (settings.modelGuidance) {
    log.warn('system-protection: no systemPrompt service, so the model was not told about these limits')
  }

  // ── Operator surface ─────────────────────────────────────────────────────
  const commands = service('commands')
  if (typeof commands?.register === 'function') {
    ctx.effect(() => commands.register({
      name: 'system-protection',
      description: 'Show what the system file protection plugin enforces, or dry-run a command or path.',
      input: { hint: 'status | test <shell command or path> | reset' },
      handler: ({ agent, rawInput }) => {
        const line = String(rawInput ?? '').trim()
        const sub = (line.split(/\s+/)[0] ?? 'status').toLowerCase()
        if (sub === 'reset') {
          audit.reset()
          return { kind: 'success', text: 'system-protection: counters and the recent list were cleared.' }
        }
        if (sub === 'test') {
          const rest = line.slice('test'.length).trim()
          if (rest === '') return { kind: 'error', text: 'Usage: /system-protection test <shell command or absolute path>' }
          const sessionRoot = sessionRootOf({ agent })
          const looksLikeCommand = /(?:^|\s)(?:rm|del|rd|rmdir|remove-item|mv|move-item|find|git|xargs)(\s|$)/i.test(rest) || /[;&|`$]/.test(rest)
          const outcome = looksLikeCommand
            ? scanCommand({ command: rest, cwd: sessionRoot, dialect: /\b(remove-item|del|rd|pwsh|powershell)\b/i.test(rest) ? 'ps' : 'sh', ctx: sysctx, sessionRoot, fs, protectWrites: settings.protectWrites })
            : { findings: [], notes: ['path mode'] }
          if (!looksLikeCommand) {
            const verdict = classifyKey(pathKey(rest, sysctx), sysctx, { sessionRoot: pathKey(sessionRoot, sysctx) })
            if (verdict !== undefined) outcome.findings.push({ tier: verdict.tier, id: verdict.id, path: rest, raw: rest, via: 'path' })
          }
          if (outcome.findings.length === 0) return { kind: 'success', text: `system-protection: "${rest}" is not protected. It would run.` }
          const text = outcome.findings.map(hit => {
            const action = settings.tiers[hit.tier] ?? 'off'
            const label = TIER_LABEL[hit.tier]?.en ?? hit.tier
            return `${action.toUpperCase()}  ${hit.tier} (${label})  ${hit.id}\n  target: ${hit.path ?? hit.raw}${hit.note === undefined ? '' : `\n  why: ${hit.note}`}`
          }).join('\n')
          return { kind: 'success', text: `system-protection dry run (nothing was executed):\n${text}` }
        }
        const snapshot = audit.snapshot({
          enabled: settings.enabled,
          enforcement: settings.enforcement,
          protectWrites: settings.protectWrites,
          scanShell: settings.scanShell,
          genericPathSweep: settings.genericPathSweep,
          tiers: settings.tiers,
          exemptTools: [...settings.exemptSet],
          protectExtra: settings.protectExtra,
          allowExtra: settings.allowExtra,
          roots: {
            systemRoot: sysctx.roots.systemRoot,
            programFiles: sysctx.roots.programFiles,
            dshHome: sysctx.roots.dshHome,
            profileDir: sysctx.roots.profileDir,
            installDirs: sysctx.roots.installDirs,
            home: sysctx.roots.home,
          },
        })
        const recent = snapshot.recent.length === 0 ? '  (none yet)' : snapshot.recent.map(row => `  ${row.at} ${row.action.toUpperCase()} ${row.tool} 鈫?${row.hits.map(hit => `${hit.tier}:${hit.path}`).join(', ')}`).join('\n')
        const tiers = TIERS.map(tier => `  ${tier.padEnd(15)} ${settings.tiers[tier]}`).join('\n')
        return {
          kind: 'success',
          text: [
            `system-protection: enabled, ${settings.enforcement}. ${snapshot.total} call(s) inspected, ${snapshot.byAction.deny} denied, ${snapshot.byAction.ask} escalated, ${snapshot.byAction.error} internal error(s).`,
            'Tiers:',
            tiers,
            `Recent decisions:\n${recent}`,
            `Protected roots: ${[snapshot.roots.systemRoot, snapshot.roots.programFiles, snapshot.roots.dshHome, snapshot.roots.profileDir, snapshot.roots.home].filter(Boolean).join(', ')}`,
          ].join('\n'),
        }
      },
    }), 'system-protection status command')
  }
  else {
    log.info('system-protection: no command registry in this profile; /system-protection is unavailable')
  }

  const denyTiers = Object.entries(settings.tiers).filter(([, action]) => action === 'deny').map(([tier]) => tier)
  const askTiers = Object.entries(settings.tiers).filter(([, action]) => action === 'ask').map(([tier]) => tier)
  log.info(`system-protection: ${settings.enforcement}; deny=[${denyTiers.join(', ')}]; ask=[${askTiers.join(', ')}]; protectWrites=${settings.protectWrites}; scanShell=${settings.scanShell}; genericSweep=${settings.genericPathSweep}`)
  if (sysctx.selfInsideWorkspace) {
    // The one case where the plugin declines to guard its own files, so it is
    // never a silent surprise: someone developing this plugin in its own
    // workspace would otherwise be denied every edit in the tree.
    log.warn('system-protection: this plugin lives inside the session workspace, so its own files are not self-protected while that holds. System, credential, Harness and version-control roots are unaffected.')
  }
}
