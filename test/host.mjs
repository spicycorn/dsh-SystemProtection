/**
 * Shared stand-in for the Host: the services, the tool guard, the waterfall
 * listeners, and the command registry that `apply()` touches — nothing more.
 *
 * Both test suites drive the plugin through this, so the audit claims
 * ("it only ever answers, never acts") are measured on the same surface the
 * wiring claims are.
 */

import os from 'node:os'
import path from 'node:path'
import process from 'node:process'

export const isWin = process.platform === 'win32'
export const SYSTEM_TARGET = isWin ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32` : '/etc'
export const PROGRAM_FILES = isWin ? (process.env.ProgramFiles ?? 'C:\\Program Files') : '/usr'
// Deliberately *not* the repository: the plugin protects its own installation
// directory, so a session rooted there would (correctly) refuse any deletion.
export const WORKSPACE = path.join(os.tmpdir(), 'dsh-system-protection-demo')

/** Service keys the stub treats as inject-gated, i.e. property access throws unless declared. */
export const SERVICE_KEYS = new Set([
  'tools', 'commands', 'fs', 'sandboxPolicy', 'workingDirectory', 'pluginManager',
  'agents', 'sessions', 'systemPrompt', 'sessionPersistence',
])

/**
 * @param {{
 *   workspace?: string,
 *   resolveMode?: string,
 *   inject?: string[],
 *   withoutSandboxPolicy?: boolean,
 * }} [options]
 */
export function createHost(options = {}) {
  const workspace = options.workspace ?? WORKSPACE
  const injected = new Set(options.inject ?? ['tools'])
  /** Services a profile might simply not provide; `get()` answers undefined. */
  const hidden = new Set(options.without ?? [])
  const listeners = []
  const guards = []
  const commands = []
  const sections = []
  const cleanups = []
  const logs = []
  /** Every property access the plugin made for a service it never declared. */
  const serviceDenials = []

  const sandboxPolicy = options.withoutSandboxPolicy ? undefined : {
    workspaceRoot: workspace,
    // The escalation case: the OS sandbox is wide open, so only the guard remains.
    resolve: () => ({ mode: options.resolveMode ?? 'danger-full-access', workspaceRoot: workspace, sessionId: 'fake' }),
  }

  const base = {
    locale: 'en',
    get(service) {
      if (hidden.has(service)) return undefined
      if (service === 'commands') {
        return {
          register(command) {
            commands.push(command)
            return () => commands.splice(commands.indexOf(command), 1)
          },
        }
      }
      if (service === 'fs') return { processPath: target => target.displayPath }
      if (service === 'workingDirectory') return { get: () => undefined }
      if (service === 'sandboxPolicy') return sandboxPolicy
      if (service === 'systemPrompt') {
        return {
          section(definition) {
            sections.push(definition)
            return () => sections.splice(sections.indexOf(definition), 1)
          },
          // Only the names this stub knows; the plugin must not need any of them.
          getSectionOrder: name => (name === 'MCP_SERVERS' ? 3100 : undefined),
        }
      }
      return undefined
    },
    logger(name) {
      return {
        info: line => logs.push(['info', name, line]),
        warn: line => logs.push(['warn', name, line]),
        error: line => logs.push(['error', name, line]),
      }
    },
    tools: {
      guard(fn) {
        guards.push(fn)
        return () => guards.splice(guards.indexOf(fn), 1)
      },
    },
    on(event, listener, listenerOptions) {
      listeners.push({ event, listener, prepend: listenerOptions?.prepend === true })
      listeners.sort((left, right) => Number(right.prepend) - Number(left.prepend))
      return () => listeners.splice(listeners.findIndex(entry => entry.listener === listener), 1)
    },
    effect(setup) {
      const cleanup = typeof setup === 'function' ? setup() : undefined
      if (typeof cleanup === 'function') cleanups.push(cleanup)
    },
  }

  // Cordis exposes a service as a `ctx` property only when the plugin declared
  // that key in `inject`, and the property access *throws* otherwise:
  // `cannot get property "sandboxPolicy" without inject`. A plugin that reads
  // such a property dies during activation and silently leaves the machine
  // unprotected — which really happened — so the stub refuses it the same way
  // instead of handing back `undefined`.
  const ctx = new Proxy(base, {
    get(target, key, receiver) {
      if (typeof key === 'string' && SERVICE_KEYS.has(key) && !injected.has(key)) {
        serviceDenials.push(key)
        throw new Error(`cannot get property "${key}" without inject`)
      }
      return Reflect.get(target, key, receiver)
    },
  })

  const agent = { session: { id: 'fake', cwd: workspace } }

  return {
    ctx,
    agent,
    guards,
    commands,
    sections,
    logs,
    workspace,
    serviceDenials,
    listenerCount: () => listeners.length,
    /** Guards in registration order; the first denial wins, like the Host. */
    runGuards(name, args) {
      const exec = { name, arguments: args, agent }
      for (const guard of guards) {
        const verdict = guard(exec)
        if (verdict !== undefined) return verdict
      }
      return undefined
    },
    async runPreExecute(name, args) {
      const exec = { name, arguments: args, agent }
      let executed = false
      const next = async () => { executed = true; return { kind: 'allow' } }
      for (const entry of listeners) {
        if (entry.event !== 'tools/pre-execute') continue
        const verdict = await entry.listener(exec, next)
        if (verdict !== undefined) return verdict
      }
      return executed ? { kind: 'allow' } : undefined
    },
    async runIntent(event, displayPath, actor) {
      let reached = false
      const next = () => { reached = true }
      for (const entry of listeners) {
        if (entry.event !== event) continue
        const verdict = entry.listener({ targetKey: displayPath, displayPath }, actor, next)
        if (verdict !== undefined) return { threw: false, verdict, reached }
      }
      return { threw: false, verdict: undefined, reached }
    },
    async runIntentCatch(event, displayPath, actor) {
      try {
        const outcome = await this.runIntent(event, displayPath, actor)
        return { ...outcome, thrown: undefined }
      }
      catch (error) {
        return { threw: true, message: String(error?.message ?? error) }
      }
    },
    runCommand(name, rawInput) {
      const command = commands.find(candidate => candidate.name === name)
      if (command === undefined) throw new Error(`no command named ${name}`)
      return command.handler({ commandId: name, agent, rawInput, attachments: [], signal: new AbortController().signal })
    },
    disposeAll() {
      for (const cleanup of cleanups.reverse()) cleanup()
    },
  }
}
