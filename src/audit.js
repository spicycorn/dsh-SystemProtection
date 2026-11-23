/**
 * Bounded, in-process record of what the plugin decided, for the
 * `/system-protection status` command and the Host log. The session log already
 * holds every denial the model saw (it is the tool error); this is the operator
 * view: counters by tier and the most recent verdicts.
 *
 * @module system-protection/audit
 */

/** @param {number} count */
function emptyCounts(count) {
  const out = Object.create(null)
  for (const key of count) out[key] = 0
  return out
}

/**
 * @param {{
 *   logger?: { warn?: (line: string) => void, info?: (line: string) => void, error?: (line: string) => void },
 *   limit?: number,
 *   logPath?: string,
 *   fs?: typeof import('node:fs'),
 * }} [options]
 */
export function createAudit(options = {}) {
  const limit = options.limit ?? 40
  const logger = options.logger
  const logPath = options.logPath === undefined ? '' : String(options.logPath).trim()
  const fsx = options.fs
  const recent = []
  const byAction = emptyCounts(['deny', 'ask', 'allow', 'error'])
  const byTier = Object.create(null)
  let startedAt = Date.now()
  let total = 0

  const record = (entry) => {
    total += 1
    const action = entry.action in byAction ? entry.action : 'allow'
    byAction[action] += 1
    if (action !== 'allow') {
      for (const hit of entry.hits ?? []) byTier[hit.tier] = (byTier[hit.tier] ?? 0) + 1
    }
    recent.push({
      at: new Date().toISOString(),
      tool: entry.tool,
      action: entry.action,
      hits: (entry.hits ?? []).slice(0, 6).map(hit => ({ tier: hit.tier, id: hit.id, path: hit.path ?? hit.raw, op: hit.op })),
    })
    while (recent.length > limit) recent.shift()

    if (action !== 'allow' && logger?.warn !== undefined) {
      const summary = (entry.hits ?? []).slice(0, 3).map(hit => `${hit.tier}:${hit.path ?? hit.raw}`).join(' ')
      logger.warn(`system-protection ${action.toUpperCase()} ${entry.tool} ${summary}`.trim())
    }
    if (action === 'error' && logger?.error !== undefined) logger.error(`system-protection internal error: ${entry.message}`)

    if (logPath !== '' && fsx !== undefined) {
      try {
        fsx.appendFileSync(logPath, `${JSON.stringify(recent[recent.length - 1])}\n`)
      }
      catch {
        // An unwritable audit path must never change a verdict.
      }
    }
  }

  return {
    record,
    /** Operator-facing summary for the `/system-protection status` command. */
    snapshot(extra = {}) {
      return {
        total,
        byAction,
        byTier,
        recent: recent.slice(-10).reverse(),
        uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
        ...extra,
      }
    },
    reset() {
      recent.length = 0
      for (const key of Object.keys(byAction)) byAction[key] = 0
      for (const key of Object.keys(byTier)) delete byTier[key]
      total = 0
      startedAt = Date.now()
    },
  }
}
