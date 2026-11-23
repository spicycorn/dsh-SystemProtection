/**
 * The words this plugin puts in front of a person, and in front of the model.
 *
 * Two audiences, deliberately different.
 *
 * The approval card is the harder one. `ApprovalRequest` carries `agent`,
 * `toolName`, `callId`, `reason`, and `displayReason` — no title, no severity,
 * no source-plugin field — so a plugin cannot make the Host render its question
 * in a different colour or with a different label. The only lever is the text
 * itself. Therefore the ask text opens with a fixed marker a user can learn to
 * recognise, and tells them what to demand before they approve.
 *
 * The model gets one short system-prompt section: the limit, and the rule that
 * the reason must be written down *before* the call, not after a prompt appears.
 *
 * @module system-protection/guidance
 */

import { TIER_LABEL } from './rules.js'

/** The first line of every ask this plugin raises. Stable: users learn it. */
export const ASK_MARKER = Object.freeze({
  en: '⚠ SYSTEM PROTECTION plugin — this is NOT a routine permission request',
  zh: '⚠ 系统保护插件请求确认 —— 这不是普通的权限请求，请勿习惯性放行',
})

const OP_LABEL = Object.freeze({
  delete: { en: 'delete', zh: '删除' },
  overwrite: { en: 'overwrite', zh: '覆盖' },
  'move-source': { en: 'move', zh: '移动' },
})

/** At most this many paths on the card; more would push the question off-screen. */
const MAX_PATHS = 4

function label(table, key, locale) {
  const entry = table[key]
  if (entry === undefined) return key
  return entry[locale] ?? entry.en
}

/**
 * The text on the approval card. `decision` is a decision from the policy layer;
 * the audit `reason` stays the plain factual sentence built by `formatReason`.
 */
export function askDisplayReason(decision, { locale = 'en', note = '' } = {}) {
  const language = locale === 'zh' ? 'zh' : 'en'
  const hits = Array.isArray(decision?.hits) ? decision.hits : []
  const lines = [ASK_MARKER[language]]

  if (language === 'zh') {
    lines.push('这次调用会改动受保护的位置，需要你当场判断是否放行。')
  }
  else {
    lines.push('This call would change a protected location, and it needs your judgement now.')
  }

  for (const hit of hits.slice(0, MAX_PATHS)) {
    const op = label(OP_LABEL, String(hit.op ?? ''), language)
    const what = op === '' ? '' : `[${op}] `
    lines.push(`  · ${label(TIER_LABEL, hit.tier, language)} ${what}${hit.path ?? hit.raw ?? ''}`)
  }
  if (hits.length > MAX_PATHS) {
    lines.push(language === 'zh' ? `  · ……还有 ${hits.length - MAX_PATHS} 处` : `  · …and ${hits.length - MAX_PATHS} more`)
  }

  if (language === 'zh') {
    lines.push('批准之前，先让 AI 用一句话说清：为什么必须动这里，以及改坏了会失去什么。')
    lines.push('它给不出具体理由，就点拒绝。')
  }
  else {
    lines.push('Before approving, ask the AI for one sentence: why this location has to change, and what is lost if it goes wrong.')
    lines.push('If it cannot answer concretely, reject.')
  }

  if (note !== '') lines.push(note)
  return lines.join('\n')
}

/**
 * One static system-prompt section. Static on purpose: the assembled prompt is
 * committed as a surface node and replaced only when the text changes, so a
 * varying paragraph would invalidate it on every step.
 */
export const MODEL_GUIDANCE = [
  'A system-file protection plugin is active in this Harness.',
  'Calls that would delete or overwrite operating-system, Harness, credential, or version-control paths are blocked outright.',
  'Calls touching user data (Documents, Desktop, AppData) or secret files (.env, .npmrc, id_rsa, .git-credentials) raise a confirmation the user must answer by hand, one call at a time.',
  'Never try to route around a block: no renamed command, no script written to disk first, no alternate tool, no rephrasing. State the limit and offer a workspace-local alternative instead.',
  'Before any call that touches those areas, write in your visible reply why the change is necessary, what it affects, and what would be lost if it went wrong — the user is being asked to decide on your word, and a confirmation they cannot reason about is one you should not have requested.',
].join(' ')
