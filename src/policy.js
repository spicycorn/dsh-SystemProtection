/**
 * Decision layer: one model tool call in, one verdict out.
 *
 * Three recognition paths feed the same rule tables:
 * 1. declared file tools (`write`, `edit`, `apply_patch`, delete/move tools)
 *    by their argument names,
 * 2. shell tools (`bash`, `pwsh`, `terminal_send`, …) through the shell scanner,
 * 3. a generic "any tool argument that names a path" sweep, which only applies
 *    the tiers the user marked `deny`. This is what keeps an unknown MCP
 *    filesystem tool from deleting `C:\Windows` while producing no noise for
 *    ordinary workspace work.
 *
 * @module system-protection/policy
 */

import { expandVariables, normalizeAbsolute, stripQuotes } from './paths.js'
import { classifyKey, isCoreTier, TIER_LABEL } from './rules.js'
import { dialectFor, scanCommand } from './shell-scan.js'

/** Tier severity: the strictest action across all hits wins. */
const SEVERITY = { allow: 0, off: 0, ask: 1, deny: 2 }

/** Argument names that hold a mutated file path, per declared tool. */
const PATH_TOOL_KEYS = Object.freeze({
  write: ['file_path', 'path', 'target_file'],
  write_file: ['file_path', 'path', 'target_file'],
  create_file: ['file_path', 'path'],
  edit: ['file_path', 'path'],
  edit_file: ['file_path', 'path'],
  str_replace_editor: ['path'],
  search_replace: ['file_path'],
  'notebook-edit': ['notebook_path'],
  delete: ['path', 'file_path', 'target'],
  delete_file: ['path', 'file_path', 'target'],
  remove: ['path', 'file_path'],
  remove_file: ['path', 'file_path'],
  trash: ['path', 'file_path'],
  move: ['source', 'origin', 'src', 'from'],
  move_file: ['source', 'origin', 'src', 'from'],
  rename: ['source', 'old_path', 'from'],
  rename_file: ['source', 'old_path', 'from'],
})

/** Argument names whose arrays of strings are targets, per declared tool. */
const PATH_TOOL_ARRAYS = Object.freeze({
  delete: ['paths', 'files', 'targets'],
  delete_file: ['paths', 'files', 'targets'],
})

/** Tools whose whole `input` is patch text with delete/update semantics. */
const PATCH_TOOLS = new Set(['apply_patch'])
/** Tools whose `command`/`input` is a shell command line. */
const SHELL_KEYS = Object.freeze({
  bash: 'command',
  pwsh: 'command',
  powershell: 'command',
  shell: 'command',
  cmd: 'command',
  run_command: 'command',
  execute: 'command',
  exec: 'command',
  terminal_send: 'text',
  terminal_write: 'text',
  terminal_input: 'text',
  terminal_run: 'text',
})
/** Working-directory override a shell tool may carry. */
const CWD_KEYS = ['workdir', 'cwd', 'working_directory', 'directory']

/** Keys that make a third-party tool argument worth checking at deny tiers. */
const GENERIC_PATH_KEY_RE = /(?:^|_)(?:file_?path|path|target|destination|dest|dir|directory|source|src|origin|out_?file|out_?path|output|filename|root)$/i
const GENERIC_DIR_SKIP_RE = /(?:^|_)(?:cwd|workdir|working_directory|basedir|base_dir|root)$/i

/**
 * A tool name that looks like it changes something on disk.
 *
 * The generic sweep is the last-resort net for tools this plugin has never seen
 * (MCP servers, other bundles). Reading a protected file is legitimate —
 * `read /etc/passwd` must stay possible — so the net only fires for names that
 * say they write, delete, move, or patch, plus whatever the user adds to
 * `sweepTools`.
 */
const MUTATING_NAME_RE = /(?:^|[_\-.])(?:delete|remove|unlink|erase|destroy|purge|wipe|trash|rm|rmdir|mv|move|rename|copy|write|create|update|replace|edit|patch|apply|save|export|truncate|clear|format|clean|upload|store)(?:[_\-.]|$)/i

/** A tool call that names paths but is only an overwrite, not a removal. */
const OVERWRITE_TOOLS = new Set(['write', 'write_file', 'create_file', 'edit', 'edit_file', 'search_replace', 'str_replace_editor', 'notebook-edit'])

/**
 * @param {string} tier
 * @param {Record<string, string>} tierActions
 * @returns {'deny'|'ask'|'off'}
 */
export function actionForTier(tier, tierActions) {
  if (tier === 'allow') return 'off'
  const value = tierActions[tier]
  return value === 'deny' || value === 'ask' || value === 'off' ? value : 'off'
}

/**
 * Decide one tool call.
 *
 * @param {{
 *   name: string,
 *   args: unknown,
 *   ctx: object,
 *   sessionRoot?: string,
 *   cwd?: string,
 *   fs?: typeof import('node:fs'),
 *   tierActions: Record<string, string>,
 *   protectWrites: boolean,
 *   scanShell: boolean,
 *   resolveSymlinksInsideWorkspace: boolean,
 *   genericPathSweep: boolean,
 * }} input
 * @returns {{ action: 'allow'|'deny'|'ask', hits: object[], notes: string[] }}
 */
export function decideToolCall(input) {
  const { name, ctx } = input
  const args = input.args
  const parsed = typeof args === 'object' && args !== null ? args : {}
  const hits = []
  const notes = []
  const cwdOf = () => {
    for (const key of CWD_KEYS) {
      const value = parsed[key]
      if (typeof value === 'string' && value.trim() !== '') {
        const expanded = expandVariables(stripQuotes(value), ctx)
        const absolute = normalizeAbsolute(expanded.text, ctx, input.sessionRoot ?? ctx.cwd)
        if (absolute !== undefined) return absolute
      }
    }
    return input.sessionRoot ?? ctx.cwd
  }

  const push = (raw, base, meta) => {
    const absoluteRaw = expandVariables(stripQuotes(String(raw)), ctx)
    const absolute = normalizeAbsolute(absoluteRaw.text, ctx, base ?? input.sessionRoot ?? ctx.cwd)
    if (absolute === undefined) return
    const verdict = classifyKey(absolute, ctx, { sessionRoot: input.sessionRoot })
    if (verdict === undefined || verdict.tier === 'allow') return
    hits.push({ tier: verdict.tier, id: verdict.id, path: absolute, raw: String(raw), via: meta.via, op: meta.op, ...(meta.generic === true ? { generic: true } : {}) })
  }

  // 1. Declared file tools.
  const keys = PATH_TOOL_KEYS[name]
  if (keys !== undefined) {
    const op = OVERWRITE_TOOLS.has(name) && input.protectWrites ? 'overwrite' : 'delete'
    for (const key of keys) {
      const value = parsed[key]
      if (typeof value === 'string' && value.trim() !== '') push(value, undefined, { via: `arg:${key}`, op })
    }
    for (const key of PATH_TOOL_ARRAYS[name] ?? []) {
      const value = parsed[key]
      if (Array.isArray(value)) {
        for (const item of value) if (typeof item === 'string' && item.trim() !== '') push(item, undefined, { via: `arg:${key}[]`, op })
      }
    }
  }

  // 2. Patch text.
  if (PATCH_TOOLS.has(name) && typeof parsed.input === 'string') {
    for (const hit of parsePatchTargets(parsed.input)) {
      if (hit.op === 'overwrite' && input.protectWrites === false) continue
      push(hit.path, undefined, { via: hit.via, op: hit.op })
    }
  }

  // 3. Shell tools.
  const shellKey = SHELL_KEYS[name]
  if (shellKey !== undefined && input.scanShell !== false) {
    const command = parsed[shellKey]
    if (typeof command === 'string' && command.trim() !== '') {
      const dialect = dialectFor(name)
      // Early exit: as soon as one operand maps to `deny`, the verdict cannot get
      // stricter, so the rest of a megabyte-long command never gets tokenized.
      let judged = 0
      const stop = findings => {
        for (; judged < findings.length; judged++) {
          if (actionForTier(findings[judged].tier, input.tierActions) === 'deny') return true
        }
        return false
      }
      const scanned = scanCommand({
        command,
        dialect,
        cwd: cwdOf(),
        ctx,
        sessionRoot: input.sessionRoot,
        fs: input.fs,
        resolveSymlinksInsideWorkspace: input.resolveSymlinksInsideWorkspace,
        protectWrites: input.protectWrites,
        stop,
      })
      for (const finding of scanned.findings) hits.push(finding)
      notes.push(...scanned.notes)
    }
  }

  // 4. Generic sweep for tools this plugin has never seen (MCP, other bundles).
  const swept = input.genericPathSweep !== false
    && keys === undefined
    && shellKey === undefined
    && !PATCH_TOOLS.has(name)
    && !(input.sweepSkipTools ?? []).includes(name)
    && (MUTATING_NAME_RE.test(name) || (input.sweepTools ?? []).includes(name))
  if (swept) {
    for (const found of sweepPathArguments(parsed)) {
      if (found.directoryOnly) continue
      push(found.raw, undefined, { via: `arg:${found.key}`, op: 'delete', generic: true })
    }
  }

  let action = 'allow'
  for (const hit of hits) {
    const tierAction = actionForTier(hit.tier, input.tierActions)
    if (hit.generic && tierAction === 'ask') continue // unknown tools only ever trip deny tiers
    hit.action = tierAction
    if (SEVERITY[tierAction] > SEVERITY[action]) action = tierAction
  }
  return { action, hits: hits.filter(hit => hit.action === 'deny' || hit.action === 'ask'), notes }
}

/**
 * `*** Delete File:`, `*** Update File:`, `*** Move to:`, `*** Add File:`.
 * @param {string} text
 * @returns {Array<{ path: string, op: string, via: string }>}
 */
export function parsePatchTargets(text) {
  const out = []
  let current = { path: undefined, op: undefined }
  for (const line of String(text).split(/\r?\n/)) {
    const match = /^\*\*\*\s+(Add|Update|Delete|Move to)\s+File:\s*(.+)$|^\*\*\*\s+Move to:\s*(.+)$/i.exec(line.trim())
    if (match === null) continue
    const kind = (match[1] ?? 'Move to').trim().toLowerCase()
    const raw = (match[2] ?? match[3] ?? '').trim()
    if (raw === '') continue
    if (kind === 'move to') {
      // A move rewrites the destination and removes the source already recorded.
      out.push({ path: raw, op: 'overwrite', via: 'patch:Move to' })
      if (current.path !== undefined) out.push({ path: current.path, op: 'delete', via: 'patch:Move source' })
      continue
    }
    if (kind === 'delete') out.push({ path: raw, op: 'delete', via: 'patch:Delete File' })
    else if (kind === 'update') out.push({ path: raw, op: 'overwrite', via: 'patch:Update File' })
    current = { path: raw, op: kind }
  }
  return out
}

/**
 * Depth-limited walk collecting string values under path-shaped keys.
 * @param {Record<string, unknown>} parsed
 * @returns {Array<{ key: string, raw: string, absolute?: string, directoryOnly: boolean }>}
 */
export function sweepPathArguments(parsed) {
  const out = []
  const visit = (value, key, depth) => {
    if (value === null || value === undefined) return
    if (typeof value === 'string') {
      if (key !== undefined && GENERIC_PATH_KEY_RE.test(key) && value.trim() !== '') {
        out.push({ key, raw: value, directoryOnly: GENERIC_DIR_SKIP_RE.test(key) })
      }
      return
    }
    if (depth > 3) return
    if (Array.isArray(value)) {
      for (const item of value) visit(item, key, depth + 1)
      return
    }
    if (typeof value === 'object') {
      for (const [childKey, child] of Object.entries(value)) visit(child, childKey, depth + 1)
    }
  }
  visit(parsed, undefined, 0)
  return out
}

/**
 * Build the model-facing (and human-readable) reason for a verdict.
 *
 * @param {{ action: string, hits: object[] }} decision
 * @param {{ locale?: 'en'|'zh', note?: string }} [options]
 */
export function formatReason(decision, options = {}) {
  const locale = options.locale === 'zh' ? 'zh' : 'en'
  const shown = decision.hits.slice(0, 4)
  const lines = shown.map(hit => {
    const label = TIER_LABEL[hit.tier]?.[locale] ?? hit.tier
    const where = hit.path === undefined ? hit.raw : hit.path
    const how = hit.op === undefined ? '' : ` [${hit.op}]`
    const via = hit.via === undefined ? '' : ` (${hit.via})`
    return `- ${label}${how}${via}: ${where}`
  })
  const extra = decision.hits.length > shown.length ? `- …${decision.hits.length - shown.length} more` : undefined
  const core = decision.hits.some(hit => isCoreTier(hit.tier))

  if (locale === 'zh') {
    const head = decision.action === 'deny'
      ? '已被「系统文件保护」强制拦截：目标属于受保护路径，删除或覆盖会破坏系统。'
      : '「系统文件保护」要求你亲自确认：目标可能无法恢复。'
    const tail = options.note === undefined || options.note === '' ? '' : `\n补充说明：${options.note}`
    return [
      head,
      ...lines,
      ...(extra === undefined ? [] : [extra]),
      '请改用其它做法：只在会话工作区内操作、用「移到回收站/备份后再删」的方式、或让用户自己手动删除。用户也可以在插件配置里用 allowExtra 精确放行某个路径，或用 tiers 把某一级降为 ask/off。',
      ...(core ? ['命中的这几级（操作系统 / Harness 自身 / 凭据）默认没有任何商量余地，只能由用户写入 allowExtra。'] : []),
      '不要换一种写法绕过本保护。',
      tail,
    ].filter(line => line !== '').join('\n')
  }

  const head = decision.action === 'deny'
    ? 'Blocked by the System file protection plugin: the target is a protected path, and removing or overwriting it would damage the system.'
    : 'The System file protection plugin requires your explicit confirmation: this target may be unrecoverable.'
  const tail = options.note === undefined || options.note === '' ? '' : `\nPlugin note: ${options.note}`
  return [
    head,
    ...lines,
    ...(extra === undefined ? [] : [extra]),
    'Do what is safe instead: work inside the session workspace, back the file up or move it to a trash folder first, or ask the user to remove it by hand. The user can also allow one exact path with the plugin\'s allowExtra config, or lower a tier to ask/off.',
    ...(core ? ['The tiers hit here (operating system, the Harness itself, credentials) have no negotiation at all: only a user-authored allowExtra entry opens them.'] : []),
    'Do not rephrase the command to get around this protection.',
    tail,
  ].filter(line => line !== '').join('\n')
}

/** Compact one-line summary used for the Host log. */
export function formatLogLine(decision, toolName) {
  const hits = decision.hits.slice(0, 3).map(hit => `${hit.tier}:${hit.path ?? hit.raw}`).join(' ')
  return `${decision.action.toUpperCase()} ${toolName} ${hits}`.trim()
}
