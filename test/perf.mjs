/**
 * Performance guard.
 *
 * The tool guard runs synchronously on the pipeline that every DSH tool call
 * crosses, so a slow path here is a slow session. This measures the scanner
 * against inputs chosen to be hostile to a text scanner — a megabyte of
 * command, twenty thousand segments, quote soup, sixty levels of `bash -c`
 * nesting, thousands of globs — and asserts it stays a rounding error next to
 * the tool it is judging.
 *
 * Thresholds are deliberately generous: they exist to catch a regression into
 * quadratic behaviour, not to benchmark a laptop.
 *
 * `node test/perf.mjs`
 */

import assert from 'node:assert/strict'
import process from 'node:process'

import { decideToolCall } from '../src/policy.js'
import { createSystemContext } from '../src/system-context.js'

const ctx = createSystemContext({})
const isWin = process.platform === 'win32'
const SYSTEM = isWin ? `${process.env.SystemRoot ?? 'C:\\Windows'}\\System32` : '/usr/bin'
const base = {
  ctx,
  sessionRoot: process.cwd(),
  tierActions: { system: 'deny', workspaceRoot: 'deny' },
  protectWrites: true,
  scanShell: true,
  genericPathSweep: true,
  resolveSymlinksInsideWorkspace: false,
}

const QUOTE = '"'
const CASES = {
  'ordinary rm': { expect: 'allow', command: 'rm -rf ./build && echo done' },
  'long benign command (1 MB)': { expect: 'allow', command: `echo ${'x'.repeat(1024 * 1024)}` },
  '20 000 chained segments': { expect: 'deny', command: Array.from({ length: 20_000 }, () => `rm -rf ${SYSTEM}`).join(' && ') },
  '20 000 chained segments, all safe': { expect: 'allow', command: Array.from({ length: 20_000 }, () => 'rm -rf ./out').join(' && ') },
  'quote soup around a real target': { expect: 'deny', command: QUOTE.repeat(4000) + `rm -rf ${SYSTEM}` + QUOTE.repeat(4000) },
  '60 levels of bash -c': { expect: 'deny', command: 'bash -c '.repeat(60) + JSON.stringify(`rm -rf ${SYSTEM}`) },
  '5 000 globs under the system tree': { expect: 'deny', command: `rm -rf ${Array.from({ length: 5000 }, (_, i) => `${SYSTEM}/pkg${i}/*`).join(' ')}` },
  'base64 blob that is not a payload': { expect: 'allow', command: `powershell -EncodedCommand ${'A'.repeat(200_000)}` },
  'workspace glob sweep (must stay allow)': { expect: 'allow', command: 'rm -rf ' + Array.from({ length: 5000 }, (_, i) => `./out/${i}/*.tmp`).join(' ') },
}

const LIMITS = {
  'ordinary rm': 30,
  'long benign command (1 MB)': 1500,
  '20 000 chained segments': 1500,
  '20 000 chained segments, all safe': 1500,
  'quote soup around a real target': 400,
  '60 levels of bash -c': 400,
  '5 000 globs under the system tree': 1500,
  'base64 blob that is not a payload': 400,
  'workspace glob sweep (must stay allow)': 1500,
}

let passed = 0
const failures = []
const rows = []

for (const [label, spec] of Object.entries(CASES)) {
  // Warm the JIT once, then time the run a hostile call would actually pay.
  decideToolCall({ ...base, name: 'bash', args: { command: spec.command } })
  const started = process.hrtime.bigint()
  const decision = decideToolCall({ ...base, name: 'bash', args: { command: spec.command } })
  const ms = Number(process.hrtime.bigint() - started) / 1e6
  rows.push({ label, ms, action: decision.action, hits: decision.hits.length })
  const limit = LIMITS[label]
  if (ms <= limit) passed += 1
  else failures.push(`${label}: ${ms.toFixed(1)} ms exceeded ${limit} ms`)
  if (decision.action !== spec.expect) {
    failures.push(`${label}: expected ${spec.expect}, got ${decision.action} (${decision.hits.length} hits)`)
  }
}

// A third-party tool whose arguments hide a path several levels down.
const nested = { recursive: true, opts: { deep: { deeper: { path: SYSTEM } } }, more: [{ file_path: `${SYSTEM}/hosts` }] }
const startedNested = process.hrtime.bigint()
const nestedDecision = decideToolCall({ ...base, name: 'mcp__files__remove_paths', args: nested })
const nestedMs = Number(process.hrtime.bigint() - startedNested) / 1e6
rows.push({ label: 'nested unknown-tool arguments', ms: nestedMs, action: nestedDecision.action, hits: nestedDecision.hits.length })
if (nestedMs <= 20) passed += 1
else failures.push(`nested unknown-tool arguments: ${nestedMs.toFixed(1)} ms exceeded 20 ms`)
if (nestedDecision.action !== 'deny') failures.push(`nested unknown-tool arguments: expected deny, got ${nestedDecision.action}`)

for (const row of rows) console.log(`  ${row.label.padEnd(42)} ${row.ms.toFixed(2).padStart(9)} ms  ${row.action}  hits=${row.hits}`)
console.log(`system-protection performance: ${passed} checks passed, ${failures.length} failed`)
for (const failure of failures) console.error(`FAIL ${failure}`)
if (failures.length > 0) process.exitCode = 1
assert.ok(rows.length > 0)
