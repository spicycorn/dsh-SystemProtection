// Bounded ASAR-aware search helper.
// usage: node asar-search.js <rootDir> <literalTerm> [nameFilterSubstring]
import fs from 'node:fs'
import path from 'node:path'

const root = process.argv[2];
const term = process.argv[3];
const nameFilter = process.argv[4] || '';
const MAX = 1024 * 1024;
let hits = 0;
const skip = process.env.SEARCH_ALL ? new Set(['.git']) : new Set(['node_modules', '.git', 'dist', 'lib', 'out']);

function* walk(dir, depth) {
  if (depth > 6) return;
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (e) {
    return;
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (skip.has(e.name)) continue;
      yield* walk(p, depth + 1);
    } else if (e.isFile() && /\.(js|mjs|cjs|ts|json|yml|yaml|md)$/.test(e.name)) {
      if (nameFilter && !e.name.includes(nameFilter)) continue;
      yield p;
    }
  }
}

for (const file of walk(root, 0)) {
  let size = 0;
  try {
    size = fs.statSync(file).size;
  } catch (e) {
    continue;
  }
  if (size > MAX) continue;
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (e) {
    continue;
  }
  if (!text.includes(term)) continue;
  const lines = text.split('\n');
  const matched = [];
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(term)) matched.push([i + 1, lines[i].slice(0, 200)]);
    if (matched.length >= 8) break;
  }
  console.log('== ' + path.relative(root, file));
  for (const [n, l] of matched) console.log('   ' + n + ': ' + l);
  if (++hits >= 25) {
    console.log('(truncated at 25 files)');
    break;
  }
}
console.log('# files with hits: ' + hits);
