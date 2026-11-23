/**
 * Packaging preflight: everything a plugin *declares* must exist where the Host
 * will look for it.
 *
 * This exists because an install from GitHub failed with
 *   ENOENT: no such file or directory, scandir '<package>/locale'
 * while the same checkout worked as a `link:` install. A linked install reads
 * the working tree, so a file that never made it into the published copy stays
 * invisible until someone else installs it. The Host is strict here: metadata is
 * read from the *exported* locale files, and a declared detail document that is
 * missing is an error, not a README fallback.
 *
 * So every path this package points at is checked: manifest exports, the `files`
 * allow-list, the patch, each locale's `meta.detail`, the icon, the runtime
 * imports, and — when this checkout is a repository — that git will actually
 * hand the files over. Run by `npm test`.
 */

import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const failures = []
let passed = 0

const check = (label, fn) => {
  try {
    fn()
    passed += 1
  }
  catch (error) {
    failures.push(`${label}: ${error?.message ?? error}`)
  }
}

const read = relative => fs.readFileSync(path.join(ROOT, relative), 'utf8')
const exists = relative => fs.existsSync(path.join(ROOT, relative))
const assert = (condition, message) => {
  if (!condition) throw new Error(message)
}

const walk = dir => {
  const found = []
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) found.push(...walk(full))
    else found.push(full)
  }
  return found
}

/** `src/*.js` and `docs` patterns, compiled without placeholders. */
function globToRegExp(pattern) {
  let source = '^'
  for (let at = 0; at < pattern.length; at++) {
    const char = pattern[at]
    if (char === '*') {
      if (pattern[at + 1] === '*') {
        source += '[^/]+(?:/[^/]+)*'
        at++
      }
      else source += '[^/]*'
      continue
    }
    if (char === '?') {
      source += '[^/]'
      continue
    }
    source += /[.+^${}()|[\]\\]/.test(char) ? `\\${char}` : char
  }
  return new RegExp(`${source}$`)
}

/** Match a package-relative glob (`src/*.js`, `docs`, `locale/*.json`) to real files. */
function globFiles(pattern) {
  const normalized = pattern.replace(/^\.\//, '')
  const base = normalized.replace(/[*?].*$/, '').replace(/\/$/, '') || '.'
  const absolute = path.join(ROOT, base)
  if (!fs.existsSync(absolute)) return []
  if (!/[*?]/.test(normalized)) {
    return fs.statSync(absolute).isDirectory()
      ? walk(absolute).map(full => path.relative(ROOT, full).split(path.sep).join('/'))
      : [normalized]
  }
  const expression = globToRegExp(normalized)
  const from = path.join(ROOT, normalized.includes('/') ? normalized.slice(0, normalized.indexOf('/')) : '.')
  return walk(from)
    .map(full => path.relative(ROOT, full).split(path.sep).join('/'))
    .filter(relative => expression.test(relative))
}

const manifest = JSON.parse(read('package.json'))

check('manifest carries the fields the Host reads', () => {
  for (const field of ['name', 'version', 'type', 'exports', 'files']) {
    assert(manifest[field] !== undefined, `package.json has no "${field}"`)
  }
  assert(manifest.dsh?.bundle?.patch !== undefined, 'package.json has no dsh.bundle.patch — it is a bundle, not just a package')
  assert(exists(manifest.dsh.bundle.patch.replace(/^\.\/?/, '')), `dsh.bundle.patch points at a missing file: ${manifest.dsh.bundle.patch}`)
})

check('every exports target exists', () => {
  for (const [specifier, target] of Object.entries(manifest.exports ?? {})) {
    const targets = Array.isArray(target) ? target : [target]
    for (const entry of targets) {
      if (typeof entry !== 'string' || !entry.startsWith('./')) continue
      const relative = entry.slice(2)
      const matched = /[*?]/.test(relative) ? globFiles(relative) : exists(relative) ? [relative] : []
      assert(matched.length > 0, `exports["${specifier}"] -> ${entry} matches no file`)
    }
  }
})

check('every files entry matches at least one real file', () => {
  for (const pattern of manifest.files ?? []) {
    assert(globFiles(pattern).length > 0, `files lists "${pattern}" but nothing in the tree matches it — a packed install will not contain it`)
  }
})

check('the bundle row in the patch matches the package name', () => {
  const patch = read(manifest.dsh.bundle.patch.replace(/^\.\/?/, ''))
  assert(patch.includes(`'${manifest.name}'`) || patch.includes(`"${manifest.name}"`),
    `the patch does not reference the package name ${manifest.name}`)
})

const localeFiles = globFiles('locale/*.json')
const languages = files => new Set(files.map(file => path.basename(file, '.json')))

check('locale files exist, because metadata comes from the exports map', () => {
  assert(localeFiles.length > 0, 'no locale/*.json — Plugin Manager reads meta.title and meta.description from them')
  assert(manifest.exports?.['./locale/*.json'] !== undefined, 'package.json must export "./locale/*.json"')
  assert((manifest.files ?? []).some(entry => entry.includes('locale')), 'files must keep the locale directory in a packed install')
})

const metaKeys = key => localeFiles.reduce((names, file) => {
  const meta = JSON.parse(read(file)).meta
  if (meta?.[key] !== undefined) names.add(path.basename(file, '.json'))
  return names
}, new Set())

check('every locale declares the same meta fields', () => {
  for (const key of ['title', 'description', 'detail']) {
    const present = metaKeys(key)
    assert(present.size === 0 || present.size === localeFiles.length,
      `meta.${key} is declared in [${[...present].join(', ')}] but not in all of [${[...languages(localeFiles)].join(', ')}]`)
  }
})

// Existence cannot be inferred from what happens to be on disk: the day a locale
// file is missing, "all locales agree" is trivially true. So the required set is
// named, and each language is cross-checked against the documents it points at.
check('the locales the package promises are the locales it ships', () => {
  const shipped = languages(localeFiles)
  assert(shipped.has('en'), 'locale/en.json is missing — it is where the language chain falls back to')
  const documented = new Set(globFiles('docs/*')
    .map(relative => /DETAIL\.([a-z]{2}(?:-[a-z]{2})?)\.md$/.exec(relative)?.[1])
    .filter(Boolean))
  for (const language of documented) {
    assert(shipped.has(language), `docs/DETAIL.${language}.md is shipped but locale/${language}.json is not, so no reader is ever pointed at it`)
  }
  for (const file of localeFiles) {
    const language = path.basename(file, '.json')
    const meta = JSON.parse(read(file)).meta ?? {}
    if (language === 'en' || meta.detail === undefined) continue
    assert(exists(meta.detail), `locale/${language}.json points at "${meta.detail}", which is not in the package`)
  }
})

check('locale titles and descriptions are non-empty and single-line', () => {
  for (const file of localeFiles) {
    const meta = JSON.parse(read(file)).meta ?? {}
    for (const key of ['title', 'description']) {
      const value = meta[key]
      assert(typeof value === 'string' && value.trim().length > 0, `${file} has no meta.${key}`)
      if (key === 'title') assert(!/\n/.test(value), `${file} meta.title must be one line`)
    }
  }
})

check('a declared meta.detail exists — a missing document is an error, not a README fallback', () => {
  for (const file of localeFiles) {
    const meta = JSON.parse(read(file)).meta ?? {}
    if (meta.detail === undefined) continue
    assert(!meta.detail.startsWith('/') && !meta.detail.includes('..'), `${file}: meta.detail must stay inside the package: ${meta.detail}`)
    assert(/\.(md|markdown)$/.test(meta.detail), `${file}: meta.detail must be markdown: ${meta.detail}`)
    const absolute = path.join(ROOT, meta.detail)
    assert(fs.existsSync(absolute), `${file} declares meta.detail "${meta.detail}" and that file does not exist`)
    assert(fs.statSync(absolute).size < 1024 * 1024, `${meta.detail} exceeds the Host's 1 MiB detail limit`)
    // A document embedding an image the package does not ship fails the same way.
    for (const match of read(meta.detail).matchAll(/!\[[^\]]*\]\(([^)\s]+)/g)) {
      const image = match[1]
      if (/^https?:/.test(image)) continue
      assert(exists(path.posix.join(path.posix.dirname(meta.detail), image)),
        `${meta.detail} embeds "${image}", which is not in the package`)
    }
  }
})

check('the icon is exported, real, small, and inert', () => {
  const target = manifest.exports?.['./icon']
  assert(typeof target === 'string', 'package.json must export "./icon"')
  const relative = target.slice(2)
  assert(exists(relative), `exported icon "${relative}" does not exist`)
  const bytes = fs.statSync(path.join(ROOT, relative)).size
  assert(bytes <= 256 * 1024, `icon is ${bytes} bytes; the Host limit is 256 KiB`)
  const text = read(relative)
  if (/\.svg$/i.test(relative)) {
    assert(/<svg\b/.test(text), 'icon.svg does not look like SVG')
    assert(!/<script|on[a-z]+\s*=/i.test(text), 'icon.svg contains script or event handlers')
  }
})

check('every runtime import of index.js is shipped', () => {
  const source = read('index.js')
  const imports = [...source.matchAll(/from\s+['"](\.[^'"]+)['"]/g)].map(match => match[1])
  assert(imports.length > 0, 'index.js imports nothing — has the import scan broken?')
  const shipped = new Set((manifest.files ?? []).flatMap(pattern => globFiles(pattern)))
  for (const specifier of imports) {
    const relative = path.posix.join(specifier).replaceAll('\\', '/')
    assert(exists(relative), `index.js imports "${specifier}", which does not exist`)
    assert(shipped.has(relative), `index.js imports "${relative}", which package.json files would leave out of a packed install`)
  }
})

check('test scripts referenced by npm test exist', () => {
  const script = manifest.scripts?.test ?? ''
  for (const match of script.matchAll(/node\s+([\w./-]+\.mjs)/g)) {
    assert(exists(match[1]), `npm test runs ${match[1]}, which does not exist`)
  }
})

// The failure that started this: a file in the working tree that git never
// published. Checked whenever this checkout is a repository.
check('git will actually hand the files over', () => {
  if (!fs.existsSync(path.join(ROOT, '.git'))) return
  const tracked = new Set(execFileSync('git', ['ls-files'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter(Boolean))
  for (const relative of [...globFiles('locale/*.json'), 'icon.svg', 'index.js', 'cordis.patch.yml']) {
    assert(tracked.has(relative), `"${relative}" is not tracked by git, so a GitHub install will not contain it`)
  }
  const untracked = execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: ROOT, encoding: 'utf8' })
    .split('\n').filter(line => line.startsWith('??'))
    assert(untracked.length === 0, `uncommitted files will be missing from a GitHub install: ${untracked.map(line => line.slice(3)).join(', ')}`)
})

console.log(`system-protection packaging preflight: ${passed} checks passed, ${failures.length} failed`)
for (const failure of failures) console.error(`FAIL ${failure}`)
if (failures.length > 0) process.exitCode = 1
