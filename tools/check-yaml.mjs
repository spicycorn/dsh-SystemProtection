import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const sources = ['yaml', 'js-yaml']
let parse = null
let used = ''
for (const name of sources) {
  try {
    const mod = require(name)
    parse = mod.parse ?? mod.load ?? null
    if (parse !== null) { used = name; break }
  }
  catch { /* try the next one */ }
}
if (parse === null) {
  console.log('no yaml parser available in this runtime')
  process.exit(0)
}
const text = readFileSync(process.argv[2], 'utf8')
const value = parse(text)
console.log(used, '->', JSON.stringify(value))
