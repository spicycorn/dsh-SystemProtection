import fs from 'node:fs'
const targets = process.argv.slice(2)
for (const p of targets) {
  try {
    console.log('== ' + p)
    console.log(fs.readdirSync(p).join('\n'))
  }
  catch (error) {
    console.log(p + ' -> ' + error.message)
  }
}
