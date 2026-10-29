// Export only bundled translation strings used by Python's native consent UI.
// Node is a development/check dependency; the packaged app only reads JSON.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const context = { navigator: { languages: ['en'] } };
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(root, 'static/i18n.js'), 'utf8'), context);
const strings = vm.runInContext('STRINGS', context);
const source = fs.readFileSync(path.join(root, 'keymelier_core/consent.py'), 'utf8');
const keys = new Set(['native.confirm', 'native.target', 'native.warning']);
for (const match of source.matchAll(/"\w+": \("[^"]+", "([^"]+)"\)/g)) keys.add(match[1]);
if (keys.size < 20) throw Error('Native operation labels were not found');
const output = {};
for (const [lang, texts] of Object.entries(strings)) {
  output[lang] = {};
  for (const key of [...keys].sort()) {
    if (typeof texts[key] !== 'string') throw Error(`Missing ${lang}:${key}`);
    output[lang][key] = texts[key];
  }
}
const file = path.join(root, 'data/native-ui.json');
const data = JSON.stringify(output, null, 2) + '\n';
if (process.argv.includes('--check')) {
  if (fs.readFileSync(file, 'utf8') !== data) throw Error('Run node tools/export_native_text.cjs');
} else fs.writeFileSync(file, data);
