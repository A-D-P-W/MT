// White-box loader for unit tests: evaluates module files (registry order) and returns any top-level names, Internal
// helpers included. Contract tests must use tests/contract/load.js instead, which refuses Internals.
const fs = require('fs'), path = require('path');
const ROOT = path.join(__dirname, '..', '..');
const ORDER = require(path.join(ROOT, 'tools', 'projects.js')).moduleOrder(ROOT);
let pass = 0, fail = 0;
module.exports = {
  ROOT,
  load(mods, globals, names) {
    const src = ORDER.filter(m => mods.includes(m)).map(m => fs.readFileSync(path.join(ROOT, 'modules', m, m + '.gs'), 'utf8')).join('\n;\n');
    const g = Object.assign({ Logger: { log() {} } }, globals || {});
    const keys = Object.keys(g);
    return new Function(...keys, src + '\n;return {' + names.join(', ') + '};')(...keys.map(k => g[k]));
  },
  ok(c, m, extra = '') { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m + (c || !extra ? '' : '  -- ' + extra)); },
  done() { console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0); },
};
