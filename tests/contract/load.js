// Contract-test loader: evaluates ONLY the named module files (in registry order) — never a consumer's own file —
// with the globals the test injects. Usage: const lib = load(['PdfSafety'], {}, ['scanPdf_']);
const fs = require('fs'), path = require('path');
// Order = project/modules.order (one source for the loader and the project list).
const ORDER = require(path.join(__dirname, '..', '..', 'tools', 'projects.js')).moduleOrder(path.join(__dirname, '..', '..'));
// Internal helpers (names in a module's "## Internal" section that do not start a Public bullet) cannot be requested
// (tests must not reach Internals, whatever syntax they use).
const internalOf = m => { const t = fs.readFileSync(path.join(__dirname, '..', '..', 'modules', m, 'CONTRACT.md'), 'utf8');
  const sec = h => (new RegExp('^## ' + h + '[^\\n]*\\n([\\s\\S]*?)(?=^## )', 'm').exec(t) || [])[1] || '';
  const pub = new Set([...sec('Public API').matchAll(/^- `([^`]*)`/gm)].flatMap(x => x[1].split(',').map(y => (/^\s*([A-Za-z_$][\w$]*)/.exec(y) || [])[1]).filter(Boolean)));
  return new Set([...sec('Internal').matchAll(/\b([A-Za-z_$][\w$]*_|[A-Z][A-Z0-9_]+)\b/g)].map(x => x[1]).filter(n => !pub.has(n))); };
module.exports = function load(mods, globals, names) {
  const internal = new Set(mods.flatMap(m => [...internalOf(m)]));
  const refused = names.filter(n => internal.has(n));
  if (refused.length) throw new Error('contract tests may not load Internal helpers: ' + refused.join(', '));
  const src = ORDER.filter(m => mods.includes(m)).map(m => fs.readFileSync(path.join(__dirname, '..', '..', 'modules', m, m + '.gs'), 'utf8')).join('\n;\n');
  const g = Object.assign({ Logger: { log() {} } }, globals || {});
  const keys = Object.keys(g);
  return new Function(...keys, src + '\n;return {' + names.join(', ') + '};')(...keys.map(k => g[k]));
};
