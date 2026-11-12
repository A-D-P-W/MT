#!/usr/bin/env node
// Drives tools/guards.js against six structural breaks, each in a fresh scratch copy of the repository, and checks
// that the guard named for it fires (plus one unmodified control copy that must pass). This is how the module GUARDs
// themselves are tested: a guard that cannot fail proves nothing.
'use strict';
const fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const ROOT = path.resolve(__dirname, '..');
let acorn; try { acorn = require.resolve(process.env.GUARDS_ACORN || path.join(ROOT, 'node_modules', 'acorn')); }
catch (e) { console.log('SKIP guard_selftest: acorn not installed (run npm ci)'); process.exit(3); }
const COPY = ['modules', 'example', 'project', 'tools', 'tests/contract'];
const edit = (dir, file, from, to) => { const p = path.join(dir, file), s = fs.readFileSync(p, 'utf8');
  if (!s.includes(from)) throw new Error('selftest anchor not found in ' + file + ': ' + from.slice(0, 50)); fs.writeFileSync(p, s.replace(from, to)); };
const BREAKS = [
  { name: '(b) module reads a consumer global', want: /HtmlText\.gs:\d+ uses Example global EXAMPLE_OPTS/,
    apply: d => edit(d, 'modules/HtmlText/HtmlText.gs', "function htmlText_(html) {\n", "function htmlText_(html) {\n  if (EXAMPLE_OPTS.debug) return '';\n") },
  { name: '(b) module calls an Apps Script service its contract does not list', want: /SecurityNames\.gs:\d+ uses Apps Script service DriveApp, not listed/,
    apply: d => edit(d, 'modules/SecurityNames/SecurityNames.gs', "function isSecurityName_(s) {\n", "function isSecurityName_(s) {\n  DriveApp.getRootFolder();\n") },
  { name: '(b) top-level initializer runs code at load time', want: /PdfSafety\.gs:\d+ top-level initializer of PDF_DEFAULT_CAPS may run code/,
    apply: d => edit(d, 'modules/PdfSafety/PdfSafety.gs', 'const PDF_DEFAULT_CAPS = { maxBytes: 20 * 1024 * 1024, inflateCap: 8 * 1024 * 1024, maxObjStm: 200 };',
      'const PDF_DEFAULT_CAPS = Object.freeze({ maxBytes: 20 * 1024 * 1024, inflateCap: 8 * 1024 * 1024, maxObjStm: 200 });') },
  { name: '(a) module behavior changed without a new version row', want: /modules\/SenderTrust: source or contract changed without a new version row/,
    apply: d => edit(d, 'modules/SenderTrust/SenderTrust.gs', 'if (want.length < 6) return false;', 'if (want.length < 5) return false;') },
  { name: '(c) contract test reaches an Internal helper', want: /HtmlText\.example\.test\.js: references Internal helper htCut_/,
    apply: d => edit(d, 'tests/contract/HtmlText.example.test.js', 'const H = { htmlText_ };', 'const H = { htmlText_ }; const cut = H.htCut_;') },
  { name: '(c) consumer uses an export its contract test never exercises', want: /PdfSafety\.example\.test\.js: Example uses PdfSafety\.PDF_MAX_CAPS but its contract test never exercises it/,
    apply: d => edit(d, 'example/ExampleTriage.gs', '  const cp = caps || PDF_DEFAULT_CAPS;\n', '  const cp = caps || PDF_DEFAULT_CAPS;\n  if (cp.maxBytes > PDF_MAX_CAPS.maxBytes) return { verdict: \'REVIEW\', hard: [], soft: [\'CapsInvalid\'] };\n') },
];
const run = dir => { try { return { rc: 0, out: cp.execFileSync(process.execPath, [path.join(dir, 'tools', 'guards.js')], { cwd: dir, encoding: 'utf8', env: Object.assign({}, process.env, { GUARDS_ACORN: acorn }) }) }; }
  catch (e) { return { rc: e.status, out: String(e.stdout || '') + String(e.stderr || '') }; } };
const scratch = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-selftest-')); for (const c of COPY) fs.cpSync(path.join(ROOT, c), path.join(d, c), { recursive: true }); return d; };
let pass = 0, fail = 0; const ok = (c, m, extra = '') => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m + (c || !extra ? '' : '  -- ' + extra)); };
{ const d = scratch(); const r = run(d); ok(r.rc === 0 && /^OK module guards: 4 modules/m.test(r.out), 'control: an unmodified copy passes the guards', r.out.trim().split('\n').slice(0, 3).join(' | ')); fs.rmSync(d, { recursive: true, force: true }); }
for (const b of BREAKS) {
  const d = scratch(); b.apply(d); const r = run(d);
  ok(r.rc === 1 && b.want.test(r.out), `caught: ${b.name}`, `exit ${r.rc}: ` + r.out.trim().split('\n').slice(0, 3).join(' | '));
  fs.rmSync(d, { recursive: true, force: true });
}
console.log(`\n${pass} passed, ${fail} failed (${BREAKS.length} structural breaks + 1 control)`);
process.exit(fail ? 1 : 0);
