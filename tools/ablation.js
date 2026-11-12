#!/usr/bin/env node
// Guard ablation: removes one safety guard at a time from the module code (in a scratch copy of the repository), runs
// the behavioral suites (`SUITES=behavior ./run.sh`) and reports how many checks fail. A guard whose removal no check
// notices is a gap in the tests, not proof the guard is useless. Structural suites (GUARDs, hygiene) are left out:
// GUARD (a) fails on ANY module edit, so it would "catch" every mutation and hide what the tests themselves catch.
// A suite that runs out of time while no check has failed counts as MISSED (hang): the build goes red, but no test
// says what broke.
// Usage: node tools/ablation.js [--timeout <s>] [--only <id>]     (default timeout 60 s per suite)
'use strict';
const fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
const ROOT = path.resolve(__dirname, '..');
const arg = k => { const i = process.argv.indexOf(k); return i > 0 ? process.argv[i + 1] : null; };
const TIMEOUT = Number(arg('--timeout') || 60), ONLY = arg('--only');
const P = 'modules/PdfSafety/PdfSafety.gs', S = 'modules/SenderTrust/SenderTrust.gs', H = 'modules/HtmlText/HtmlText.gs', N = 'modules/SecurityNames/SecurityNames.gs';
// Each guard: the exact text removed or weakened (from → to). expect = the result recorded in README.md.
// Not in the list: the authserv-id re-check in authAligned_ ("clauses.shift() !== 'mx.google.com'"). Removing it is an
// equivalent mutant: topAuthResults_ only ever returns a header that starts with "mx.google.com;", so no input reaches it.
const GUARDS = [
  { id: 'pdf-js', file: P, what: 'hard keywords /JavaScript and /JS', expect: 'caught',
    from: "([['JavaScript', /\\/JavaScript\\b/], ['JS', /\\/JS\\b/], ['Launch'", to: "([['Launch'" },
  { id: 'pdf-launch', file: P, what: 'hard keyword /Launch', expect: 'caught',
    from: "['Launch', /\\/Launch\\b/], ", to: '' },
  { id: 'pdf-xfa-group', file: P, what: 'hard keywords /XFA /GoToE /GoToR /SubmitForm /ImportData /Rendition', expect: 'caught',
    from: ", ['XFA', /\\/XFA\\b/], ['GoToE', /\\/GoToE\\b/], ['GoToR', /\\/GoToR\\b/],\n                  ['SubmitForm', /\\/SubmitForm\\b/], ['ImportData', /\\/ImportData\\b/], ['Rendition', /\\/Rendition\\b/]]);", to: ']);' },
  { id: 'pdf-name-escapes', file: P, what: '#xx name-escape decoding (/J#61vaScript)', expect: 'caught',
    from: 'function pdfNames_(s) { return s.replace(', to: 'function pdfNames_(s) { return s; return s.replace(' },
  { id: 'pdf-objstm', file: P, what: 'object-stream inflation before the keyword scan', expect: 'caught',
    from: "  if (/\\/ObjStm\\b|\\/First\\s+\\d/.test(raw)) text += '\\n' + objStmText_(data, raw, hard, cp);\n", to: '' },
  { id: 'pdf-encrypt-objstm', file: P, what: 'hold for an encrypted object stream (ciphertext cannot be inspected)', expect: 'caught',
    from: "    if (enc) { hard.push('Encrypt+ObjStm'); return out; }", to: '' },
  { id: 'pdf-inflate-cap', file: P, what: 'inflate output cap (decompression bomb)', expect: 'caught',
    from: 'const t = inflateZlib_(data.substr(start, len), dest.subarray(0, budget));', to: 'const t = inflateZlib_(data.substr(start, len), new Uint8Array(64 * 1024 * 1024));' },
  { id: 'pdf-polyglot-tail', file: P, what: 'polyglot check after the last %%EOF', expect: 'caught',
    from: "    if (foreign(tail)) hard.push('Polyglot');\n", to: '' },
  { id: 'pdf-polyglot-prefix', file: P, what: 'polyglot check before %PDF- (PdfSafety.gs:68)', expect: 'caught',
    from: "if (head > 0) { soft.push('HeaderOffset'); if (foreign(data.slice(0, head))) hard.push('Polyglot'); }", to: "if (head > 0) { soft.push('HeaderOffset'); }" },
  { id: 'auth-quoted', file: S, what: 'quoted strings neutralized before the AR is split on ";"', expect: 'caught',
    from: "  v = v.replace(/\"(?:[^\"\\\\]|\\\\.)*\"/g, '\"\"');", to: '' },
  { id: 'from-ambiguous', file: S, what: 'two <addr> in From → ambiguous', expect: 'caught',
    from: 'const ambiguous = angles.length > 1 || ', to: 'const ambiguous = ' },
  { id: 'auth-rank', file: S, what: 'best-of ranking of passing clauses (equivalent mutant: > → >=)', expect: 'equivalent', differential: 'authRank', control: ['parent: 2, sub: 1', 'parent: 1, sub: 2'],
    from: 'if (k && (!best || RANK[k] > RANK[best])) best = k;', to: 'if (k && (!best || RANK[k] >= RANK[best])) best = k;' },
  { id: 'html-hidden', file: H, what: 'hidden-element detection (display:none, hidden, …)', expect: 'caught',
    from: 'function htHidden_(attrs) {\n', to: 'function htHidden_(attrs) {\n  return false;\n' },
  { id: 'html-redos', file: H, what: 'linear tag regex [^<>]* (HtmlText.gs:43; ReDoS if [^>]*)', expect: 'caught',
    from: 'const re = /<(\\/?)([a-zA-Z][a-zA-Z0-9:-]*)([^<>]*)>|([^<]+)|(<)/g;', to: 'const re = /<(\\/?)([a-zA-Z][a-zA-Z0-9:-]*)([^>]*)>|([^<]+)|(<)/g;' },
  { id: 'name-confusable', file: N, what: 'mixed-script (look-alike) word check', expect: 'caught',
    from: "  for (const w of raw.matchAll(/\\p{L}+/gu)) if (/\\p{Script=Latin}/u.test(w[0]) && /[\\p{Script=Cyrillic}\\p{Script=Greek}]/u.test(w[0])) return { hit: true, why: 'confusable' };\n", to: '' },
];
// Differential checks for mutants believed equivalent: original and mutant module run side by side on seeded random
// inputs; any difference in output proves the mutant is NOT equivalent (and a test is missing).
const DIFFERENTIAL = {
  authRank(orig, mut) {
    const load = src => new Function('Gmail', 'Logger', src + ';return authAligned_;')(undefined, { log() {} });
    const A = load(orig), B = load(mut);
    let seed = 20261112; const rnd = n => (seed = (seed * 1103515245 + 12345) % 2147483648) % n;
    const DOM = ['shop.example', 'mail.shop.example', 'x.mail.shop.example', 'example', 'evil.example', 'shop.example.evil'];
    const clause = () => { const m = ['dkim', 'spf', 'dmarc'][rnd(3)], r = ['pass', 'fail', 'none', 'PASS'][rnd(4)], d = DOM[rnd(DOM.length)];
      return m + '=' + r + ' ' + (m === 'dkim' ? (rnd(2) ? 'header.d=' + d : 'header.i=@' + d) : m === 'spf' ? 'smtp.mailfrom=' + (rnd(2) ? 'bounce@' : '') + d : 'header.from=' + d); };
    let diff = 0, n = 20000;
    for (let i = 0; i < n; i++) {
      const ar = 'Authentication-Results: mx.google.com; ' + Array.from({ length: 1 + rnd(5) }, clause).join('; ');
      const msg = { getId: () => 'm', getRawContent: () => 'Received: from a (a [192.0.2.1]) by mx.google.com with ESMTPS id x\r\n' + ar + '\r\n\r\nbody' };
      const from = DOM[rnd(3)], wa = {}, wb = {};
      if (A(msg, from, wa, {}) !== B(msg, from, wb, {}) || wa.via !== wb.via) diff++;
    }
    return { n, diff };
  },
};
const COPY = ['modules', 'example', 'project', 'tools', 'tests', 'corpus', 'scanner', 'run.sh'];
const scratch = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ablation-')); for (const c of COPY) fs.cpSync(path.join(ROOT, c), path.join(d, c), { recursive: true }); return d; };
const runSuites = d => { const r = cp.spawnSync('bash', [path.join(d, 'run.sh')], { cwd: d, encoding: 'utf8', env: Object.assign({}, process.env, { SUITES: 'behavior', SUITE_TIMEOUT: String(TIMEOUT) }) });
  const out = r.stdout || '';
  const rows = out.split('\n').filter(l => /^tests\//.test(l)).map(l => { const m = /^(\S+)\s+(\d+)\s+(\d+)\s+(.*)$/.exec(l); return { suite: m[1], pass: +m[2], fail: +m[3], res: m[4] }; });
  return { rc: r.status, rows, verdict: (out.match(/^VERDICT: .*$/m) || [''])[0] }; };
// baseline: the unmodified copy must pass, or the table means nothing
const base = (() => { const d = scratch(); const r = runSuites(d); fs.rmSync(d, { recursive: true, force: true }); return r; })();
if (base.rc !== 0) { console.log('ABLATION ABORTED: the unmodified behavioral suites do not pass: ' + base.verdict); process.exit(2); }
const baseChecks = base.rows.reduce((a, r) => a + r.pass, 0);
console.log(`baseline: ${base.rows.length} behavioral suites, ${baseChecks} checks pass (per-suite timeout ${TIMEOUT}s)\n`);
const results = [];
for (const g of GUARDS.filter(x => !ONLY || x.id === ONLY)) {
  const d = scratch(), f = path.join(d, g.file), src = fs.readFileSync(f, 'utf8');
  if (src.split(g.from).length !== 2) { console.log(`ABLATION ERROR: anchor for ${g.id} not found exactly once in ${g.file}`); process.exit(2); }
  fs.writeFileSync(f, src.replace(g.from, g.to));
  const t0 = Date.now(), r = runSuites(d), secs = ((Date.now() - t0) / 1000).toFixed(0);
  fs.rmSync(d, { recursive: true, force: true });
  const fails = r.rows.reduce((a, x) => a + x.fail, 0), timeouts = r.rows.filter(x => /TIMEOUT/.test(x.res)).map(x => path.basename(x.suite, '.test.js'));
  const crashed = r.rows.filter(x => !/TIMEOUT/.test(x.res) && x.res !== 'ok' && x.fail === 0).map(x => path.basename(x.suite, '.test.js'));
  let result = fails > 0 || crashed.length ? 'caught' : 'missed', dnote = '';
  if (result === 'missed' && g.differential) {
    const r = DIFFERENTIAL[g.differential](src, src.replace(g.from, g.to));
    const c = DIFFERENTIAL[g.differential](src, src.replace(g.control[0], g.control[1]));   // control: a real change must show up
    if (c.diff === 0) dnote = 'differential check is blind (its control mutant showed no difference)';
    else if (r.diff === 0) { result = 'equivalent'; dnote = `equivalent: 0 of ${r.n} seeded differential inputs differ (control mutant: ${c.diff} differ)`; }
    else dnote = `NOT equivalent: ${r.diff} of ${r.n} differential inputs differ`; }
  const by = r.rows.filter(x => x.fail > 0).map(x => `${path.basename(x.suite, '.test.js')}:${x.fail}`).join(' ');
  const note = dnote ? dnote : result === 'caught' ? by + (crashed.length ? ' crashed:' + crashed.join(',') : '') : timeouts.length ? 'hang: ' + timeouts.join(', ') + ' timed out, no check failed' : 'no check failed';
  results.push(Object.assign({ fails, result, note, secs }, g));
  console.log(`${result.toUpperCase().padEnd(10)} ${g.id.padEnd(20)} ${String(fails).padStart(3)} failing checks  ${note}  (${secs}s)`);
}
const caught = results.filter(r => r.result === 'caught').length, equiv = results.filter(r => r.result === 'equivalent').length;
console.log('\n| # | guard removed | module | failing checks | result |\n|---|---|---|---|---|');
results.forEach((r, i) => console.log(`| ${i + 1} | ${r.what} | ${path.basename(r.file, '.gs')} | ${r.fails} | ${r.result === 'missed' ? 'MISSED' : r.result}${r.result === 'caught' ? '' : ' (' + r.note + ')'} |`));
const drift = results.filter(r => r.result !== r.expect);
console.log(`\nABLATION: ${results.length} guards removed one at a time, ${caught} caught by at least one failing check, ${equiv} equivalent (no test can catch), ${results.length - caught - equiv} missed`);
if (!ONLY) console.log(drift.length ? `ABLATION DRIFT: differs from README.md for ${drift.map(r => r.id).join(', ')}` : 'ABLATION matches README.md (expected caught/missed for every guard)');
process.exit(drift.length && !ONLY ? 1 : 0);
