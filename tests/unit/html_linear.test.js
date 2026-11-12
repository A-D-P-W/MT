// Linear-time (ReDoS) checks and a seeded fuzz for HtmlText, adapted from the source project's v3.7.3 suite: every
// open-without-close construct at 500 KB must stay linear, and random HTML-ish soup never throws or leaks a URL or a
// control character. The source suite's mail-query and run() checks are app code and are not part of this extract.
const { load, ok, done } = require('./lib');
const T = load(['HtmlText'], {}, ['htmlText_']).htmlText_;

// ---- linear time on every unclosed construct, at a 500 KB body. Each pair runs in a child process with a 10 s limit
// (tests/unit/timed.js), so a quadratic regression FAILs here with a message instead of hanging the suite.
const path = require('path'), { measure } = require('./timed');
const HT = path.join(__dirname, '..', '..', 'modules', 'HtmlText', 'HtmlText.gs');
for (const unit of ['<!--', '<![CDATA[', '<a', '<td x="', '&#x', '<p style="', '<!DOCTYPE', '<?x', '</', '<a b=1 <c ']) {
  const r = measure(HT, 'htmlText_(s)', unit, 100000, 500000, 10000);   // best of 3 per size, pair retried up to 3 times
  if (r.timeout || r.error) { ok(false, `500 KB of ${JSON.stringify(unit)}… ${r.timeout ? 'did not finish in 10 s: super-linear (ReDoS)' : 'crashed'}`, r.error || ''); continue; }
  ok(r.tb < 1500, `500 KB of ${JSON.stringify(unit)}… runs in ${r.tb} ms (< 1.5 s)`);
  ok(r.tb < 10 * Math.max(r.ts, 15), `${JSON.stringify(unit)}: 5× input ≈ linear time (${r.ts} → ${r.tb} ms)`);
}
// seeded fuzz: random HTML-ish soup never throws, never leaks a URL/control char, stays fast
let seed = 20261020; const rnd = n => (seed = (seed * 1103515245 + 12345) % 2147483648) % n;
const PARTS = ['<', '>', '</', '<!--', '-->', '<![CDATA[', ']]>', '<td', '<tr>', '<p ', ' style="display:none"', ' hidden', '"', "'", '=', 'https://x.example/a', 'javascript:alert(1)', '&#x', ';', '&amp;', 'TEXT', ' ', '\n', '<pre>', '</pre>', '<script>', '</script>', '‮', '\u0000'];
let worst = 0, threw = null, leak = null;
for (let i = 0; i < 3000; i++) {
  let s = ''; const n = 5 + rnd(60); for (let j = 0; j < n; j++) s += PARTS[rnd(PARTS.length)];
  try { const t0 = Date.now(); const o = T(s); worst = Math.max(worst, Date.now() - t0);
        if (/https?:\/\/|javascript:/i.test(o) || /[\u0000-\u0008]/.test(o)) { leak = { s, o }; break; } }
  catch (e) { threw = { s, e: String(e) }; break; }
}
ok(!threw, 'fuzz: 3000 random inputs, no exception', JSON.stringify(threw));
ok(!leak, 'fuzz: no URL or control character in any output', JSON.stringify(leak));
ok(worst < 200, `fuzz: worst case ${worst} ms`);

// ---- review fixes
ok(T('<p>keep</p><!-- unclosed comment <p>gone') === 'keep', 'unclosed comment drops the rest (no hidden text leaks)');
ok(T('a<![CDATA[x]]>b<!--c-->d') === 'abd', 'closed comment/CDATA removed in place');
ok(T('<div style="max-height:0.5em">VISIBLE</div>') === 'VISIBLE', 'max-height:0.5em is not hidden');
ok(T('<div style="max-height:0">x</div>ok') === 'ok' && T('<div style="max-height: 0px">x</div>ok') === 'ok', 'max-height:0 / 0px still hidden');
ok(T('<div style="display&#58;none">SECRET</div>ok') === 'ok' && T('<div style="display&colon;none">S</div>ok') === 'ok', 'entity-encoded display:none detected');
const u = T('<p>xhttps://evil.example/a _https://b.example javascript:alert(1) data:text/html,x vbscript:y ftp://f.example www.track.example/p ok</p>');
ok(!/evil|b\.example|alert|text\/html|vbscript|f\.example|track/.test(u) && /ok/.test(u), 'URLs removed in any position and scheme', u);

done();
