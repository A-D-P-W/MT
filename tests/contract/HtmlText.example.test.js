// Contract test: what the Example consumer relies on from HtmlText 1.0.0 — htmlText_ turns an untrusted HTML body into
// visible text: one field per line (<br>, <li>, <p> → newline), hidden text removed, entities decoded, link targets
// dropped. Merged from the source project's two consumer tests; markup shapes are synthetic.
const load = require('./load'), { ok, done } = require('./_h');
const { htmlText_ } = load(['HtmlText'], {}, ['htmlText_']);
const H = { htmlText_ };
ok(htmlText_('<p>Total</p><p>$12.34</p>').replace(/\s+/g, ' ').trim() === 'Total $12.34', 'blocks become separate lines; text kept');
ok(!/hidden|secret|alert/.test(htmlText_('<div style="display:none">hidden</div><script>alert(1)</script><span hidden>secret</span>ok')), 'hidden elements and scripts never appear');
ok(htmlText_('A&amp;B &lt;x&gt; &#36;5') === 'A&B <x> $5', 'entities decoded');
let threw = false; for (const s of ['<', '<a', '<!--', '<div><div><div>', '&#xFFFFFFFF;']) try { htmlText_(s); } catch (e) { threw = true; }
ok(!threw, 'malformed HTML does not throw');
// Linear time, in a child process with a 10 s limit (a ReDoS regression FAILs instead of hanging); best of 3, pair retried.
const lin = require('../unit/timed').measure(require('path').join(__dirname, '..', '..', 'modules', 'HtmlText', 'HtmlText.gs'), 'htmlText_(s)', '<a ', 90000, 450000, 10000);
ok(!lin.timeout && !lin.error && lin.tb < 12 * Math.max(lin.ts, 15), lin.timeout ? '5× input ≈ linear time -- did not finish in 10 s: super-linear (ReDoS)' : `5× input ≈ linear time (${lin.ts} → ${lin.tb} ms)`, lin.error || '');
ok(!/Gone/.test(htmlText_('<span style="opacity:0;">Gone</span><div style="max-height:0;overflow:hidden">Gone</div><p style="font-size:0px;">Gone</p>ok')), 'opacity:0, max-height:0 and font-size:0 hide text');
const lines = h => H.htmlText_(h).split('\n').map(l => l.trim()).filter(Boolean);
ok(lines('Hi there!<br />\nOrder: 1042, two items <br />\nShip to: 1 Test St, Town, ST 00000<br />').join('|') ===
  'Hi there!|Order: 1042, two items|Ship to: 1 Test St, Town, ST 00000', '<br /> separates fields; trailing spaces trimmed by the caller');
ok(lines('<ul>\r\n\t<li style="x">Item: desk lamp</li>\r\n\t<li>Qty: 2 – boxed</li></ul>').join('|') === 'Item: desk lamp|Qty: 2 – boxed', '<li> items become their own lines');
ok(!/Total: \$0/.test(H.htmlText_('<div style="display:none">Total: $0.00 (paid)</div><p>visible</p>')), 'hidden text never appears (a hidden fake total cannot be read)');
ok(!/https?:/.test(H.htmlText_('click <a href="https://evil.example/x">https://short.example/j/x</a>')), 'link targets and URLs are dropped');
ok(H.htmlText_('Where: 1 A&amp;B St').includes('1 A&B St'), 'entities decoded');
done();
