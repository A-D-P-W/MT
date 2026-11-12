// Repository hygiene: no credential and no personal data in any tracked file. Credential patterns are the source
// project's (its v3.7.5 suite); the personal-data patterns were added for this public extract. Every mailbox-provider
// address in the repo must be one of the placeholders below (the modules' Gmail-only rules need Gmail-shaped test data).
// Text files are read whole; PDFs are read as Latin-1 bytes (their uncompressed parts).
const fs = require('fs'), path = require('path'), cp = require('child_process');
const ROOT = path.join(__dirname, '..');
let pass = 0, fail = 0; const ok = (c, m, extra = '') => { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m + (c || !extra ? '' : '  -- ' + extra)); };
let files = [];
try { files = cp.execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split('\0').filter(Boolean); } catch (e) { }
if (!files.length) {   // not a git checkout (e.g. a downloaded archive): walk the tree, skipping .git, out/ and node_modules/
  const walk = d => fs.readdirSync(path.join(ROOT, d), { withFileTypes: true }).forEach(x => { const r = d ? d + '/' + x.name : x.name;
    if (x.isDirectory()) { if (!/^(\.git|out|node_modules)$/.test(x.name)) walk(r); } else files.push(r); });
  walk('');
}
ok(files.length > 40, `scan sees the repository's files (${files.length})`);
// Patterns are split so this file does not match itself.
const CRED = [['refresh', '_token"\\s*:'], ['"access', '_token"\\s*:'], ['ya', '29\\.[0-9A-Za-z_-]{20,}'], ['1//0', '[0-9A-Za-z_-]{30,}'], ['GOC', 'SPX-[0-9A-Za-z_-]{10,}'],
  ['"client', '_secret"\\s*:\\s*"[^"]{8,}'], ['-----BEGIN [A-Z ]*PRIV', 'ATE KEY-----'], ['gh', '[pousr]_[0-9A-Za-z]{30,}'], ['github', '_pat_[0-9A-Za-z_]{30,}'], ['AI', 'za[0-9A-Za-z_-]{35}'],
  ['"id', '_token"\\s*:'], ['sk', '_live_[0-9A-Za-z]{10,}'], ['AK', 'IA[0-9A-Z]{16}']].map(p => new RegExp(p.join('')));
const PLACEHOLDER = new Set(['owner@gmail.com', 'o.wner@gmail.com', 'forwarder@gmail.com', 'forwarder@icloud.com', 'forwarder+caf_=owner=gmail.com@gmail.com',
  'stranger+caf_=owner=gmail.com@gmail.com', 'help_at_vendor_example_abc123xyz9_def45678@icloud.com',
  'mylocal@gmail.com', '=gmail.com@gmail.com']);   // the last two: templates in SenderTrust's code and contract
const MAILBOX = new RegExp('[A-Za-z0-9._%+=-]+@(?:g' + 'mail|google' + 'mail|i' + 'cloud|me|mac|ya' + 'hoo|hot' + 'mail|out' + 'look|live|msn|aol|proton(?:mail)?|pm|gmx|zoho|yandex|mail)\\.(?:com|me|net|ch)\\b', 'gi');
const PERSONAL = [['Windows user path', new RegExp('[A-Za-z]:\\\\{1,2}' + 'Users\\\\{1,2}', 'i')], ['Stripe account id', new RegExp('ac' + 'ct_[0-9A-Za-z]{8,}')],
  ['Google Drive / Apps Script id', new RegExp('\\b1(?=[A-Za-z0-9_-]*[A-Z_-])[A-Za-z0-9_-]{24,60}\\b')], ['home.local address', new RegExp('@[A-Za-z0-9.-]*\\.' + 'local\\b', 'i')]];
const credHits = [], mailHits = [], personalHits = [];
for (const f of files) {
  if (/(^|\/)\.clasprc\.json$|(^|\/)\.env$/.test(f)) { credHits.push(f + ' (credential file tracked)'); continue; }
  let b; try { b = fs.readFileSync(path.join(ROOT, f)); } catch (e) { continue; }
  if (b.length > 5e6) continue;
  const pdf = /\.pdf$/i.test(f), bin = !pdf && b.includes(0);
  if (bin) continue;
  const t = b.toString(pdf ? 'latin1' : 'utf8');
  for (const re of CRED) if (re.test(t)) credHits.push(f + ' ~ ' + re.source.slice(0, 20));
  for (const m of t.match(MAILBOX) || []) if (!PLACEHOLDER.has(m.toLowerCase())) mailHits.push(f + ' ~ ' + m.replace(/^(.).*@/, '$1…@'));
  if (!pdf) t.split('\n').forEach((l, i) => { for (const [n, re] of PERSONAL) if (re.test(l)) personalHits.push(`${f}:${i + 1} ${n}`); });
}
ok(credHits.length === 0, 'no credential pattern in any tracked file', credHits.slice(0, 5).join('; '));
ok(mailHits.length === 0, `no mailbox-provider address other than the ${PLACEHOLDER.size} placeholders`, mailHits.slice(0, 5).join('; '));
ok(personalHits.length === 0, 'no Windows user path, Stripe account id, Drive/Apps Script-shaped id or .local address', personalHits.slice(0, 5).join('; '));
// A repo created on Windows (core.filemode=false) records run.sh as 100644, and CI's ./run.sh then fails (GitHub review QA, M1).
let mode = ''; try { mode = cp.execFileSync('git', ['ls-files', '-s', '--', 'run.sh'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).slice(0, 6); } catch (e) { }
ok(mode === '' || mode === '100755', 'run.sh is executable in the git index (100755; not checked outside a git checkout)', 'mode ' + mode);
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
