// Contract test: what the Example consumer relies on from SecurityNames 1.0.0 — isSecurityName_(subject + ' ' + names)
// keeps security codes, recovery keys and secrets out of automatic handling. Merged from the source project's two consumer
// tests: (1) mail subjects + attachment names, including every string the module's predecessor regex held (it must never
// let one through); (2) downloaded-file names, including the look-alike spellings the predecessor missed.
const load = require('./load'), { ok, done } = require('./_h');
const S = load(['SecurityNames'], {}, ['isSecurityName_']);
const C = String.fromCodePoint;   // invisible / look-alike characters are built from code points (no literal escapes)
// ---- (1) mail: subject + attachment name
const hitMail = (subject, pdf) => S.isSecurityName_(subject + ' ' + pdf).hit;
for (const n of ['recovery_codes.pdf', '2FA_backup_codes.pdf', 'github_recovery_codes.pdf', 'RecoveryCodes.pdf', 'recovery-codes.pdf', 'Backup__Codes.pdf', 'two_factor_recovery_codes.pdf'])
  ok(hitMail('Your document', n), 'predecessor case: filename still a security code: ' + n);
for (const s of ['Your recovery' + C(0xa0) + 'codes', 'Your recovery' + C(0x200b) + 'codes', 'Your recovery' + C(0x2060) + 'codes', 'Your recovery' + C(0xad) + 'codes',
  'Your recovery_codes', 'Your 2FA' + C(0x202f) + 'backup' + C(0x2009) + 'codes', 'Your two-factor key'])
  ok(hitMail(s, 'doc.pdf'), 'predecessor case: subject still a security code: ' + JSON.stringify(s));
for (const n of ['discovery_codes.pdf', 'security_codebook.pdf', 'recoveryfund.pdf', 'backupcodex.pdf', 'invoice_recovery.pdf'])
  ok(!hitMail('Your invoice', n), 'predecessor case: still no false match: ' + n);
ok(hitMail('Your backup.codes', 'doc.pdf') && hitMail('Recovery codes', 'codes2.pdf') && hitMail('One-time passcode for your account', 'doc.pdf'), 'widening: dotted, digit-suffixed and one-time-passcode subjects now caught');
for (const [s, p] of [['Your receipt from Example Store.', 'Receipt.pdf'], ['Your airline itinerary', 'itinerary.pdf'], ['Your boarding pass', 'boarding-pass.pdf'],
  ['Security camera order', 'Receipt.pdf'], ['Your one time payment receipt', 'Receipt.pdf'], ['Your OTP receipt', 'invoice.pdf'], ['Beach hotel folio', 'Folio.pdf'],
  ['Data recovery service invoice', 'statement.pdf'], ['Order 10' + C(0xb5) + 'F capacitor', 'invoice.pdf'], ['Caf' + C(0xe9) + ' receipt', 'r.pdf'], ['Car insurance policy declaration', 'Policy.pdf']])
  ok(!hitMail(s, p), 'ordinary mail is not held as a security code: ' + JSON.stringify(s + ' ' + p));
ok(hitMail('Your r' + C(0x301) + 'ecovery codes', 'doc.pdf'), 'a combining mark inside a word does not hide it');
ok(S.isSecurityName_('Your document recovery_codes.pdf').why === 'phrase', 'why names the kind of hit');
// The module must never let through a name its predecessor held. OLD is the frozen predecessor test (a regex on a
// separator-folded text); every string of its grammar, with separators and any neighbouring character, must hit.
{ const OLD = /(?<![a-z0-9])(backup|recovery|emergency|2fa|two ?factor|security|verification) ?(codes?|keys?|kit)(?![a-z0-9])/i;
  const oldText = s => String(s || '').replace(/\p{Cf}/gu, '').replace(/[\s_-]+/g, ' ');
  const A = ['backup', 'recovery', 'emergency', '2fa', 'twofactor', 'two factor', 'security', 'verification', 'Backup', 'RECOVERY'], B = ['code', 'codes', 'key', 'keys', 'kit', 'KEY'];
  const SEP = ['', ' ', '_', '-', C(0xa0), C(0x200b), C(0x3000)], EDGE = ['', ' ', '.', '(', '_', C(0xe9), C(0x436), C(0x3b1), C(0xe23), C(0x4e2d), C(0xdf), '!', '#', "'", '1', 'x'];
  let old = 0; const missed = [];
  for (const a of A) for (const b of B) for (const sp of SEP) for (const pre of EDGE) for (const post of EDGE) {
    const str = 'Your ' + pre + a + sp + b + post + ' doc.pdf'; if (!OLD.test(oldText(str))) continue; old++; if (!S.isSecurityName_(str).hit) missed.push(str); }
  ok(old > 10000 && missed.length === 0, 'every one of ' + old + ' old-grammar strings (separators, non-ASCII neighbours) is still a security code', missed.slice(0, 3).map(x => JSON.stringify(x)).join(' ')); }
// ---- (2) file names
const hit = n => S.isSecurityName_(n).hit;
const caught = ['backup' + C(0x200b) + 'code.txt', 'backup' + C(0x200c) + 'codes', 'backup' + C(0x200d) + 'codes', 'backupcodes.pdf', 'securitycodes.txt',
  'BackupCodes.txt', 'Backup-codes-user.txt', 'github-recovery-codes.txt', 'recovery-codes(1).txt', 'mail-recovery-kit.pdf',
  'vault_two-step_login_recovery_code.txt', 'recovery-key.bin'];
const missed = ['backup.codes.txt', 'recovery.codes.pdf', 'backupcodes2.txt', 'backup' + C(0x301) + ' codes', 'b' + C(0x301) + 'ackup' + C(0x308) + 'codes.txt', C(0xff42) + 'ackup codes',
  'b' + C(0x430) + 'ckup codes', 'backup codes' + C(0x202e) + 'txt.exe'];
for (const n of caught) ok(hit(n), 'held by the predecessor regex, still caught: ' + JSON.stringify(n));
for (const n of missed) ok(hit(n), 'missed by the predecessor regex, now caught: ' + JSON.stringify(n));
for (const n of ['2fa-codes.txt', '2FA_backup_codes.pdf', 'one-time-passcode.txt', 'otp codes.txt', 'MFA_recovery_codes.pdf', 'wallet seed phrase.txt', 'mnemonic.txt', 'private_key.txt'])
  ok(hit(n), 'widened words: ' + n);
for (const n of ['vault.kdbx', 'export.1pux', 'server.pem', 'id.key', 'cert.p12', 'cert.pfx']) ok(S.isSecurityName_(n).why === 'extension', 'secret-store extension: ' + n);
for (const n of ['vacation.jpg', 'invoice-2026.pdf', 'Security Camera Manual.pdf', 'keyboard-driver-setup.exe', 'recovery.iso', 'Screenshot 2026-11-07.png',
  'IMG_20261107.jpg', 'Internet bill 2026-10.pdf', 'keynote.pdf', 'Ohm 10' + C(0x2126) + ' resistor.pdf', 'monkey.png'])
  ok(!hit(n), 'ordinary name is not a security name: ' + JSON.stringify(n));
ok(S.isSecurityName_('vacation.jpg').why === '' && S.isSecurityName_(null).hit === false && S.isSecurityName_(undefined).hit === false, 'no hit → why ""; null/undefined coerced');
ok(S.isSecurityName_('b' + C(0x430) + 'ckup.pdf').why === 'confusable', 'one word mixing Latin and Cyrillic → confusable');
// linear time (every parser of untrusted input gets one): best of 3 per size, 10x input → well under 30x time
const best3 = f => Math.min(...[0, 1, 2].map(() => { const t = process.hrtime.bigint(); f(); return Number(process.hrtime.bigint() - t); }));
const big = k => 'backup '.repeat(k) + C(0x200b).repeat(k) + 'a'.repeat(k) + ' ' + 'b' + C(0x301).repeat(k);
let linear = false;
for (let attempt = 0; attempt < 3 && !linear; attempt++) {   // retried pairs: a busy machine must not fail it
  const ts = best3(() => S.isSecurityName_(big(400))), tb = best3(() => S.isSecurityName_(big(4000)));
  linear = tb < 30 * Math.max(ts, 1e5);   // best of 3 each
}
ok(linear, 'isSecurityName_ is linear in input length (10x input, < 30x time; retried pairs)');
done();
