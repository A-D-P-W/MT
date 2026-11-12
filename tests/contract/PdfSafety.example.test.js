// Contract test: what the Example consumer relies on from PdfSafety 1.0.0 (pdfInfo_, scanPdf_, textComplete_, caps).
const load = require('./load'), { ok, done } = require('./_h'), zlib = require('zlib');
const P = load(['PdfSafety'], {}, ['pdfInfo_', 'scanPdf_', 'textComplete_', 'PDF_DEFAULT_CAPS']);
const CAPS = { maxBytes: 20 * 1024 * 1024, inflateCap: 8 * 1024 * 1024, maxObjStm: 200 };   // the source project's limits
const pdf = body => '%PDF-1.4\n1 0 obj\n<</Type/Catalog' + (body || '') + '>>\nendobj\nxref\n0 1\ntrailer<</Root 1 0 R>>\nstartxref\n9\n%%EOF\n';
const att = (name, data, type = 'application/pdf') => ({ getName: () => name, getContentType: () => type, getSize: () => data.length, getDataAsString: () => data });
ok(P.pdfInfo_(att('a.txt', 'x', 'text/plain'), CAPS) === null, 'pdfInfo_: not a PDF → null');
ok(P.pdfInfo_(att('a.pdf', 'hello'), CAPS).malformed === true, 'pdfInfo_: .pdf without %PDF- header → malformed (never filed)');
ok(P.pdfInfo_(Object.assign(att('a.pdf', pdf()), { getSize: () => 21 * 1024 * 1024 }), CAPS).oversized === true, 'pdfInfo_: over maxBytes → oversized');
ok(P.pdfInfo_(att('a.pdf', pdf()), CAPS).data === pdf(), 'pdfInfo_: a PDF returns its Latin-1 data');
ok(JSON.stringify(P.scanPdf_(pdf(), false, CAPS)) === '{"hard":[],"soft":[]}', 'scanPdf_: benign PDF → no findings');
ok(P.scanPdf_(pdf('/OpenAction<</S/JavaScript/JS(app.alert(1))>>'), false, CAPS).hard.includes('JavaScript'), 'scanPdf_: JavaScript → hard');
ok(P.scanPdf_(pdf('/Launch<</F(cmd.exe)>>'), false, CAPS).hard.includes('Launch') && P.scanPdf_(pdf('/J#61vaScript'), false, CAPS).hard.includes('JavaScript'), 'scanPdf_: Launch and #-escaped names → hard');
ok(P.scanPdf_(pdf('/Encrypt 5 0 R'), false, CAPS).soft.includes('Encrypt'), 'scanPdf_: Encrypt → soft');
const js = zlib.deflateSync(Buffer.from('<</S/JavaScript/JS(x)>>')).toString('latin1');
const objstm = '%PDF-1.5\n3 0 obj\n<</Type/ObjStm/N 1/First 4/Filter/FlateDecode/Length ' + js.length + '>>\nstream\n' + js + '\nendstream\nendobj\nstartxref\n9\n%%EOF\n';
ok(P.scanPdf_(objstm, false, CAPS).hard.includes('JavaScript'), 'scanPdf_: JavaScript inside a compressed object stream → hard');
ok(JSON.stringify(P.scanPdf_(pdf(), false, { maxObjStm: 0 }).hard) === '["CapsInvalid"]', 'scanPdf_: an invalid cap fails closed');
ok(JSON.stringify(P.PDF_DEFAULT_CAPS) === JSON.stringify(CAPS), 'defaults equal the documented limits (20 MB / 8 MB / 200)');
ok(typeof P.textComplete_(pdf()) === 'boolean', 'textComplete_ returns a boolean');
ok(P.scanPdf_(pdf('/EmbeddedFiles 4 0 R'), false, CAPS).hard.includes('EmbeddedFile') && P.scanPdf_(pdf('/AA<</O<</S/Launch>>>>/RichMedia'), false, CAPS).hard.includes('RichMedia'), 'scanPdf_: embedded files and rich media → hard');
ok(P.scanPdf_(pdf('/A<</S/URI/URI(javascript:alert(1))>>'), false, CAPS).hard.includes('URIscheme') && !P.scanPdf_(pdf('/A<</S/URI/URI(https://shop.example/r)>>'), false, CAPS).hard.length, 'scanPdf_: non-http(s)/mailto URI scheme → hard; a plain https link → nothing');
const many = '%PDF-1.5\n' + Array.from({ length: 201 }, (_, i) => (i + 3) + ' 0 obj\n<</Type/ObjStm/N 0/First 0/Length 0>>\nstream\n\nendstream\nendobj\n').join('') + 'startxref\n9\n%%EOF\n';
ok(P.scanPdf_(many, false, CAPS).hard.includes('ObjStmCount'), 'scanPdf_: more object streams than maxObjStm (200) → hard ObjStmCount');
ok(P.pdfInfo_(att('a.pdf', ' '.repeat(1100) + pdf()), CAPS).malformed === true && P.pdfInfo_(att('a.pdf', ' '.repeat(500) + pdf()), CAPS).data, 'pdfInfo_: %PDF- header must start within the first 1024 bytes');
ok(JSON.stringify(P.scanPdf_(pdf(), false, { maxBytes: Number.MAX_VALUE }).hard) === '["CapsInvalid"]' && P.pdfInfo_(att('a.pdf', pdf()), { maxObjStm: 1e9 }).malformed === true, 'caps above PDF_MAX_CAPS are invalid (a bound cannot be switched off)');
// Every PDF_HARD keyword has its own behavioral case (ablation 2026-11-11: removing these six went unnoticed).
for (const [n, body] of [['XFA', '/AcroForm<</XFA 5 0 R>>'], ['GoToE', '/OpenAction<</S/GoToE/T<</R/C/N(x)>>>>'], ['GoToR', '/OpenAction<</S/GoToR/F(\\\\\\\\host\\\\share\\\\a.pdf)/D[0/Fit]>>'],
  ['SubmitForm', '/AA<</O<</S/SubmitForm/F(https://collect.example/x)>>>>'], ['ImportData', '/OpenAction<</S/ImportData/F(data.fdf)>>'], ['Rendition', '/OpenAction<</S/Rendition/OP 0>>']])
  ok(P.scanPdf_(pdf(body), false, CAPS).hard.includes(n), `scanPdf_: /${n} → hard ${n}`);
// Polyglot with the foreign file BEFORE %PDF- and nothing after %%EOF (ablation: both corpus polyglots also carry trailing
// ZIP data, so the tail check held them and the prefix check was never tested on its own).
for (const [n, pre] of [['ZIP', 'PK\x03\x04' + '\x14\x00'.repeat(20)], ['EXE', 'MZ\x90\x00' + '\x00'.repeat(40)], ['HTML', '<html><script>x()</script>']]) {
  const r = P.scanPdf_(pre + pdf(), false, CAPS);
  ok(r.hard.includes('Polyglot') && r.soft.includes('HeaderOffset'), `scanPdf_: ${n} bytes before %PDF- (prefix-only polyglot) → hard Polyglot`, JSON.stringify(r));
}
ok(!P.scanPdf_('%comment line\n'.repeat(3) + pdf(), false, CAPS).hard.length, 'scanPdf_: harmless text before %PDF- → no hard finding (HeaderOffset is soft)');
done();
