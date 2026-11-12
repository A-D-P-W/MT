// Writes eight hand-built adversarial PDFs (A-H) to scanner/adversarial/ as Latin-1 strings, each hiding active content
// a different way (object streams, URI schemes, encryption, a polyglot, #-escaped names). Adapted from the source
// project's mk.js, which also ran an early scanner on them; tests/scan_corpus.test.js now scans them with PdfSafety.
// Usage: node scanner/mk.js      (Node built-ins only; output is deterministic)
const zlib = require('zlib'), fs = require('fs'), path = require('path');
const OUT = path.join(__dirname, 'adversarial');
fs.mkdirSync(OUT, { recursive: true });
const L = b => Buffer.from(b).toString('latin1');
function objStmPdf(objs, extraTrailer) {          // objs: {num: 'dict text'} placed in ObjStm 10
  const nums = Object.keys(objs); let hdr = '', body = '', off = 0;
  for (const n of nums) { hdr += n + ' ' + off + ' '; body += objs[n] + '\n'; off = body.length; }
  const raw = hdr + body, z = L(zlib.deflateSync(raw));
  return '%PDF-1.7\n%\xe2\xe3\xcf\xd3\n10 0 obj\n<</Type/ObjStm/N ' + nums.length + '/First ' + hdr.length + '/Filter/FlateDecode/Length ' + z.length + '>>\nstream\n' + z + '\nendstream\nendobj\n' +
    '11 0 obj\n<</Type/XRef/Size 12/Root 1 0 R' + (extraTrailer || '') + '>>\nstream\n\nendstream\nendobj\nstartxref\n0\n%%EOF\n';
}
const cases = {
  'A docJS name tree in ObjStm (runs on open, no OpenAction)': objStmPdf({1: '<</Type/Catalog/Pages 2 0 R/Names<</JavaScript<</Names[(x) 3 0 R]>>>>>>', 2: '<</Type/Pages/Kids[]/Count 0>>', 3: '<</S/JavaScript/JS(app.alert(1))>>'}),
  'B Launch on link annot in ObjStm': objStmPdf({1: '<</Type/Catalog/Pages 2 0 R>>', 2: '<</Type/Pages/Kids[]/Count 0>>', 4: '<</Type/Annot/Subtype/Link/A<</S/Launch/F(cmd.exe)>>>>'}),
  'C OpenAction hidden inside ObjStm too': objStmPdf({1: '<</Type/Catalog/OpenAction 3 0 R>>', 3: '<</S/JavaScript/JS(x)>>'}),
  'D URI phishing link (uncompressed)': '%PDF-1.4\n1 0 obj<</Type/Annot/Subtype/Link/A<</S/URI/URI(https://xn--pypal-4ve.com/login)>>>>endobj\n%%EOF',
  'E URI javascript: scheme': '%PDF-1.4\n1 0 obj<</S/URI/URI(javascript:alert(1))>>endobj\n%%EOF',
  'F encrypted + ObjStm': objStmPdf({1: '<</Type/Catalog>>'}, '/Encrypt 12 0 R'),
  'G PDF+ZIP polyglot (PK after %%EOF)': '%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\nPK\x03\x04' + 'x'.repeat(200),
  'H control: hex-obfuscated /J#61vaScript raw': '%PDF-1.4\n1 0 obj<</S/J#61vaScript/JS(x)>>endobj\n%%EOF',
};
for (const [k, v] of Object.entries(cases)) { fs.writeFileSync(path.join(OUT, k[0] + '.pdf'), Buffer.from(v, 'latin1')); console.log(k[0] + '.pdf  ' + k.slice(2)); }
