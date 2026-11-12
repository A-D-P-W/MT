#!/usr/bin/env python3
"""Writes the scanner false-positive / false-negative set used by tests/scan_corpus.test.js.
Usage: python3 -I scanner/gen_scanner_set.py      (needs pikepdf and reportlab: pip install pikepdf reportlab)

benign/       ordinary PDFs a real writer produces: reportlab output (compressed and not, many pages, links, outlines,
              a form, vector graphics, hex-string text) and the same files rewritten by qpdf (via pikepdf) with object
              streams, xref streams and linearization. Every file must come out of scanPdf_ with no hard finding.
adversarial/  bomb.pdf (an object stream that inflates past the 8 MB cap) and js_docjs*.pdf (a document-level
              JavaScript name tree, plain and inside an object stream). A-H.pdf come from scanner/mk.js.
All output is deterministic (fixed dates and IDs), so scanner/SHA256SUMS pins the set: the test fails when a file
changes, appears or goes missing. The source project used public TeX font-documentation PDFs here; they were replaced
by this generator so the repository carries no third-party documents."""
import hashlib, io, os, zlib
import pikepdf
from pikepdf import Array, Dictionary, Name, String
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas

HERE = os.path.dirname(os.path.abspath(__file__))
BEN, ADV = os.path.join(HERE, 'benign'), os.path.join(HERE, 'adversarial')
for d in (BEN, ADV): os.makedirs(d, exist_ok=True)
LOREM = ('Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore '
         'magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo.').split()


def rl(pages=1, compress=1, size=letter, link=None, outline=False, form=False, shapes=False):
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=size, pageCompression=compress, invariant=1)
    for p in range(pages):
        c.setFont('Helvetica-Bold', 14); c.drawString(72, 740, 'Example Supplies - Statement page %d of %d' % (p + 1, pages))
        if outline: c.bookmarkPage('p%d' % p); c.addOutlineEntry('Page %d' % (p + 1), 'p%d' % p)
        c.setFont('Times-Roman', 11)
        for i in range(36):
            c.drawString(72, 712 - i * 18, ' '.join(LOREM[(i * 7 + p) % len(LOREM):][:12]) + '  %d.%02d' % (i * 3 + p, i))
        if shapes:
            for k in range(20): c.setFillColorRGB(k / 20, 0.4, 1 - k / 20); c.rect(72 + k * 22, 60, 18, 18, fill=1, stroke=0)
            c.setFillColorRGB(0, 0, 0)
        if link and p == 0: c.linkURL(link, (72, 730, 300, 750), relative=0)
        if form and p == 0:
            c.acroForm.textfield(name='amount', tooltip='Amount', x=72, y=40, width=120, height=16)
        c.showPage()
    c.save()
    return buf.getvalue()


def rewrite(data, **kw):
    out = io.BytesIO()
    with pikepdf.open(io.BytesIO(data)) as pdf:
        pdf.save(out, deterministic_id=True, **kw)
    return out.getvalue()


def hex_text():
    """Hand-built page whose text uses hex strings (<...> Tj and TJ arrays), as CID-font writers do."""
    content = b'BT /F1 12 Tf 72 720 Td <4578616d706c6520696e766f696365> Tj 0 -18 Td [<546f74616c> 120 <2034352e3030>] TJ ET'
    objs = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
            b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
            b'<< /Length %d >>\nstream\n' % len(content) + content + b'\nendstream',
            b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>']
    out = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n'); offs = []
    for i, body in enumerate(objs, 1):
        offs.append(len(out)); out += b'%d 0 obj\n' % i + body + b'\nendobj\n'
    x = len(out); out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objs) + 1)
    for o in offs: out += b'%010d 00000 n \n' % o
    out += b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(objs) + 1, x)
    return bytes(out)


OS = dict(object_stream_mode=pikepdf.ObjectStreamMode.generate, compress_streams=True)
benign = {
    'b01_one_page_plain.pdf': rl(compress=0),
    'b02_ten_pages.pdf': rl(pages=10),
    'b03_invoice_https_link.pdf': rl(link='https://www.example.com/pay'),
    'b04_outline_40_pages.pdf': rl(pages=40, outline=True, size=A4),
    'b05_form_field.pdf': rl(form=True),
    'b06_vector_shapes.pdf': rl(pages=3, shapes=True),
    'b07_hex_string_text.pdf': hex_text(),
}
benign['b08_ten_pages_objstm.pdf'] = rewrite(benign['b02_ten_pages.pdf'], **OS)
benign['b09_invoice_objstm.pdf'] = rewrite(benign['b03_invoice_https_link.pdf'], **OS)
benign['b10_outline_objstm.pdf'] = rewrite(benign['b04_outline_40_pages.pdf'], **OS)
benign['b11_form_objstm.pdf'] = rewrite(benign['b05_form_field.pdf'], **OS)
benign['b12_linearized.pdf'] = rewrite(benign['b02_ten_pages.pdf'], linearize=True)
benign['b13_linearized_objstm.pdf'] = rewrite(benign['b06_vector_shapes.pdf'], linearize=True, **OS)
benign['b14_300_pages_objstm.pdf'] = rewrite(rl(pages=300), **OS)


def js_docjs(**save):
    out = io.BytesIO()
    with pikepdf.open(io.BytesIO(rl(compress=0))) as pdf:
        act = pdf.make_indirect(Dictionary(Type=Name.Action, S=Name.JavaScript, JS=String('app.alert("x");')))
        pdf.Root.Names = Dictionary(JavaScript=Dictionary(Names=Array([String('init'), act])))
        pdf.save(out, deterministic_id=True, **save)
    return out.getvalue()


def bomb():
    """One FlateDecode object stream whose content inflates to 24 MB of spaces (cap: 8 MB): ~24 KB on disk."""
    z = zlib.compress(b' ' * (24 * 1024 * 1024), 9)
    body = (b'%PDF-1.5\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
            b'2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n'
            + b'3 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length %d >>\nstream\n' % len(z) + z + b'\nendstream\nendobj\n')
    x = len(body)
    return body + b'xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % x


adversarial = {'js_docjs.pdf': js_docjs(), 'js_docjs_os.pdf': js_docjs(**OS), 'bomb.pdf': bomb()}
for d, files in ((BEN, benign), (ADV, adversarial)):
    for n, b in files.items():
        open(os.path.join(d, n), 'wb').write(b)
        print('%-12s %-30s %8d bytes  sha256 %s' % (os.path.basename(d), n, len(b), hashlib.sha256(b).hexdigest()[:16]))
