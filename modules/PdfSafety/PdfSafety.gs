// ===================== MODULE PdfSafety v1.0.0 =====================
// Contract: modules/PdfSafety/CONTRACT.md. Shared by source (ADR-0003); never reference a consumer's globals (GUARD (b)).

// True when every stream's bytes are visible to scanPdf_: no filtered stream other than an object stream (which scanPdf_
// inflates) and no hex-string text operators. Compressed page content or hex/CID text would hide dates from the comparison.
function textComplete_(data) {
  const raw = pdfNames_(data);
  if (/<[0-9A-Fa-f\s]{2,}>\s*(Tj|'|")|\[[^\]]*<[0-9A-Fa-f\s]{2,}>[^\]]*\]\s*TJ/.test(raw)) return false;
  for (let at = raw.indexOf('stream'); at >= 0; at = raw.indexOf('stream', at + 6)) {
    if (raw.slice(at - 3, at) === 'end') continue;
    const objAt = raw.lastIndexOf('obj', at);
    if (objAt < 0) return false;
    const dict = raw.slice(objAt + 3, at);
    if (/\/Filter\b/.test(dict) && !/\/Type\s*\/ObjStm\b/.test(dict)) return false;
  }
  return true;
}

// Reads each candidate attachment once (as a Latin-1 string) and reuses it for the magic-byte check and the scan.
// A .pdf (or application/pdf) that cannot be read or has no %PDF- in its first 1 KB is returned as malformed:
// it is labeled Needs-review, never filed and never silently dropped.
// 3.9.0 (contract PdfSafety 1.0.0): limits come from `caps` (consumer values), else PDF_DEFAULT_CAPS; a supplied
// non-finite or ≤ 0 limit fails closed (pdfInfo_: malformed; scanPdf_: hard 'CapsInvalid') — review: `x > undefined`
// is always false, so a missing limit must never switch the bound off.
const PDF_DEFAULT_CAPS = { maxBytes: 20 * 1024 * 1024, inflateCap: 8 * 1024 * 1024, maxObjStm: 200 };
// Ceilings (review 1a L3): a consumer may raise a cap up to these, never past them — {maxBytes: Number.MAX_VALUE} would
// otherwise switch the size bound off. Above a ceiling = invalid = fail closed.
const PDF_MAX_CAPS = { maxBytes: 50 * 1024 * 1024, inflateCap: 32 * 1024 * 1024, maxObjStm: 1000 };

function pdfCaps_(c) {
  const o = Object.assign({}, PDF_DEFAULT_CAPS, c && typeof c === 'object' ? c : {});
  return ['maxBytes', 'inflateCap', 'maxObjStm'].every(k => typeof o[k] === 'number' && isFinite(o[k]) && o[k] > 0 && o[k] <= PDF_MAX_CAPS[k]) ? o : null;
}

function pdfInfo_(a, caps) {
  const named = /\.pdf$/i.test(a.getName() || '');
  if (!named && a.getContentType() !== 'application/pdf') return null;
  const cp = pdfCaps_(caps);
  if (!cp) return { att: a, data: null, malformed: true };
  if (a.getSize && a.getSize() > cp.maxBytes) return named ? { att: a, data: null, oversized: true } : null;
  let data;
  try { data = String(a.getDataAsString('ISO-8859-1')); } catch (e) { return { att: a, data: null, malformed: true }; }
  const at = data.slice(0, 1024 + 4).indexOf('%PDF-');      // header must start in the first 1024 bytes
  return at < 0 ? { att: a, data: null, malformed: true } : { att: a, data, offset: at };
}

// pdfid-style keyword scan over the raw file plus every inflated object stream. Hard = active content or content
// that cannot be inspected (never filed). Soft = filed, flagged for review.
const PDF_HARD = /** @type {Array<[string, RegExp]>} */ ([['JavaScript', /\/JavaScript\b/], ['JS', /\/JS\b/], ['Launch', /\/Launch\b/], ['EmbeddedFile', /\/EmbeddedFiles?\b/],
                  ['RichMedia', /\/RichMedia\b/], ['XFA', /\/XFA\b/], ['GoToE', /\/GoToE\b/], ['GoToR', /\/GoToR\b/],
                  ['SubmitForm', /\/SubmitForm\b/], ['ImportData', /\/ImportData\b/], ['Rendition', /\/Rendition\b/]]);

const PDF_SOFT = /** @type {Array<[string, RegExp]>} */ ([['Encrypt', /\/Encrypt\b/], ['AcroForm', /\/AcroForm\b/], ['JBIG2', /\/JBIG2Decode\b/]]);   // OpenAction/AA alone are near-universal

function scanPdf_(data, withText, caps) {
  const hard = [], soft = [];
  const cp = pdfCaps_(caps);
  if (!cp) return { hard: ['CapsInvalid'], soft: [] };
  const raw = pdfNames_(data);
  let text = raw;
  if (/\/ObjStm\b|\/First\s+\d/.test(raw)) text += '\n' + objStmText_(data, raw, hard, cp);
  PDF_HARD.forEach(([n, re]) => { if (re.test(text)) hard.push(n); });
  PDF_SOFT.forEach(([n, re]) => { if (re.test(text)) soft.push(n); });
  pdfUris_(text, hard, soft);
  // Structure: header offset, end marker, cross-reference pointer, and what sits before %PDF- / after the last %%EOF.
  const head = data.indexOf('%PDF-'), eof = data.lastIndexOf('%%EOF');
  const foreign = s => /PK\x03\x04|MZ/.test(s) || /<script/i.test(s);
  if (head > 0) { soft.push('HeaderOffset'); if (foreign(data.slice(0, head))) hard.push('Polyglot'); }
  if (eof < 0) soft.push('NoEOF');
  else {
    const tail = data.slice(eof + 5);
    if (foreign(tail)) hard.push('Polyglot');
    if (tail.length > 1024) soft.push('TrailingData');
  }
  if (!/startxref\s+\d/.test(data)) soft.push('NoXref');
  const res = { hard: [...new Set(hard)], soft: [...new Set(soft)] };
  if (withText) res.text = text;                         // raw bytes + inflated object streams, for migrateTripYear_ only
  return res;
}

// Names with #xx escapes decoded (/J#61vaScript → /JavaScript).
function pdfNames_(s) { return s.replace(/\/[A-Za-z0-9#]{2,40}/g, n => (n.indexOf('#') < 0 ? n : n.replace(/#([0-9A-Fa-f]{2})/g, (x, h) => String.fromCharCode(parseInt(h, 16))))); }

// Inflates every object stream (a stream whose dictionary has /Type /ObjStm or /First) and returns the text with
// names decoded. Anything that cannot be inspected exactly is pushed to `hard`.
function objStmText_(data, raw, hard, cp) {
  const enc = /\/Encrypt\b/.test(raw);
  const want = (raw.match(/\/Type\s*\/ObjStm\b/g) || []).length;
  const re = /\/Type\s*\/ObjStm\b|\/First\s+\d/g, done = new Set();
  let m, n = 0, found = 0, budget = cp.inflateCap, dest = null, out = '';
  while ((m = re.exec(data))) {
    const objAt = data.lastIndexOf('obj', m.index), sAt = data.indexOf('stream', m.index), eAt = data.indexOf('endobj', m.index);
    if (objAt < 0 || data.slice(objAt - 3, objAt) === 'end' || sAt < 0 || (eAt >= 0 && eAt < sAt) || sAt - objAt > 4096) {
      if (/ObjStm/.test(m[0])) { hard.push('ObjStmUninspectable'); return out; }
      continue;                                          // a /First outside a stream dictionary is not an object stream
    }
    if (done.has(objAt)) continue;
    done.add(objAt);
    const dict = pdfNames_(data.slice(objAt + 3, sAt));
    const typed = /\/Type\s*\/ObjStm\b/.test(dict);
    if (!typed && !(/\/N\s+\d/.test(dict) && /\/First\s+\d/.test(dict))) continue;
    if (typed) found++;
    if (enc) { hard.push('Encrypt+ObjStm'); return out; }   // stream bytes are ciphertext: cannot be inspected
    if (++n > cp.maxObjStm) { hard.push('ObjStmCount'); return out; }
    const filters = ((/\/Filter\s*(\[[^\]]*\]|\/[A-Za-z0-9]+)/.exec(dict) || [])[1] || '').match(/\/[A-Za-z0-9]+/g) || [];
    if (!filters.length && !/\/DecodeParms/.test(dict)) continue;   // uncompressed: its bytes are already in the raw scan
    if (filters.length !== 1 || filters[0] !== '/FlateDecode' || /\/DecodeParms/.test(dict)) { hard.push('ObjStmFilter'); return out; }
    const lm = /\/Length\s+(\d+)(?:\s+(\d+)\s+R)?/.exec(dict);
    let len = lm ? Number(lm[1]) : NaN;
    if (lm && lm[2] !== undefined) {                      // indirect length: "N G obj <int> endobj" in the file body
      const r = new RegExp('(?:^|[^0-9])' + lm[1] + '\\s+' + lm[2] + '\\s+obj\\s*(\\d+)\\s*endobj').exec(data);
      len = r ? Number(r[1]) : NaN;
    }
    if (!(len >= 0)) { hard.push('ObjStmLength'); return out; }
    let start = sAt + 6;
    if (data.charAt(start) === '\r') start++;
    if (data.charAt(start) === '\n') start++;
    try {
      if (!dest) dest = new Uint8Array(cp.inflateCap);
      const t = inflateZlib_(data.substr(start, len), dest.subarray(0, budget));
      budget -= t.length;
      out += '\n' + pdfNames_(t);
    } catch (e) { hard.push(String(e && e.message) === 'cap' ? 'InflateCap' : 'InflateError'); return out; }
  }
  if (found < want) hard.push(enc ? 'Encrypt+ObjStm' : 'ObjStmUninspectable');   // e.g. /Type /Obj#53tm spelled so the byte search missed it
  return out;
}

// zlib (RFC 1950) wrapper around INFLATE_: 2-byte header checked, preset dictionaries refused, Adler-32 not checked.
function inflateZlib_(s, dest) {
  if (s.length < 3) throw new Error('Data error');
  const c0 = s.charCodeAt(0) & 255, c1 = s.charCodeAt(1) & 255;
  if ((c0 & 0x0f) !== 8 || ((c0 << 8) | c1) % 31 || (c1 & 0x20)) throw new Error('Data error');
  const src = new Uint8Array(s.length - 2);
  for (let i = 2; i < s.length; i++) src[i - 2] = s.charCodeAt(i) & 255;
  const o = INFLATE_(src, dest);
  let r = '';
  for (let i = 0; i < o.length; i += 8192) r += String.fromCharCode.apply(null, o.subarray(i, i + 8192));
  return r;
}

// /URI actions: schemes other than http, https, mailto are held; web links that hide their host are flagged.
function pdfUris_(text, hard, soft) {
  const uris = [];
  text.replace(/\/URI\s*\(((?:\\[\s\S]|[^\\)]){0,4096})\)/g, (x, u) => { uris.push(u); return x; });
  text.replace(/\/URI\s*<([0-9A-Fa-f\s]{0,8192})>/g, (x, h) => {
    soft.push('URIhex');
    h = h.replace(/\s+/g, ''); if (h.length % 2) h += '0';
    uris.push(h.replace(/../g, b => String.fromCharCode(parseInt(b, 16))).replace(/[()\\]/g, c => '\\' + c));
    return x;
  });
  if (/\/URI\s+\d+\s+\d+\s+R\b/.test(text)) soft.push('URIindirect');
  for (const lit of uris) {
    if (/\\/.test(lit.slice(0, 64))) soft.push('URIescaped');
    let u = lit.replace(/\\([0-7]{1,3}|[\s\S])/g, (x, c) => /^[0-7]/.test(c) ? String.fromCharCode(parseInt(c, 8) & 255)
                                                     : ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f' })[c] || (/[\r\n]/.test(c) ? '' : c));
    if (u.charCodeAt(0) === 0xfe && u.charCodeAt(1) === 0xff) {                                   // UTF-16BE text string
      let w = ''; for (let i = 2; i + 1 < u.length; i += 2) w += String.fromCharCode((u.charCodeAt(i) << 8) | u.charCodeAt(i + 1)); u = w;
    }
    const c = u.replace(/[\u0000-\u0020\u007f-\u00a0\u200b-\u200f\u2028\u2029\ufeff]+/g, '');   // readers drop these inside URLs
    const sch = /^([a-z][a-z0-9+.-]*):/i.exec(c);
    if (sch && !/^(https?|mailto)$/i.test(sch[1])) { if (/\./.test(sch[1])) soft.push('URIsuspect'); else hard.push('URIscheme'); continue; }
    if (!sch || !/^https?$/i.test(sch[1])) continue;
    const auth = (/^https?:[\/\\]*([^\/?#\\]*)/i.exec(c) || [])[1] || '', host = auth.replace(/^.*@/, '').replace(/:\d*$/, '');
    if (/@/.test(auth) || /xn--/i.test(auth) || /%[0-9a-f]{2}/i.test(auth) || /^\[|^[0-9.]+$|^0x[0-9a-fx.]+$/i.test(host)) soft.push('URIsuspect');
    else if (/log-?in|sign-?in|verify|password|passwd|credential/i.test(c.slice(c.indexOf(auth) + auth.length))) soft.push('URIsuspect');
  }
}

/* Derived from tiny-inflate 1.0.3 (https://github.com/foliojs/tiny-inflate).
 * MIT License — Copyright (c) 2015-present Devon Govett
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * Changes for MailToDrive: wrapped in one closure (no globals); output capped (throws 'cap' when dest is full);
 * fails closed on reads past the input, invalid symbols/distances and over-long codes (no endless loop on garbage);
 * uncompressed-block copy loop braced. Plain ECMAScript typed arrays only (no Node or browser APIs).
 */
const INFLATE_ = (function () {
  function Tree() { this.table = new Uint16Array(16); this.trans = new Uint16Array(288); }
  function Data(source, dest) {
    this.source = source; this.sourceIndex = 0; this.tag = 0; this.bitcount = 0;
    this.dest = dest; this.destLen = 0; this.ltree = new Tree(); this.dtree = new Tree();
  }
  const sltree = new Tree(), sdtree = new Tree();
  const length_bits = new Uint8Array(30), length_base = new Uint16Array(30);
  const dist_bits = new Uint8Array(30), dist_base = new Uint16Array(30);
  const clcidx = new Uint8Array([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]);
  const code_tree = new Tree(), lengths = new Uint8Array(288 + 32), offs = new Uint16Array(16);
  function fail() { throw new Error('Data error'); }
  function put(d, v) { if (d.destLen >= d.dest.length) throw new Error('cap'); d.dest[d.destLen++] = v; }
  function build_bits_base(bits, base, delta, first) {
    let i, sum;
    for (i = 0; i < delta; ++i) bits[i] = 0;
    for (i = 0; i < 30 - delta; ++i) bits[i + delta] = i / delta | 0;
    for (sum = first, i = 0; i < 30; ++i) { base[i] = sum; sum += 1 << bits[i]; }
  }
  function build_fixed_trees(lt, dt) {
    let i;
    for (i = 0; i < 7; ++i) lt.table[i] = 0;
    lt.table[7] = 24; lt.table[8] = 152; lt.table[9] = 112;
    for (i = 0; i < 24; ++i) lt.trans[i] = 256 + i;
    for (i = 0; i < 144; ++i) lt.trans[24 + i] = i;
    for (i = 0; i < 8; ++i) lt.trans[24 + 144 + i] = 280 + i;
    for (i = 0; i < 112; ++i) lt.trans[24 + 144 + 8 + i] = 144 + i;
    for (i = 0; i < 5; ++i) dt.table[i] = 0;
    dt.table[5] = 32;
    for (i = 0; i < 32; ++i) dt.trans[i] = i;
  }
  function build_tree(t, lens, off, num) {
    let i, sum;
    for (i = 0; i < 16; ++i) t.table[i] = 0;
    for (i = 0; i < num; ++i) t.table[lens[off + i]]++;
    t.table[0] = 0;
    for (sum = 0, i = 0; i < 16; ++i) { offs[i] = sum; sum += t.table[i]; }
    for (i = 0; i < num; ++i) if (lens[off + i]) t.trans[offs[lens[off + i]]++] = i;
  }
  function getbit(d) {
    if (!d.bitcount--) { if (d.sourceIndex >= d.source.length) fail(); d.tag = d.source[d.sourceIndex++]; d.bitcount = 7; }
    const bit = d.tag & 1; d.tag >>>= 1; return bit;
  }
  function refill(d) {
    while (d.bitcount < 24) { d.tag |= (d.source[d.sourceIndex++] | 0) << d.bitcount; d.bitcount += 8; }
    if (d.sourceIndex > d.source.length + 4) fail();                  // ran off the end of the input
  }
  function read_bits(d, num, base) {
    if (!num) return base;
    refill(d);
    const val = d.tag & (0xffff >>> (16 - num)); d.tag >>>= num; d.bitcount -= num; return val + base;
  }
  function decode_symbol(d, t) {
    refill(d);
    let sum = 0, cur = 0, len = 0, tag = d.tag;
    do {
      cur = 2 * cur + (tag & 1); tag >>>= 1;
      if (++len > 15) fail();                                          // incomplete or empty code
      sum += t.table[len]; cur -= t.table[len];
    } while (cur >= 0);
    d.tag = tag; d.bitcount -= len;
    return t.trans[sum + cur];
  }
  function decode_trees(d, lt, dt) {
    const hlit = read_bits(d, 5, 257), hdist = read_bits(d, 5, 1), hclen = read_bits(d, 4, 4);
    let i, num, length;
    for (i = 0; i < 19; ++i) lengths[i] = 0;
    for (i = 0; i < hclen; ++i) lengths[clcidx[i]] = read_bits(d, 3, 0);
    build_tree(code_tree, lengths, 0, 19);
    for (num = 0; num < hlit + hdist;) {
      const sym = decode_symbol(d, code_tree);
      if (sym === 16) { if (!num) fail(); const prev = lengths[num - 1]; for (length = read_bits(d, 2, 3); length; --length) lengths[num++] = prev; }
      else if (sym === 17) { for (length = read_bits(d, 3, 3); length; --length) lengths[num++] = 0; }
      else if (sym === 18) { for (length = read_bits(d, 7, 11); length; --length) lengths[num++] = 0; }
      else if (sym < 16) lengths[num++] = sym;
      else fail();
      if (num > hlit + hdist) fail();
    }
    build_tree(lt, lengths, 0, hlit);
    build_tree(dt, lengths, hlit, hdist);
  }
  function inflate_block_data(d, lt, dt) {
    for (;;) {
      let sym = decode_symbol(d, lt);
      if (sym === 256) return;
      if (sym < 256) { put(d, sym); continue; }
      sym -= 257;
      if (!(sym >= 0 && sym < 29)) fail();
      const length = read_bits(d, length_bits[sym], length_base[sym]);
      const dist = decode_symbol(d, dt);
      if (!(dist >= 0 && dist < 30)) fail();
      const from = d.destLen - read_bits(d, dist_bits[dist], dist_base[dist]);
      if (from < 0) fail();
      for (let i = from; i < from + length; ++i) put(d, d.dest[i]);
    }
  }
  function inflate_uncompressed_block(d) {
    while (d.bitcount > 8) { d.sourceIndex--; d.bitcount -= 8; }
    if (d.sourceIndex + 4 > d.source.length) fail();
    const length = 256 * d.source[d.sourceIndex + 1] + d.source[d.sourceIndex];
    const invlength = 256 * d.source[d.sourceIndex + 3] + d.source[d.sourceIndex + 2];
    if (length !== (~invlength & 0x0000ffff)) fail();
    d.sourceIndex += 4;
    if (d.sourceIndex + length > d.source.length) fail();
    for (let i = length; i; --i) { put(d, d.source[d.sourceIndex++]); }
    d.bitcount = 0;
  }
  function uncompress(source, dest) {
    const d = new Data(source, dest);
    let bfinal;
    do {
      bfinal = getbit(d);
      const btype = read_bits(d, 2, 0);
      if (btype === 0) inflate_uncompressed_block(d);
      else if (btype === 1) inflate_block_data(d, sltree, sdtree);
      else if (btype === 2) { decode_trees(d, d.ltree, d.dtree); inflate_block_data(d, d.ltree, d.dtree); }
      else fail();
    } while (!bfinal);
    return d.dest.subarray(0, d.destLen);
  }
  build_fixed_trees(sltree, sdtree);
  build_bits_base(length_bits, length_base, 4, 3);
  build_bits_base(dist_bits, dist_base, 2, 1);
  length_bits[28] = 0; length_base[28] = 258;
  return uncompress;
})();
