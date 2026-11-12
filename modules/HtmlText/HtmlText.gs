// ===================== MODULE HtmlText v1.0.0 =====================
// Contract: modules/HtmlText/CONTRACT.md. Shared by source (ADR-0003); never reference a consumer's globals (GUARD (b)).

// 3.7.1: visible text of an untrusted HTML email (no DOM in Apps Script; nothing is rendered or fetched). Tag-stack walk:
// subtrees that a mail client hides (display:none, mso-hide:all, visibility:hidden, zero size/opacity, hidden attribute,
// head/style/script/title/noscript/template/svg) are dropped, <pre> keeps its spacing, cells are joined by a space,
// rows and blocks by a newline, images and link targets are dropped, entities decoded, URLs and invisible filler removed.
const HT_VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr']);

const HT_SKIP = new Set(['head', 'style', 'script', 'title', 'noscript', 'template', 'svg']);

const HT_BLOCK = new Set(['p', 'div', 'tr', 'li', 'ul', 'ol', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'table', 'tbody', 'thead', 'tfoot', 'pre', 'blockquote', 'section', 'article', 'header', 'footer', 'center', 'dl', 'dt', 'dd', 'hr']);

const HT_AUTOCLOSE = { p: ['p'], li: ['li'], dt: ['dt', 'dd'], dd: ['dt', 'dd'], option: ['option'], td: ['td', 'th'], th: ['td', 'th'], tr: ['td', 'th', 'tr'] };

const HT_ENT = { nbsp: ' ', amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", copy: '©', reg: '®', trade: '™', mdash: '—', ndash: '–', hellip: '…', rsquo: '’', lsquo: '‘', rdquo: '”', ldquo: '“', bull: '•', middot: '·', zwnj: '', zwj: '' };

// Removes every open…close block in one left-to-right pass (indexOf only: linear); an unclosed block drops the rest.
function htCut_(s, open, close) {
  let out = '', i = 0;
  for (;;) {
    const a = s.indexOf(open, i);
    if (a < 0) return out + s.slice(i);
    out += s.slice(i, a);
    const b = s.indexOf(close, a + open.length);
    if (b < 0) return out;
    i = b + close.length;
  }
}

function htHidden_(attrs) {
  const st = (attrs.match(/style\s*=\s*("[^"]*"|'[^']*'|[^\s"'>]+)/i) || [''])[0]
    .replace(/&#(x[0-9a-f]{1,4}|\d{1,5});?/gi, (x, e) => { const n = /^x/i.test(e) ? parseInt(e.slice(1), 16) : parseInt(e, 10); return n > 0 && n < 0xd800 ? String.fromCharCode(n) : ''; })
    .replace(/&colon;/gi, ':').replace(/&semi;/gi, ';');
  if (st && /display\s*:\s*none|mso-hide\s*:\s*all|visibility\s*:\s*hidden|max-height\s*:\s*0(?![.\d])|font-size\s*:\s*0(px)?\s*[;"']|opacity\s*:\s*0\s*[;"']/i.test(st)) return true;
  return /(^|\s)hidden(\s|=|$)/i.test(attrs.replace(/=\s*("[^"]*"|'[^']*'|[^\s"'>]+)/g, '=')) && !/hidden\s*=\s*["']?false/i.test(attrs);
}

function htmlText_(html) {
  const h = htCut_(htCut_(String(html || '').replace(/\r\n?/g, '\n'), '<!--', '-->'), '<![CDATA[', ']]>')
    .replace(/<![^<>]*>/g, '').replace(/<\?[^<>]*>/g, '');                     // doctype, declarations, PIs (3.7.2)
  const out = [], stack = []; let hide = 0, pre = 0, m;
  const re = /<(\/?)([a-zA-Z][a-zA-Z0-9:-]*)([^<>]*)>|([^<]+)|(<)/g;     // [^<>]: linear on '<a<a<a…' (review 3.7.1)
  while ((m = re.exec(h))) {
    if (m[4] !== undefined || m[5] !== undefined) { if (hide) continue; const t = m[4] !== undefined ? m[4] : '<'; out.push(pre ? t.replace(/ /g, '\u00a0') : t.replace(/\s+/g, ' ')); continue; }   // <pre>: spaces protected until the end
    const close = m[1] === '/', tag = m[2].toLowerCase(), attrs = m[3] || '';
    if (!close) {
      if (HT_VOID.has(tag) || /\/\s*$/.test(attrs)) { if (!hide && (tag === 'br' || tag === 'hr')) out.push('\n'); continue; }
      const top = () => stack.length ? stack[stack.length - 1].tag : '';
      const pop = () => { const e = stack.pop(); if (e.hid) hide--; if (e.tag === 'pre') pre--; };
      if (HT_AUTOCLOSE[tag]) while (HT_AUTOCLOSE[tag].includes(top())) pop();   // browsers close an open p/li/td/tr here
      const hid = HT_SKIP.has(tag) || htHidden_(attrs);
      if (stack.length > 2000) break;                        // pathological nesting: stop, never loop
      stack.push({ tag, hid }); if (hid) hide++; if (tag === 'pre') pre++;
      if (!hide && HT_BLOCK.has(tag)) out.push('\n');
    } else {
      let i = stack.length - 1; while (i >= 0 && stack[i].tag !== tag) i--;
      if (i < 0) continue;                                   // stray close tag
      while (stack.length > i) { const e = stack.pop(); if (e.hid) hide--; if (e.tag === 'pre') pre--; }
      if (!hide) out.push(tag === 'td' || tag === 'th' ? ' ' : HT_BLOCK.has(tag) ? '\n' : '');
    }
  }
  return out.join('')
    .replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z0-9]{2,8});/gi, (x, e) => {
      if (e[0] === '#') { const n = /^#x/i.test(e) ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return n > 0 && n < 0x110000 && (n < 0xd800 || n > 0xdfff) ? String.fromCodePoint(n) : ''; }
      const v = HT_ENT[e.toLowerCase()]; return v === undefined ? x : v; })
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u034f\u00ad\u200b-\u200f\u2060-\u2064\ufeff]/g, '')   // 3.7.3: + control chars
    .replace(/(?:https?|ftp|file):\/\/\S*|(?:javascript|vbscript|data):\S*|\bwww\.\S+/gi, '')   // 3.7.3: any position, more schemes
    .split('\n').map(l => l.replace(/[ \t]+/g, ' ').replace(/^[ \t]+|[ \t]+$/g, '')).join('\n')
    .replace(/\n{3,}/g, '\n\n').replace(/\u00a0/g, ' ').trim();
}
