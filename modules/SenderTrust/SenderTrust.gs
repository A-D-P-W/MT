// ===================== MODULE SenderTrust v1.0.0 =====================
// Contract: modules/SenderTrust/CONTRACT.md. Shared by source (ADR-0003); never reference a consumer's globals (GUARD (b)).

// Uses only the LAST <addr>; anything unusual is ambiguous and never trusted.
function parseFrom_(raw) {
  const s = String(raw || '');
  const angles = s.match(/<[^<>]*>/g) || [];
  const m = /<([^<>]+)>\s*$/.exec(s);
  const addr = (m ? m[1] : s).trim().toLowerCase();
  const ambiguous = angles.length > 1 || (addr.match(/@/g) || []).length !== 1 || /[\s,;<>"()]/.test(addr);
  return { addr, domain: ambiguous ? '' : addr.split('@')[1], ambiguous };
}

// iCloud Hide-My-Email rewrites senders as <local>_at_<domain_with_underscores>_<token>_<tail>@icloud.com.
// The tail is alphanumeric, not hex (shape: ..._<token>_<tail>@icloud.com).
function effectiveSender_(from) {
  if (from.ambiguous || from.domain !== 'icloud.com') return { addr: from.addr, domain: from.domain, relay: false };
  const m = /^(.+?)_at_([a-z0-9-]+(?:_[a-z0-9-]+)+)_[a-z0-9]+_[a-z0-9]+$/i.exec(from.addr.split('@')[0]);
  if (!m) return { addr: from.addr, domain: from.domain, relay: false };
  const domain = m[2].replace(/_/g, '.').toLowerCase();
  return { addr: m[1].toLowerCase() + '@' + domain, domain, relay: true };
}

function matchesAny_(s, list) {
  return list.some(f => f.includes('@') ? s.addr === f : (s.domain === f || s.domain.endsWith('.' + f)));
}

// Strict reading of the TOPMOST Authentication-Results header written by mx.google.com.
// Comments are stripped, each ';' clause is parsed as method=result + properties, and the
// identity in the passing clause must align with the visible From domain.
// 3.8.4 (ADR-0010, owner decision 2026-10-21: measure first): `why` (optional) receives how the sender passed —
// 'dmarc' | 'exact' | 'parent' | 'sub' | 'forward' — so mail that passed ONLY through a signer that is a subdomain of
// the From domain can be counted. Every clause is evaluated (none has side effects), so the return value is the same
// as the first-match loop it replaces.
function authAligned_(msg, fromDomain, why, opts) {
  if (!fromDomain) return false;
  const first = topAuthResults_(msg);
  if (!first) return false;
  let v = first.replace(/^Authentication-Results:\s*/i, '');
  v = v.replace(/"(?:[^"\\]|\\.)*"/g, '""');                       // quoted local parts may hide ';' or '('
  for (let i = 0; i < 5; i++) v = v.replace(/\([^()]*\)/g, ' ');          // strip (nested) comments
  if (/[()]/.test(v)) return false;                                        // unbalanced or too deeply nested → fail closed
  if (/["\\]/.test(v.replace(/""/g, ''))) return false;                    // stray quote or backslash outside a quoted string
  const clauses = v.split(';').map(c => c.trim());
  if (clauses.shift().toLowerCase() !== 'mx.google.com') return false;    // authserv-id must be Google's MX
  const RANK = { dmarc: 4, exact: 3, parent: 2, sub: 1 };
  const kind = d => { d = String(d || '').toLowerCase().replace(/^@/, ''); return !d ? '' : d === fromDomain ? 'exact' : fromDomain.endsWith('.' + d) ? 'parent' : d.endsWith('.' + fromDomain) ? 'sub' : ''; };
  let best = '';
  const take = k => { if (k && (!best || RANK[k] > RANK[best])) best = k; };
  for (const c of clauses) {
    const m = /^(dkim|spf|dmarc)=([a-z]+)(?:\s|$)/i.exec(c);
    if (!m || m[2].toLowerCase() !== 'pass') continue;
    const props = {};
    for (const p of c.slice(m[0].length).matchAll(/(?:^|\s)((?:header|smtp)\.[a-z]+)=(\S+)/gi)) props[p[1].toLowerCase()] = p[2];
    const method = m[1].toLowerCase();
    if (method === 'dmarc' && String(props['header.from'] || '').toLowerCase() === fromDomain) take('dmarc');
    if (method === 'dkim') { take(kind(props['header.d'])); take(kind(String(props['header.i'] || '').split('@').pop())); }
    if (method === 'spf') take(kind(String(props['smtp.mailfrom'] || '').split('@').pop()));
  }
  if (best) { if (why) why.via = best; return true; }
  const fw = forwardedAligned_(msg, fromDomain, first, opts);
  if (fw && why) why.via = 'forward';
  return fw;
}

// 3.8.0: true when the owner set PLATFORM_ID_<rule id> (≥ 6 characters after trimming) and the message body contains it,
// compared case-insensitively with runs of whitespace collapsed. The value is never logged or returned.
function platformIdOk_(expected, getBody) {
  const norm = x => String(x || '').toLowerCase().replace(/\s+/g, ' ').trim();
  const want = norm(expected);
  if (want.length < 6) return false;
  try { return norm(getBody()).includes(want); } catch (e) { return false; }
}

// 3.8.0: top-level clauses of an Authentication-Results value, each with the text of the comment that follows it.
// One linear pass; quoted strings are kept whole (a quoted local part may hide ';' or '('); nesting > 5, an unclosed
// quote or comment → null (fail closed).
function arClauses_(v) {
  const out = []; let cur = '', com = '', depth = 0, q = false, lastComment = null;
  const push = () => { const t = cur.trim(); if (t) out.push({ text: t, comment: lastComment }); cur = ''; lastComment = null; };
  for (let i = 0; i < v.length; i++) {
    const ch = v[i];
    if (q) { if (ch === '\\' && i + 1 < v.length) { (depth ? com += ch + v[++i] : cur += ch + v[++i]); continue; } if (ch === '"') q = false; depth ? com += ch : cur += ch; continue; }
    if (ch === '"') { q = true; depth ? com += ch : cur += ch; continue; }
    if (ch === '(') { if (++depth > 5) return null; if (depth > 1) com += ch; continue; }
    if (ch === ')') { if (!depth) return null; if (--depth === 0) { if (lastComment === null) lastComment = com; com = ''; cur += ' '; } else com += ch; continue; }
    if (depth) { com += ch; continue; }
    if (ch === ';') { push(); continue; }
    cur += ch;
  }
  if (q || depth) return null;
  push();
  return out;
}

// 3.8.0 (owner decision 2026-10-21): mail auto-forwarded by Gmail from one of TRUSTED_FORWARDERS. Every part comes from
// Google, never from the sender: Google's own AR (googleAuthResults_) must say
//   arc=pass (i=N … dmarc=pass fromdomain=<From domain or parent>)  — Google verified the ARC chain and reports set N;
//   spf=pass smtp.mailfrom=<forwarder local>+caf_=<my local>=gmail.com@gmail.com  — Gmail's forwarding envelope;
// and the raw headers must hold exactly one ARC-Seal with i=N, signed d=google.com (the forwarding Gmail sealed it).
function forwardedAligned_(msg, fromDomain, first, opts) {
  try {
    if (!opts || typeof opts.myAddress !== 'string' || !/@gmail\.com$/i.test(opts.myAddress)) return false;   // 3.9.0: consumer values; none → no forwarding trust
    const forwarders = (Array.isArray(opts.trustedForwarders) ? opts.trustedForwarders : []).filter(f => typeof f === 'string' && /^[a-z0-9.+_-]+@gmail\.com$/i.test(f));   // only the local part is compared below: non-Gmail entries never count
    const cl = arClauses_(String(first).replace(/^Authentication-Results:\s*/i, ''));
    if (!cl || !cl.length || cl[0].text.toLowerCase() !== 'mx.google.com') return false;
    const arcs = cl.filter(c => /^arc=/i.test(c.text.trim())), arc = arcs.length === 1 && /^arc=pass$/i.test(arcs[0].text.trim()) ? arcs[0] : null;   // exactly one arc clause
    if (!arc || !arc.comment) return false;
    const n = /^\s*i=(\d{1,2})\s/.exec(arc.comment), dm = /(?:^|\s)dmarc=pass\s/.test(arc.comment + ' '), fd = /(?:^|\s)fromdomain=([a-z0-9.-]+)(?:\s|$)/i.exec(arc.comment);
    if (!n || !dm || !fd) return false;
    const d = fd[1].toLowerCase();
    if (d !== fromDomain) return false;                                            // Google reports the From domain it saw: exact match
    const me = opts.myAddress.split('@')[0].toLowerCase();
    const spf = cl.find(c => /^spf=pass\s/i.test(c.text));
    const mf = spf && /(?:^|\s)smtp\.mailfrom=("?)([^"\s;]+)\1(?:\s|$)/i.exec(spf.text);
    const env = mf ? mf[2].toLowerCase() : '';
    if (!forwarders.some(f => env === f.split('@')[0].toLowerCase() + '+caf_=' + me + '=gmail.com@gmail.com')) return false;
    const raw = msg.getRawContent(), end = raw.search(/\r?\n\r?\n/);
    // Every ARC set must be Google's (review M1: a captured Google chain re-sealed by another domain stays valid per RFC 8617
    // §5.2, and Google's comment need not report the latest set): one seal per instance 1..max, each d=google.com, no
    // repeated tags (RFC 6376 §3.2), and the reported set N within the chain.
    const seals = (end > 0 ? raw.slice(0, end) : raw).replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/).filter(l => /^ARC-Seal:/i.test(l))
      .map(l => { const t = {}; for (const kv of l.replace(/^ARC-Seal:/i, '').split(';')) { const m = /^\s*([a-z]+)\s*=\s*(.*?)\s*$/i.exec(kv); if (!m) continue;
                  const k = m[1].toLowerCase(); if (k in t) return null; t[k] = m[2]; } return t; });
    if (!seals.length || seals.some(t => !t)) return false;
    const is = seals.map(t => Number(t.i)).sort((a, b) => a - b);
    if (is.some((v, k) => v !== k + 1) || Number(n[1]) > is.length) return false;
    return seals.every(t => String(t.d).toLowerCase() === 'google.com');
  } catch (e) { return false; }
}

// 3.7.5 (D11): the Authentication-Results header Google added on SMTP delivery, or null. Header lines must be unfolded
// and in wire order. Google prepends its own trace headers, so its delivery hop is the first Received line after its
// internal hops; everything below it came from the sender. Owner sample 2026-10-20: Received (by mx.google.com with
// ESMTPS) → Received-SPF → Authentication-Results: mx.google.com.
function googleAuthResults_(lines) {
  let i = lines.findIndex(l => /^Received:/i.test(l));
  while (i >= 0 && /^Received:\s*by [0-9a-f.:]+ with SMTP id\b/i.test(lines[i])) {
    let k = i + 1; while (k < lines.length && !/^Received:/i.test(lines[k])) k++;
    i = k < lines.length ? k : -1;
  }
  if (i < 0) return null;
  let g = lines[i];
  for (let n = 0; n < 5; n++) g = g.replace(/\([^()]*\)/g, ' ');            // comments may not carry the by-host
  if (/[()]/.test(g) || !/^Received:\s*from\s.+?\sby mx\.google\.com with (?:E?SMTPS?A?|UTF8SMTPS?A?) id \S+/i.test(g)) return null;
  let j = i + 1;
  if (j < lines.length && /^Received-SPF:/i.test(lines[j])) j++;
  return j < lines.length && /^Authentication-Results:\s*mx\.google\.com\s*;/i.test(lines[j]) ? lines[j] : null;
}

// The Google-written Authentication-Results header (googleAuthResults_), or null. Advanced Gmail (format=metadata) avoids
// downloading attachments, but its header order is undocumented: its answer is used only when it passes the full rule;
// otherwise the raw message's headers (exact wire order) decide.
function topAuthResults_(msg) {
  if (typeof Gmail !== 'undefined' && Gmail.Users) {
    try {
      const r = Gmail.Users.Messages.get('me', msg.getId(), { format: 'metadata', metadataHeaders: ['Received', 'Received-SPF', 'Authentication-Results'] });
      const hs = ((r.payload && r.payload.headers) || []).filter(h => /^(Received|Received-SPF|Authentication-Results)$/i.test(h.name));
      const ls = hs.map(h => h.name + ': ' + String(h.value).replace(/\r?\n[ \t]+/g, ' '));
      // Metadata order is undocumented: a sender-forged block needs a 2nd Google-style hop and a 2nd mx.google.com AR,
      // so the fast path is trusted only with exactly one of each (forwarded mail falls back to raw).
      const one = re => ls.filter(l => re.test(l)).length === 1;
      const hit = one(/^Authentication-Results:\s*mx\.google\.com\s*;/i) && one(/\sby mx\.google\.com with (?:E?SMTPS?A?|UTF8SMTPS?A?) id\s/i) ? googleAuthResults_(ls) : null;
      if (hit) return hit;
    } catch (e) { /* fall through to raw */ }
  }
  const raw = msg.getRawContent();
  const end = raw.search(/\r?\n\r?\n/);
  const headers = (end > 0 ? raw.slice(0, end) : raw).replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/);
  return googleAuthResults_(headers);
}

// True when the mail was addressed to a dotted spelling of the user's Gmail and never to the exact address.
function isMisdirected_(msg, myLocal) {
  const hdr = (String(msg.getTo() || '') + ',' + String(msg.getCc() || '')).replace(/"(?:[^"\\]|\\.)*"/g, '');
  let dotted = false, exact = false;
  const addrs = [];
  for (const part of hdr.split(',')) {                  // with a display name, only the <addr> counts
    const angle = part.match(/<([^<>]*)>/g);
    addrs.push(angle ? angle[angle.length - 1].slice(1, -1) : part);
  }
  // Left edge anchored: no RFC 5322 atext (or '.') may precede the local part, so "x=j.doe@…" is not ours.
  const re = /(?<![A-Za-z0-9!#$%&'*+\/=?^_`{|}~.-])[A-Za-z0-9._%+-]+@(?:gmail|googlemail)\.com(?![A-Za-z0-9.-])/gi;
  for (const a of addrs.join(',').match(re) || []) {
    const local = a.split('@')[0].split('+')[0];
    if (local.replace(/\./g, '').toLowerCase() !== myLocal) continue;
    if (local.includes('.')) dotted = true; else exact = true;
  }
  return dotted && !exact;
}
