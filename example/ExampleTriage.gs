// Example consumer of the four safety modules: a mail-triage decision with no side effects (no labels, no Drive, no
// state). It exists so the contract GUARDs have a consumer to check, and it shows the consumer obligations each
// CONTRACT.md lists: hold an ambiguous From, authenticate parseFrom_'s domain (never a relay's), trust a relay only by an
// explicit rule, keep security-looking names out of automatic handling, and treat any hard PDF finding as "never file".
// The values in EXAMPLE_OPTS are placeholders.
const EXAMPLE_OPTS = { myAddress: 'owner@gmail.com', trustedForwarders: ['forwarder@gmail.com'], relayOk: ['vendor.example'],
  platformSenders: ['mg.platform.example'], platformId: '' };

// One attachment → { verdict: 'NOT_PDF' | 'HELD' | 'REVIEW' | 'FILED', hard, soft }. Only finding classes, never text.
function examplePdfVerdict_(att, caps) {
  const cp = caps || PDF_DEFAULT_CAPS;
  const info = pdfInfo_(att, cp);
  if (!info) return { verdict: 'NOT_PDF', hard: [], soft: [] };
  if (!info.data) return { verdict: 'REVIEW', hard: [], soft: [info.oversized ? 'Oversized' : 'Malformed'] };
  const r = scanPdf_(info.data, false, cp);
  if (r.hard.length) return { verdict: 'HELD', hard: r.hard, soft: r.soft };
  return { verdict: r.soft.length ? 'REVIEW' : 'FILED', hard: [], soft: r.soft, textComplete: textComplete_(info.data) };
}

// One message → { action: 'HOLD' | 'LABEL_ONLY' | 'REVIEW' | 'FILE' | 'SKIP', why }.
function exampleTriage_(msg, opts) {
  const o = opts || EXAMPLE_OPTS;
  const from = parseFrom_(msg.getFrom());
  if (from.ambiguous) return { action: 'HOLD', why: 'ambiguous-from' };
  const sender = effectiveSender_(from);
  if (sender.relay && !matchesAny_(sender, o.relayOk)) return { action: 'HOLD', why: 'relay' };
  const how = {};
  if (!authAligned_(msg, from.domain, how, o)) return { action: 'HOLD', why: 'auth' };
  const atts = msg.getAttachments();
  if (isSecurityName_(msg.getSubject() + ' ' + atts.map(a => a.getName()).join(' ')).hit) return { action: 'LABEL_ONLY', why: 'security-name' };
  if (isMisdirected_(msg, o.myAddress.split('@')[0].toLowerCase())) return { action: 'REVIEW', why: 'misdirected' };
  if (matchesAny_(sender, o.platformSenders) && !platformIdOk_(o.platformId, () => msg.getPlainBody())) return { action: 'REVIEW', why: 'platform' };
  const v = atts.map(a => examplePdfVerdict_(a)).filter(x => x.verdict !== 'NOT_PDF');
  if (!v.length) return { action: 'SKIP', why: 'no-pdf' };
  if (v.some(x => x.verdict === 'HELD')) return { action: 'HOLD', why: 'pdf-hard' };
  if (v.some(x => x.verdict === 'REVIEW') || how.via === 'sub') return { action: 'REVIEW', why: v.some(x => x.verdict === 'REVIEW') ? 'pdf-soft' : 'subdomain-signer' };
  return { action: 'FILE', why: how.via };
}

// Visible text of an HTML body (hidden text, scripts and URLs removed), e.g. to build a receipt from a body.
function exampleBodyText_(msg) {
  return htmlText_(msg.getBody());
}
