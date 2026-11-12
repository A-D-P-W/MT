// ===================== MODULE SecurityNames v1.0.0 =====================
// Contract: modules/SecurityNames/CONTRACT.md. Shared by source (ADR-0003); never reference a consumer's globals (GUARD (b)).
// Fail-closed test for names (file names, email subject + attachment name) that look like security codes, recovery keys or
// secrets (DownloadsSorter SPEC § 8.1). A false positive only keeps an item out of automatic filing.

// Word edges are ASCII letters/digits, as in MailToDrive's old SECURITY_CODES_RE: any other character (é, 中, ร, ß, …)
// next to the phrase is an edge, so this check catches everything the old one did (review 2026-11-07, driven: 443,520
// old-grammar strings, all caught — tests/contract/SecurityNames.mailtodrive.test.js).
const SECNAME_PAIR_RE = /(?<![a-z0-9])(backup|recovery|emergency|2fa|two ?factor|security|verification|one ?time|otp|mfa) ?(codes?|passcodes?|keys?|kit|phrase|seed)(?![a-z0-9])/;
const SECNAME_WORD_RE = /(?<![a-z0-9])(seed ?phrase|mnemonic|private ?key)(?![a-z0-9])/;
const SECNAME_EXT = new Set(['kdbx', '1pux', 'pem', 'key', 'p12', 'pfx']);

// Candidate texts: (1) and (2) of SPEC § 8.1 step 2 — format characters removed / turned into spaces, after NFKC
// (fullwidth folds) and NFD with combining marks removed; then runs of non-letters/digits → one space, a space at each
// letter→digit boundary. (3) MailToDrive's old secText_ reading of the raw text (format characters removed; _ - and
// whitespace incl. NBSP → one space), so a mark-stripped neighbour (é → e) cannot glue onto the phrase.
function secCandidates_(s) {
  const raw = String(s === undefined || s === null ? '' : s);
  const n = raw.normalize('NFKC').normalize('NFD').replace(/\p{M}/gu, '');
  return [n.replace(/\p{Cf}/gu, ''), n.replace(/\p{Cf}/gu, ' ')]
    .map(t => t.replace(/[^\p{L}\p{N}]+/gu, ' ').replace(/(\p{L})(?=\p{N})/gu, '$1 ').toLowerCase().trim())
    .concat([raw.replace(/\p{Cf}/gu, '').replace(/[\s_-]+/g, ' ').toLowerCase()]);
}

// { hit, why }: why = 'phrase' | 'word' | 'confusable' | 'extension' | '' (no hit).
function isSecurityName_(s) {
  const raw = String(s === undefined || s === null ? '' : s);
  const c = secCandidates_(raw);
  if (c.some(t => SECNAME_PAIR_RE.test(t))) return { hit: true, why: 'phrase' };
  if (c.some(t => SECNAME_WORD_RE.test(t))) return { hit: true, why: 'word' };
  // One word (a run of letters) mixing Latin with Cyrillic or Greek = a look-alike spelling ("bаckup" with a Cyrillic а).
  // Per word, not per name: "10Ω resistor" or a Greek word beside a Latin one is not a disguise (driven 2026-11-07).
  for (const w of raw.matchAll(/\p{L}+/gu)) if (/\p{Script=Latin}/u.test(w[0]) && /[\p{Script=Cyrillic}\p{Script=Greek}]/u.test(w[0])) return { hit: true, why: 'confusable' };
  const dot = raw.lastIndexOf('.');
  if (dot >= 0 && SECNAME_EXT.has(raw.slice(dot + 1).trim().toLowerCase())) return { hit: true, why: 'extension' };
  return { hit: false, why: '' };
}
