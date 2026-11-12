# PdfSafety — contract

Version: 1.0.0
Status: as in the source project (MailToDrive, private). Showcase extract: the .gs is byte-identical to the source; this contract names the extract's consumer and test files.
Implementation: `modules/PdfSafety/PdfSafety.gs`.

## Purpose
Classify an untrusted PDF as safe, soft-flagged or hard-blocked, without rendering it.

## Public API (inputs → outputs)
- `pdfInfo_(attachment, caps) → {att, data, offset} | {att, data:null, oversized} | {att, data:null, malformed} | null` — null = not a PDF. caps.maxBytes (default 20 MB); invalid caps → malformed.
- `scanPdf_(data, withText, caps) → {hard[], soft[], text?}` — pdfid-style keyword scan over raw bytes + inflated object streams; `caps` = {maxBytes, inflateCap, maxObjStm}, each optional (PDF_DEFAULT_CAPS); a supplied non-finite, ≤ 0 or above-ceiling value → hard ['CapsInvalid']. scanPdf_(null) throws.
- `textComplete_(data) → boolean` — true only when page text is fully readable (no compressed or hex text).
- `PDF_DEFAULT_CAPS` — {maxBytes: 20 MB, inflateCap: 8 MB, maxObjStm: 200}; changing a default is a minor version.
- `PDF_MAX_CAPS` — ceilings {maxBytes: 50 MB, inflateCap: 32 MB, maxObjStm: 1000}: a cap above its ceiling is invalid (fail closed). Raising a ceiling is a major version (it widens what a consumer can switch off).
- `PDF_HARD, PDF_SOFT` — Keyword tables; adding = minor, removing or reclassifying = major.

## Internal (not API; may change at patch level; contract tests must not call)
pdfCaps_(caps), objStmText_(data, raw, hard, cp), pdfNames_(s), pdfUris_(text, hard, soft), inflateZlib_(s, dest) (throws "Data error" on bad input; objStmText_ catches), INFLATE_ (closed IIFE).

## Safe composition (consumer obligations)
- Treat a non-empty `hard` list as "never file".

## Guarantees
- Never executes or renders PDF content.
- Output arrays name keyword classes only; text only when withText, for date reading.
- Bounds can never be switched off: omitted caps use PDF_DEFAULT_CAPS; a supplied cap that is invalid or above PDF_MAX_CAPS fails closed.
- Linear time in input (tests/scan_corpus.test.js times every scan).

## Never does
- Never logs document text.
- Never writes to Drive or properties.

## Errors
Malformed input returns {malformed}; inflate errors become hard findings; objStmText_ has no throw path for string input `[derived: review 2026-10-21]`; scanPdf_(null) throws.

## Host ctx members read
none

## Apps Script services
none

## Scopes the consumer must hold
none

## Runtime / quota budget
CPU linear in PDF bytes; inflate ≤ caps.inflateCap bytes and ≤ caps.maxObjStm streams per PDF (MailToDrive: 8 MB, 200).

## Depends on
none

## Consumers
- Example — callers today: `examplePdfVerdict_`

## Version history
| Version | sha256 (module + contract API sections; node tools/guards.js --sha PdfSafety) | Change | Origin |
|---|---|---|---|
| 1.0.0 | 6d4717d62ea2a770c0d519a8fa5f071b1d452864a22e18dd87cd411957182da2 | Extracted from MailToDrive.gs (Phase 1a, behavior unchanged); showcase extract, sha recomputed | MailToDrive ADR-0011 |

Contract tests: `tests/contract/PdfSafety.example.test.js`. Every consumer adds its own file.
