# HtmlText — contract

Version: 1.0.0
Status: as in the source project (MailToDrive, private). Showcase extract: the .gs is byte-identical to the source; this contract names the extract's consumer and test files.
Implementation: `modules/HtmlText/HtmlText.gs`.

## Purpose
Turn untrusted HTML email bodies into plain text.

## Public API (inputs → outputs)
- `htmlText_(html) → string` — Visible text; hidden elements, scripts and styles removed; entities decoded.

## Internal (not API; may change at patch level; contract tests must not call)
HT_VOID, HT_SKIP, HT_BLOCK, HT_AUTOCLOSE, HT_ENT (const tables: new Set(literal) / literal), htCut_, htHidden_.

## Guarantees
- Linear time in input length (tests/unit/html_linear.test.js: 5× input ≈ 5× time).
- Hidden text (display:none, etc.) never appears in output.

## Never does
- Never fetches URLs or images.
- No writes.

## Errors
No throw observed on 4 malformed inputs `[derived: review 2026-10-21, driven — not proof]`.

## Host ctx members read
none

## Apps Script services
none

## Scopes the consumer must hold
none

## Runtime / quota budget
linear in input; no service calls.

## Depends on
none

## Consumers
- Example — callers today: `exampleBodyText_`

## Version history
| Version | sha256 (module + contract API sections; node tools/guards.js --sha HtmlText) | Change | Origin |
|---|---|---|---|
| 1.0.0 | 3bafcc0b8db844fca92f6acc6a5c4fe55c614c8052da120724e5157784d4b206 | Extracted from MailToDrive.gs (Phase 1a, behavior unchanged); showcase extract, sha recomputed | MailToDrive ADR-0011 |

Contract tests: `tests/contract/HtmlText.example.test.js`. Every consumer adds its own file.
