# SecurityNames — contract

Version: 1.0.0
Status: as in the source project (MailToDrive, private). Showcase extract: the .gs is byte-identical to the source; this contract names the extract's consumer and test files.
Implementation: `modules/SecurityNames/SecurityNames.gs`.

## Purpose
Fail-closed test of whether a name looks like security codes, recovery keys or secrets.

## Public API (inputs → outputs)
- `isSecurityName_(s) → {hit: boolean, why: string}` — `why` is `phrase` (a security word + codes/passcodes/keys/kit/phrase/seed),
  `word` (seed phrase, mnemonic, private key), `confusable` (one word — a run of letters — mixing Latin with Cyrillic or Greek letters), `extension`
  (last extension kdbx, 1pux, pem, key, p12, pfx), or `''` when `hit` is false. Non-strings are coerced (null/undefined → '').

## Internal (not API; may change at patch level; contract tests must not call)
secCandidates_(s), SECNAME_PAIR_RE, SECNAME_WORD_RE, SECNAME_EXT

## Safe composition (consumer obligations)
- Pass the raw text (no prior normalization): the confusable check reads the original letters.
- A hit means "keep out of automatic handling"; the consumer decides what that is (MailToDrive: security-code path;
  DownloadsSorter: left in place, reported by ID only). Never log the text that hit.

## Guarantees
- Normalizes before matching: NFKC (fullwidth forms), NFD then combining marks removed, format characters (`\p{Cf}`, incl.
  bidi controls and zero-width characters) both removed and turned into spaces (either reading may hit), runs of
  characters other than letters/digits → one space, a space at each letter→digit boundary, lowercase.
- Catches every "caught" and "missed" name of the source project's file-name table (the contract test drives both lists).
- Pure; linear in input length (no nested quantifiers over the same characters).

## Never does
- No service calls, no state, no logging.

## Errors
none (any input is coerced to a string)

## Host ctx members read
none

## Apps Script services
none

## Scopes the consumer must hold
none

## Runtime / quota budget
linear in input length; two candidate strings per call.

## Depends on
none

## Consumers
- Example — callers today: `exampleTriage_`

## Version history
| Version | sha256 (module + contract API sections; node tools/guards.js --sha SecurityNames) | Change | Origin |
|---|---|---|---|
| 1.0.0 | 4fbdc9d783f5a3de8f4b49f27f687f38371c152226d2eaf2796266bc417ceeb4 | New: replaces MailToDrive's SECURITY_CODES_RE + secText_ (wider, fail closed); showcase extract, sha recomputed | MailToDrive ADR-0016 |

Contract tests: `tests/contract/SecurityNames.example.test.js`. Every consumer adds its own file.
