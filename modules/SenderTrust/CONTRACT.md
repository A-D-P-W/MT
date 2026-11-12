# SenderTrust — contract

Version: 1.0.0
Status: as in the source project (MailToDrive, private). Showcase extract: the .gs differs from the source in two comments only (personal values removed); this contract names the extract's consumer and test files.
Implementation: `modules/SenderTrust/SenderTrust.gs`.

## Purpose
Decide whether an email's visible sender is authenticated by Google.

## Public API (inputs → outputs)
- `parseFrom_(raw) → {addr, domain, ambiguous}` — Uses only the last <addr>; anything unusual → ambiguous, domain ''.
- `effectiveSender_(from) → {addr, domain, relay}` — Unwraps iCloud Hide-My-Email relay addresses; anything else unchanged.
- `matchesAny_(sender, list) → boolean` — Entry with @ = exact address; else domain or subdomain.
- `authAligned_(msg, fromDomain, why, opts) → boolean` — `why` (optional object) receives `via` = 'dmarc' | 'exact' | 'parent' | 'sub' | 'forward' (source project 3.8.4). true when Google's topmost Authentication-Results (located by topAuthResults_) passes DMARC with header.from = fromDomain, or DKIM/SPF aligned with fromDomain, or the forwarding rule passes. `opts` = {myAddress, trustedForwarders}; without opts, or with a non-Gmail myAddress, there is no forwarding trust; trustedForwarders entries that are not @gmail.com never count (only the local part is compared).
- `platformIdOk_(expected, getBody) → boolean` — The expected identifier is passed in (MailToDrive: ctx.state PLATFORM_ID_<rule id>). < 6 chars → false. Never logged or returned.
- `isMisdirected_(msg, myLocal) → boolean` — true when To/Cc hold ≥ 1 dotted spelling of myLocal@gmail.com/googlemail.com and no exact spelling; other recipients are ignored.

## Internal (not API; may change at patch level; contract tests must not call)
topAuthResults_, googleAuthResults_, forwardedAligned_, arClauses_ — they trust the header text or line order they are given; only authAligned_ may call them. A contract test that calls them directly FAILS GUARD (c).

## Safe composition (consumer obligations)
- Hold (never trust) when parseFrom_ returns ambiguous.
- Call authAligned_ with parseFrom_(...).domain, never with effectiveSender_(...).domain (a relay's auth is the relay's).
- A relay (effectiveSender_.relay) is trusted only by an explicit consumer rule (MailToDrive: relayOk).

## Guarantees
- Fails closed: any parse doubt returns false/null/ambiguous.
- Reads only Google-written headers for trust; sender-written headers never raise trust.
- Linear time in header size (tests/unit/auth_headers.test.js).
- No writes of any kind.

## Open items
- Design note: DKIM/SPF alignment accepts a signer that is a subdomain of the From domain, with no public-suffix floor (`d.endsWith('.' + fromDomain)` in authAligned_'s `kind()`): From billing@co.uk signed by d=evil.co.uk passes. `why.via` reports such a pass as 'sub', so a consumer that needs a floor routes it to review (the Example consumer does).

## Never does
- Never logs or returns header values or platform identifiers.
- Never sends mail, labels, or calls GmailApp.search.
- Widening trust (anything that returns true where 1.0.0 returned false) is always a MAJOR version (and a decision record in the source project).

## Errors
forwardedAligned_ catches its own errors (→ false). topAuthResults_ catches metadata-path errors and falls back to raw; a `getRawContent()` error on the raw path is NOT caught and propagates through authAligned_ to the caller (MailToDrive: triage_ → processThread_ error handling) `[derived: MailToDrive.gs topAuthResults_, authAligned_]`.

## Host ctx members read
none

## Apps Script services
Gmail advanced service (`Gmail.Users.Messages.get`, format=metadata) when present; `GmailMessage.getRawContent`.

## Scopes the consumer must hold
https://mail.google.com/ (MailToDrive). Whether gmail.readonly covers getRawContent: [unverified].

## Runtime / quota budget
≤ 1 Messages.get + ≤ 1 getRawContent per message; CPU linear in header bytes.

## Depends on
none

## Consumers
- Example — callers today: `exampleTriage_`

## Version history
| Version | sha256 (module + contract API sections; node tools/guards.js --sha SenderTrust) | Change | Origin |
|---|---|---|---|
| 1.0.0 | f57589a06e107fe0edac6692bbdc307afaceb9a06cbd5493e3d3d42e0f1221a0 | Extracted from MailToDrive.gs (Phase 1a, behavior unchanged); showcase extract, sha recomputed | MailToDrive ADR-0011 |

Contract tests: `tests/contract/SenderTrust.example.test.js`. Every consumer adds its own file.
