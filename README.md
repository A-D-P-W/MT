# MailToDrive safety core

This is the input-safety core of **MailToDrive**, a private Google Apps Script that files PDF attachments from Gmail into a
structured Google Drive tree. This repository holds the four modules that touch untrusted input, their written contracts,
and the tests behind two claims you can rerun yourself:

1. **An adversarial PDF corpus:** 15 attack files plus 1 control, and a pinned benign set. The PDF scanner holds active
   content and lets ordinary documents through.
2. **Module contracts:** each module has a `CONTRACT.md`. Static AST guards enforce the contracts, and the guards are
   themselves tested by six deliberate breaks.

The app itself is not here: no Gmail or Drive code, no sender rules, no folder map. Together those would describe the
owner's mail and accounts.

| Module | What it decides | Public API |
|---|---|---|
| `PdfSafety` | Is an untrusted PDF safe, flagged for review, or never to be filed? It scans keywords pdfid-style over the raw bytes and over the inflated object streams, and never renders anything. | `pdfInfo_`, `scanPdf_`, `textComplete_`, caps |
| `SenderTrust` | Did Google authenticate the visible sender? It reads only the Authentication-Results header Google wrote, plus ARC for Gmail forwarding. | `parseFrom_`, `authAligned_`, `effectiveSender_`, … |
| `SecurityNames` | Does a subject or file name look like backup codes, recovery keys or secrets (including look-alike spellings)? | `isSecurityName_` |
| `HtmlText` | What is the visible text of an untrusted HTML email (hidden text, scripts and URLs removed)? | `htmlText_` |

`example/ExampleTriage.gs` is a small consumer with no side effects. It gives the guards a consumer to check, and it
shows the obligations each contract places on callers.

## How it was built

I built MailToDrive by directing AI coding agents (Claude Code). The agents wrote the code and the tests; I made the
design and policy decisions. Every expert review was done by an AI agent playing a domain expert (security, Apps Script,
Gmail, software architecture, JavaScript tooling, GitHub). A separate QA-tester agent then checked each review's claims
with driven tests before any finding was accepted. This extract was built the same way.

## Run it

Needs Node 18 or later (tested on Node 22) and bash.

```bash
npm ci
```

```bash
./run.sh
```

`npm ci` installs one dev dependency, acorn 8.14.0, pinned by its lockfile integrity hash; the guards use it to parse
modules. `./run.sh` runs every suite in about 6 seconds and ends with one line:

```
VERDICT: PASS - 11 suites, 327 checks passed, 0 failed
```

| Suite | Checks | What it does |
|---|---|---|
| `tests/contract/*.example.test.js` | 149 | What the consumer relies on from each module, one case per hard PDF keyword included. The loader refuses Internal helpers. |
| `tests/unit/html_linear.test.js` | 29 | Linear time (ReDoS) for 10 open-without-close constructs at 500 KB, each in a child process with a 10 s limit, plus a seeded 3,000-input fuzz. |
| `tests/unit/auth_headers.test.js` | 87 | Forged and look-alike header stacks, quoted-string smuggling, the ARC forwarding rule, linear time at 500 KB, and two seeded fuzzers. |
| `tests/corpus.test.js` | 21 | The 16-file adversarial corpus, through the consumer (each file's sha256 checked first). |
| `tests/scan_corpus.test.js` | 28 | Scans a pinned benign set and 11 hand-built attacks in a bare `vm` context, which proves the scanner is plain ECMAScript. |
| `tests/hygiene.test.js` | 5 | No credentials and no personal data in any tracked file; `run.sh` is executable in the git index. |
| `tools/guards.js` | 1 | The module GUARDs (below). |
| `tools/guard_selftest.js` | 7 | Six structural breaks, each caught by the guard named for it, plus an unmodified control. |

The runner also fails on any `tests/**/*.test.js` it does not run. A suite counts as failed when it passes nothing,
crashes, or runs out of time.

To regenerate the PDFs (needs `pip install pikepdf reportlab`):

```bash
python3 -I corpus/gen_corpus.py
```

```bash
python3 -I scanner/gen_scanner_set.py && node scanner/mk.js
```

The output is deterministic, except the two encrypted corpus files, which get a random key each run.
`scanner/SHA256SUMS` pins the scanner set, so results never depend on what PDFs a machine happens to have.

## The adversarial corpus

`corpus/gen_corpus.py` writes the following files. Each is checked after writing (pikepdf opens it, zipfile reads it),
and `corpus/manifest.json` records which keywords are visible in the raw bytes.

| File | Attack | Expected |
|---|---|---|
| 01 | control: plain invoice | FILED |
| 02, 03, 03b | JavaScript via `/OpenAction`, a `/Names` tree, and inside a compressed object stream | HELD |
| 04, 05 | `/Launch` an external program; an embedded `.exe` | HELD |
| 06 | full-page link to a look-alike login page | REVIEW |
| 07 | `/J#61vaScript`, a `#`-escaped name obfuscation | HELD |
| 08, 08b | encrypted (cannot be inspected); encrypted object stream hiding JavaScript | REVIEW, HELD |
| 09, 09b | PDF+ZIP polyglots: ZIP after `%%EOF`, and ZIP first with `%PDF-` at offset 35 | HELD |
| 10, 10b | truncated; header followed by random bytes | REVIEW |
| 11, 11b | prompt injection in the visible text and in the file name | text: no effect; name: kept out of automatic filing |

`scanner/` adds 14 benign PDFs of the kinds real writers produce (object streams, xref streams, linearized files, forms,
outlines, hex-string text, 300 pages), a decompression bomb, and eight hand-built attacks (A–H).

## Module contracts and their GUARDs

Every `modules/<Name>/CONTRACT.md` has the same sections: Public API, Internal, Safe composition (what the consumer
must do), Guarantees, Never does, Errors, Apps Script services, Depends on, Consumers, and a version table.
`tools/guards.js` enforces three rules:

- **(a) A version row per change.** The sha256 of the module source plus its contract's API sections must match the top
  row of the version table. Changing behavior or a promise without a new version fails.
- **(b) Static AST checks of each module.** No free identifier from a consumer. Other modules only through "Depends on".
  Apps Script services only when the contract lists them. No `eval`, `Function`, `globalThis`, `this` or `.constructor`.
  Top-level initializers make no call at load time. Every top-level name is either Public or Internal.
- **(c) Consumer contract tests.** Each consumer has a contract test that calls or reads every Public export the
  consumer uses, read from the test's AST, and never references an Internal helper.

`tools/guard_selftest.js` breaks the repository six ways, each in a scratch copy, and checks that the right guard fires:

1. a module reads a consumer global;
2. a module calls an unlisted service;
3. a top-level initializer runs code at load time;
4. a module's behavior changes without a version row;
5. a contract test reaches an Internal helper;
6. the consumer starts using an export its test never exercises.

The guard caught all 6.

## Ablation: do the tests notice when a guard is removed?

```bash
node tools/ablation.js
```

This takes about 2 minutes. It removes one safety guard at a time from the module code (in a scratch copy), runs the
behavioral suites, and counts the failing checks. The structural guards are left out of this run, because GUARD (a)
fails on any edit and would hide what the tests themselves catch.

A review on 2026-11-11 found that the tests caught 11 of 15 removed guards. That review's list was not saved, so this
script rebuilds it with the same 4 misses; run against the tests as they stood then, it gave the same totals. Tests were
then added for each miss that a test can catch.

**Result: 15 guards, 14 caught, 1 equivalent mutant, 0 missed** (was 11 caught, 4 missed).

| # | Guard removed | Module | Failing checks | Result |
|---|---|---|---|---|
| 1 | hard keywords `/JavaScript`, `/JS` | PdfSafety | 14 | caught |
| 2 | hard keyword `/Launch` | PdfSafety | 3 | caught |
| 3 | hard keywords `/XFA /GoToE /GoToR /SubmitForm /ImportData /Rendition` | PdfSafety | 6 | caught (was missed) |
| 4 | `#xx` name-escape decoding | PdfSafety | 3 | caught |
| 5 | object-stream inflation before the scan | PdfSafety | 11 | caught |
| 6 | hold for an encrypted object stream | PdfSafety | 1 | caught |
| 7 | inflate output cap (decompression bomb) | PdfSafety | 1 | caught |
| 8 | polyglot check after the last `%%EOF` | PdfSafety | 2 | caught |
| 9 | polyglot check before `%PDF-` (`PdfSafety.gs:68`) | PdfSafety | 3 | caught (was missed) |
| 10 | quoted strings neutralized before the header is split | SenderTrust | 2 | caught |
| 11 | two `<addr>` in From → ambiguous | SenderTrust | 2 | caught |
| 12 | best-of ranking of passing clauses (`>` → `>=`) | SenderTrust | 0 | equivalent mutant |
| 13 | hidden-element detection | HtmlText | 5 | caught |
| 14 | linear tag regex `[^<>]*` (`HtmlText.gs:43`) | HtmlText | 5 | caught (was a hang) |
| 15 | mixed-script (look-alike) word check | SecurityNames | 2 | caught |

What the original misses were, and what changed:

- **#3, six hard keywords.** No corpus file or test used them, so nothing noticed when they went. The PdfSafety contract
  test now has one case per keyword.
- **#9, the prefix polyglot branch.** Both corpus polyglots also carry ZIP data after `%%EOF`, so the tail check (#8)
  held them anyway. The contract test now has three prefix-only polyglots (ZIP, EXE and HTML bytes before `%PDF-`, nothing
  after `%%EOF`), plus a control: harmless text before `%PDF-` is only flagged soft.
- **#12, an equivalent mutant.** Every rank is unique, so `>=` behaves exactly like `>`. No test can catch it, and none
  should. Instead of trusting that argument, the ablation runs the original and the mutant side by side on 20,000 seeded
  random Authentication-Results headers: 0 differ. As a control, a mutant that really changes the ranking makes 1,323 of
  them differ, so the check can see a difference when there is one.
  While rebuilding the table I found a second equivalent case: the `mx.google.com` re-check inside `authAligned_` can
  never be reached, because `topAuthResults_` only returns a header that already starts that way. That check is defence
  in depth, so the table uses #10 instead.
- **#14, a ReDoS regression.** Changing `[^<>]*` to `[^>]*` makes the tag regex quadratic on `<a <a <a …`, and the
  linear-time suites used to hang until the runner's time limit. The timed runs now happen in a child process with a 10 s
  limit (`tests/unit/timed.js`), so the regression fails 5 named checks ("did not finish in 10 s: super-linear") instead.

## Known open item

The keyword scan reads raw bytes, including compressed page content. Random bytes that happen to spell `/JS` followed
by a non-word byte will hold a benign file. This fails safe: the file is held, never let through. On 1 MB random-byte
streams, about 4% are held as `JS`. One file in the benign set (`b14_300_pages_objstm.pdf`) hits this by chance.
`tests/scan_corpus.test.js` keeps it visible: it checks that the file is held for exactly this reason, and the runner
prints it as a `NOTICE`.

## What differs from the private source

- **Module code.** `PdfSafety.gs`, `SecurityNames.gs` and `HtmlText.gs` are byte-identical to the source.
  `SenderTrust.gs` differs in two comments, where personal values were replaced.
- **Contracts.** They name this repository's consumer and test files, and their version rows carry recomputed hashes.
- **Tests.** The source's per-consumer contract tests (three consumer apps) are merged into one consumer, `Example`.
  Every address, domain, business and person name is a placeholder; the Gmail-shaped placeholders are needed because
  the modules' forwarding and misdirection rules are Gmail-only.
- **PDFs.** The source's benign scanner set used public TeX font-documentation PDFs and whatever PDFs the host had
  under `/usr/share`. Both were replaced by the deterministic generator above.
- **Tooling.** `tools/guards.js` lost three rules that need files not in this extract: ADR citations, release tags and
  the architecture registry.

## Repository settings

`.github/workflows/run.yml` runs `npm ci --ignore-scripts && ./run.sh` on every push and pull request, with a read-only
token and actions pinned by full commit SHA. `.gitattributes` keeps every file LF and the PDFs byte-exact on Windows
checkouts (`core.autocrlf=true` otherwise rewrites 18 PDFs and breaks `run.sh`). Security reports: see `SECURITY.md`.

## Related

[qa-test-harness-template](https://github.com/A-D-P-W/qa-test-harness-template) is the public template for the same
project's test harness: one-command runner, CI and the lessons log.

The inflate code inside `PdfSafety.gs` is derived from [tiny-inflate](https://github.com/foliojs/tiny-inflate) 1.0.3
(MIT, © Devon Govett); its notice is kept in the file.

## License

Copyright © 2026 A-D-P-W. All rights reserved. You may view, clone and run this code to evaluate it; no other rights
are granted. The inflate code in `modules/PdfSafety/PdfSafety.gs` is MIT-licensed (notice in the file).
