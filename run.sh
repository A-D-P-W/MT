#!/usr/bin/env bash
# Runs every suite and prints one VERDICT line (exit 0 = PASS, 1 = FAIL).
#   ./run.sh                  all suites: behavioral tests + hygiene + module GUARDs + guard self-test
#   SUITES=behavior ./run.sh  behavioral tests only (what tools/ablation.js runs on each mutated copy)
#   SUITE_TIMEOUT=<s>         per-suite time limit (default 300 s); a suite that runs out of time is a FAIL (TIMEOUT)
# A suite FAILs when it exits non-zero, prints a FAIL line, prints no PASS line at all, or times out.
# Needs: node >= 18; `npm ci` once for acorn (the GUARDs' parser). Writes out/ (per-suite logs).
set -u
cd "$(dirname "$0")"
SUITES=${SUITES:-all}; T=${SUITE_TIMEOUT:-300}
rm -rf out; mkdir -p out
BEHAVIOR=(tests/contract/HtmlText.example.test.js tests/contract/PdfSafety.example.test.js tests/contract/SecurityNames.example.test.js
          tests/contract/SenderTrust.example.test.js tests/unit/html_linear.test.js tests/unit/auth_headers.test.js
          tests/corpus.test.js tests/scan_corpus.test.js)
STRUCTURE=(tests/hygiene.test.js tools/guards.js tools/guard_selftest.js)
LIST=("${BEHAVIOR[@]}"); [ "$SUITES" = behavior ] || LIST+=("${STRUCTURE[@]}")
bad=0; total_pass=0; total_fail=0
printf '%-44s %6s %6s  %s\n' SUITE PASS FAIL RESULT
for f in "${LIST[@]}"; do
  name=$(basename "$f" .js); log="out/$name.txt"
  timeout --kill-after=5 "$T" node "$f" > "$log" 2>&1; rc=$?
  p=$(grep -c '^PASS ' "$log"); x=$(grep -c '^FAIL ' "$log")
  if [ "$f" = tools/guards.js ]; then grep -q '^OK module guards' "$log" && p=1; x=$(grep -c '^GUARD ' "$log"); fi
  res=ok
  if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then res="FAIL (TIMEOUT after ${T}s)"
  elif [ $rc -eq 3 ]; then res="FAIL (SKIPPED: acorn not installed, run npm ci)"
  elif [ $rc -ne 0 ] || [ "$x" -gt 0 ]; then res="FAIL (exit $rc)"
  elif [ "$p" -eq 0 ]; then res="FAIL (passed nothing)"; fi
  [ "$res" = ok ] || bad=$((bad + 1))
  total_pass=$((total_pass + p)); total_fail=$((total_fail + x))
  printf '%-44s %6s %6s  %s\n' "$f" "$p" "$x" "$res"
  [ "$res" = ok ] || grep -E '^(FAIL|GUARD) ' "$log" | head -5 | sed 's/^/    /'
done
grep -h '^PASS KNOWN-OPEN' out/*.txt 2>/dev/null | sed 's/^PASS /NOTICE /'
# every test file in the repo must be in one of the lists above (a test that never runs proves nothing)
if [ "$SUITES" = all ]; then
  while IFS= read -r t; do
    case " ${BEHAVIOR[*]} ${STRUCTURE[*]} " in *" $t "*) ;; *) echo "FAIL unrun test file: $t"; bad=$((bad + 1));; esac
  done < <(find tests -name '*.test.js' | sort)
fi
if [ $bad -eq 0 ]; then echo "VERDICT: PASS - ${#LIST[@]} suites, $total_pass checks passed, 0 failed"; exit 0
else echo "VERDICT: FAIL - $bad of ${#LIST[@]} suite(s) failed ($total_pass checks passed, $total_fail failed)"; exit 1; fi
