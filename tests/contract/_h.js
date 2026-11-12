// Shared PASS/FAIL printer for contract tests (same line format as the other suites).
let pass = 0, fail = 0;
module.exports = {
  ok(c, m, extra = '') { c ? pass++ : fail++; console.log((c ? 'PASS ' : 'FAIL ') + m + (c || !extra ? '' : '  -- ' + extra)); },
  done() { console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0); },
};
