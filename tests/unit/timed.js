// Linear-time measurement in a child process with a hard time limit, so a super-linear (ReDoS) regression FAILs with a
// message instead of hanging the suite (ablation 2026-11-11: changing HtmlText's tag regex to [^>]* hung both linear-
// time suites until the runner's per-suite timeout, and no check said what broke).
// measure(moduleFile, expr, unit, smallLen, bigLen, limitMs) → { ts, tb } (best of 3 ms each, pair retried up to 3 times)
//                                                          or { timeout: true } / { error }
'use strict';
const cp = require('child_process');
const CHILD = `
const fs = require('fs'); const [file, expr, unitJson, smallLen, bigLen] = process.argv.slice(1);
const run = new Function('Logger', fs.readFileSync(file, 'utf8') + ';return s => (' + expr + ');')({ log() {} });
const unit = JSON.parse(unitJson), mk = n => unit.repeat(Math.ceil(n / unit.length));
const big = mk(+bigLen), small = mk(+smallLen);
const time = s => { const t = process.hrtime.bigint(); run(s); return Number(process.hrtime.bigint() - t) / 1e6; };
const best = s => Math.min(time(s), time(s), time(s));
let ts, tb; for (let k = 0; k < 3; k++) { ts = best(small); tb = best(big); if (tb < 10 * Math.max(ts, 15)) break; }
process.stdout.write(JSON.stringify({ ts: Math.round(ts), tb: Math.round(tb) }));`;
function measure(file, expr, unit, smallLen, bigLen, limitMs) {
  const r = cp.spawnSync(process.execPath, ['-e', CHILD, file, expr, JSON.stringify(unit), String(smallLen), String(bigLen)],
    { encoding: 'utf8', timeout: limitMs, killSignal: 'SIGKILL', maxBuffer: 1 << 20 });
  if (r.error && r.error.code === 'ETIMEDOUT' || r.signal === 'SIGKILL') return { timeout: true };
  try { return JSON.parse(r.stdout); } catch (e) { return { error: (r.stderr || String(r.error || 'no output')).slice(0, 200) }; }
}
module.exports = { measure };
