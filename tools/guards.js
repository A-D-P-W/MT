#!/usr/bin/env node
// Module GUARDs (adapted from the source project's tools/guards.js). Prints one "GUARD ..." line per problem and exits
// 1 when there is any; exit 3 = AST parser (acorn) not installed (run `npm ci`).
//   (a) a module's source + the API sections of its CONTRACT.md must match the sha256 in the top row of its version
//       table; versions are unique and go up; a row already on main can never change.
//   (b) static AST check of each module: no free identifier that is a consumer's top-level name; other modules only
//       when listed under "Depends on" and Public there; Apps Script services only when listed in the contract;
//       no globalThis / eval / Function / top-level this; top-level = function declarations and const/let whose
//       initializer makes no call except a closed IIFE and new Set/Map; every top-level name is Public or Internal;
//       no top-level name declared twice in a project; a project bundles exactly the modules it uses.
//   (c) each consumer has tests/contract/<Module>.<consumer>.test.js that names every Public export the consumer's
//       code uses (a call or member access, read from the test's AST) and references no Internal helper.
// Dropped from the source version: the ADR citation rule, the release-tag rule and the ARCHITECTURE.md registry check
// (docs/ and release tags are not part of this extract).
// Usage: node tools/guards.js [--sha <Module>]   (GUARDS_ACORN = path of acorn, else ./node_modules/acorn)
'use strict';
const fs = require('fs'), path = require('path'), crypto = require('crypto'), cp = require('child_process');
const D = path.resolve(__dirname, '..');
const read = p => fs.readFileSync(path.join(D, p), 'utf8');
// GUARD (a) hash: the module source plus the contract sections a consumer relies on (review 1a: a guarantee could be
// deleted from CONTRACT.md without a version change). Version line, version table and the callers list are excluded.
const API_SECTIONS = ['Purpose', 'Public API', 'Internal', 'Safe composition', 'Guarantees', 'Open items', 'Never does', 'Errors', 'Host ctx members read', 'Apps Script services', 'Scopes the consumer must hold', 'Runtime / quota budget', 'Depends on'];
const section = (t, h) => { const r = new RegExp('^## ' + h.replace(/[/()]/g, '\\$&') + '[^\\n]*\\n([\\s\\S]*?)(?=^## |(?![\\s\\S]))', 'm').exec(t); return r ? r[1].trim() : ''; };
const modSha = m => { const gs = read(`modules/${m}/${m}.gs`).replace(/\r\n/g, '\n'), ct = fs.existsSync(path.join(D, `modules/${m}/CONTRACT.md`)) ? read(`modules/${m}/CONTRACT.md`).replace(/\r\n/g, '\n') : '';
  return crypto.createHash('sha256').update(gs + '\n---- contract ----\n' + API_SECTIONS.map(h => '## ' + h + '\n' + section(ct, h)).join('\n')).digest('hex'); };
if (process.argv[2] === '--sha') { console.log(modSha(process.argv[3])); process.exit(0); }   // needs no parser
let acorn;
try { acorn = require(process.env.GUARDS_ACORN || path.join(D, 'node_modules', 'acorn')); }
catch (e) { console.log('SKIP guards: acorn not installed (run npm ci)'); process.exit(3); }
const MODS = fs.existsSync(path.join(D, 'modules')) ? fs.readdirSync(path.join(D, 'modules')).filter(m => fs.existsSync(path.join(D, 'modules', m, m + '.gs'))).sort() : [];
// consumer → its own files, from project/*.files (every project list is a consumer)
let PLIST_ERR = null; const PLIST = (() => { try { return require(path.join(D, 'tools', 'projects.js')).projects(D); } catch (e) { PLIST_ERR = e.message; return []; } })();
const PROJECTS = Object.fromEntries(PLIST.map(p => [p.name, p.own]));
const SERVICES = ['GmailApp', 'Gmail', 'DriveApp', 'Drive', 'SpreadsheetApp', 'PropertiesService', 'LockService', 'ScriptApp', 'Utilities',
  'CacheService', 'CalendarApp', 'Calendar', 'UrlFetchApp', 'MailApp', 'Session', 'Logger', 'HtmlService', 'ContentService', 'Charts'];
const BUILTINS = new Set(('Array Object String Number Boolean Math Date JSON RegExp Error TypeError RangeError SyntaxError Set Map WeakMap WeakSet Symbol ' +
  'Promise Uint8Array Uint16Array Uint32Array Int8Array Int16Array Int32Array Float32Array Float64Array ArrayBuffer DataView BigInt ' +
  'parseInt parseFloat isNaN isFinite encodeURIComponent decodeURIComponent encodeURI decodeURI escape unescape undefined NaN Infinity ' +
  'Intl Proxy arguments console').split(' '));
const out = [];
if (PLIST_ERR) out.push('GUARD ' + PLIST_ERR);
const bad = m => out.push('GUARD ' + m);
const parseRaw = (file) => acorn.parse(read(file), { ecmaVersion: 'latest', sourceType: 'script', allowHashBang: false, locations: true });
const EMPTY = { type: 'Program', body: [] };
const parse = (file) => { try { return parseRaw(file); } catch (e) { bad(`${file} does not parse: ${e.message}`); return EMPTY; } };   // review 1a H1: never crash silently

// ---- scope walk: free identifiers of a node (references not bound by any enclosing scope inside the node)
const { freeIds, topNames } = require('./ast');   // 3.9.2: shared with tools/reachable.js

// ---- contracts
function contract(m) {
  const p = `modules/${m}/CONTRACT.md`; if (!fs.existsSync(path.join(D, p))) { bad(`modules/${m}: no CONTRACT.md`); return null; }
  const t = read(p), sec = h => { const r = new RegExp('^## ' + h + '[^\\n]*\\n([\\s\\S]*?)(?=^## |(?![\\s\\S]))', 'm').exec(t); return r ? r[1] : ''; };
  // Public = the names that START the first backtick span of a "- `...`" bullet, comma-separated, and look like exports
  // (trailing _ or ALL_CAPS) — never a name merely mentioned elsewhere (review 1a L1).
  const pub = new Set([...sec('Public API').matchAll(/^- `([^`]*)`/gm)].flatMap(x => x[1].split(',').map(y => (/^\s*([A-Za-z_$][\w$]*)/.exec(y) || [])[1]).filter(n => n && (/_$/.test(n) || /^[A-Z][A-Z0-9_]+$/.test(n)))));
  const internal = new Set([...sec('Internal').matchAll(/\b([A-Za-z_$][\w$]*_|[A-Z][A-Z0-9_]+)\b/g)].map(x => x[1]));
  const deps = sec('Depends on').trim().split(/[,\s]+/).filter(x => /^[A-Z]\w+$/.test(x));
  const services = sec('Apps Script services');
  const consumers = [];
  if (!/^## Consumers\s*$/m.test(t)) bad(`${p}: no "## Consumers" section`);
  for (const line of sec('Consumers').split('\n').filter(l => l.trim())) {
    if (!line.startsWith('- ')) { bad(`${p}: Consumers line is not "- <Project> — …": ${line.slice(0, 60)}`); continue; }         // review 1a M2: a malformed line must not drop a consumer
    const x = /^- (\w+) — (.+)$/.exec(line);
    if (!x) { bad(`${p}: Consumers line is not "- <Project> — <callers or planned …>": ${line.slice(0, 60)}`); continue; }
    if (!/^planned \(Phase \d\)(; keeps its own contract tests)?$/i.test(x[2])) consumers.push(x[1]); }
  const ver = (/^Version: (\d+\.\d+\.\d+)/m.exec(t) || [])[1];
  const rows = [...sec('Version history').matchAll(/^\| (\d+\.\d+\.\d+) \| ([0-9a-f]{64}) \| [^|]* \| ([^|]*) \|$/gm)].map(x => ({ v: x[1], sha: x[2], adr: x[3].trim() }));
  return { t, pub, internal, deps, services, consumers, ver, rows, p };
}
const C = {}; MODS.forEach(m => { C[m] = contract(m); });
const AST = {}; for (const m of MODS) { try { AST[m] = parse(`modules/${m}/${m}.gs`); } catch (e) { bad(`modules/${m}/${m}.gs does not parse: ${e.message}`); } }
const consumerTop = {}; for (const [proj, files] of Object.entries(PROJECTS)) consumerTop[proj] = new Set(files.flatMap(f => topNames(parse(f))));
const modTop = {}; for (const m of MODS) if (AST[m]) modTop[m] = new Set(topNames(AST[m]));
const owner = new Map(); for (const m of MODS) for (const n of (modTop[m] || [])) owner.set(n, m);
for (const m of MODS) if (C[m] && modTop[m]) C[m].internal = new Set([...C[m].internal].filter(n => modTop[m].has(n) && !C[m].pub.has(n)));   // prose in the Internal section may name public functions

// ---- (a)
const semverGt = (x, y) => { const a = x.split('.').map(Number), b = y.split('.').map(Number); for (let k = 0; k < 3; k++) if (a[k] !== b[k]) return a[k] > b[k]; return false; };
const gitShow = ref => { try { return cp.execSync(`git -C ${JSON.stringify(D)} show ${ref}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch (e) { return null; } };
for (const m of MODS) { const c = C[m]; if (!c) continue;
  const f = `modules/${m}/${m}.gs`, cur = modSha(m);
  if (!c.ver) { bad(`modules/${m}: CONTRACT.md has no "Version: X.Y.Z" line`); continue; }
  if (!c.rows.length) { bad(`modules/${m}: CONTRACT.md version table has no "| version | sha256 | change | origin |" row`); continue; }
  if (c.rows[0].v !== c.ver) bad(`modules/${m}: Version ${c.ver} is not the top row of the version table (${c.rows[0].v})`);
  if (c.rows[0].sha !== cur) bad(`modules/${m}: source or contract changed without a new version row (sha ${cur.slice(0, 12)}…; run node tools/guards.js --sha ${m})`);
  const onMain = gitShow(`origin/main:modules/${m}/CONTRACT.md`) ?? gitShow(`main:modules/${m}/CONTRACT.md`);       // review 1a M2: rows are immutable once on main
  if (onMain) for (const x of onMain.matchAll(/^\| (\d+\.\d+\.\d+) \| ([0-9a-f]{64}) \|/gm)) { const r = c.rows.find(y => y.v === x[1]);
    if (!r) bad(`modules/${m}: version ${x[1]} (on main) was removed from the version table`); else if (r.sha !== x[2]) bad(`modules/${m}: version ${x[1]} row changed after it reached main (bump the version instead)`); }
  const seen = new Set(); for (const r of c.rows) { if (seen.has(r.v)) bad(`modules/${m}: version ${r.v} appears twice`); seen.add(r.v); }
  for (let i = 1; i < c.rows.length; i++) if (!semverGt(c.rows[i - 1].v, c.rows[i].v)) bad(`modules/${m}: version rows must go up from bottom to top (${c.rows[i].v} then ${c.rows[i - 1].v})`); }

// ---- (b)
// Allowlist (review 1a L1/M2): returns '' when an initializer cannot run consumer code or read another file at load time.
function staticInit(n) {
  if (!n) return '';
  switch (n.type) {
    case 'Literal': return '';
    case 'TemplateLiteral': return n.expressions.length ? 'template with expressions' : '';
    case 'Identifier': return ['undefined', 'NaN', 'Infinity'].includes(n.name) ? '' : 'reads ' + n.name;
    case 'ArrayExpression': for (const e of n.elements) { if (!e) continue; if (e.type === 'SpreadElement') return 'spread'; const w = staticInit(e); if (w) return w; } return '';
    case 'ObjectExpression': for (const p of n.properties) { if (p.type !== 'Property' || p.computed || p.kind !== 'init') return 'computed/spread/getter property'; const w = p.method ? '' : staticInit(p.value); if (w) return w; } return '';
    case 'UnaryExpression': return n.operator === 'delete' ? 'delete' : staticInit(n.argument);
    case 'BinaryExpression': case 'LogicalExpression': return staticInit(n.left) || staticInit(n.right);
    case 'ConditionalExpression': return staticInit(n.test) || staticInit(n.consequent) || staticInit(n.alternate);
    case 'NewExpression': if (n.callee.type === 'Identifier' && (n.callee.name === 'Set' || n.callee.name === 'Map')) { for (const a of n.arguments) { const w = staticInit(a); if (w) return w; } return ''; } return 'new ' + (n.callee.name || n.callee.type);
    case 'FunctionExpression': case 'ArrowFunctionExpression': return '';
    case 'CallExpression': { const c = n.callee; if (/Function/.test(c.type) && n.arguments.length === 0 && [...freeIds(c).keys()].every(k => BUILTINS.has(k))) return ''; return 'call'; }
    default: return n.type;
  }
}
for (const m of MODS) { const prog = AST[m], c = C[m]; if (!prog || !c) continue;
  const where = `modules/${m}/${m}.gs`;
  for (const st of prog.body) {
    if (st.type === 'FunctionDeclaration') continue;
    if (st.type === 'VariableDeclaration' && st.kind !== 'var') { for (const d of st.declarations) {
        if (d.id.type !== 'Identifier') { bad(`${where}:${st.loc.start.line} top-level destructuring`); continue; }
        if (st.kind === 'let' && !c.t.includes('module-owned state')) bad(`${where}:${st.loc.start.line} top-level let ${d.id.name} (only listed module-owned state)`);
        const why = staticInit(d.init);
        if (why) bad(`${where}:${d.loc.start.line} top-level initializer of ${d.id.name} may run code or read other files at load time (${why}; allowed: literals, regex, arrays/objects of those, new Set/Map, function expressions, closed IIFE)`); } continue; }
    if (st.type === 'EmptyStatement') continue;
    bad(`${where}:${st.loc.start.line} top-level ${st.type} (modules declare functions and constants only)`);
  }
  const ctors = new Set(); (function c(n) { if (!n || typeof n.type !== 'string') return; if (n.type === 'NewExpression' && n.callee.type === 'Identifier') ctors.add(n.callee.name);
    for (const k of Object.keys(n)) { if (k === 'loc') continue; const v = n[k]; if (Array.isArray(v)) v.forEach(c); else if (v && typeof v.type === 'string') c(v); } })(prog);
  (function plain(n) { if (!n || typeof n.type !== 'string') return;                     // a constructor called without new would see the global this
    if (n.type === 'CallExpression' && n.callee.type === 'Identifier' && ctors.has(n.callee.name)) bad(`${where}:${n.loc.start.line} calls constructor ${n.callee.name} without new`);
    for (const k of Object.keys(n)) { if (k === 'loc') continue; const v = n[k]; if (Array.isArray(v)) v.forEach(plain); else if (v && typeof v.type === 'string') plain(v); } })(prog);
  let fnStack = [];                                                                       // `this` only inside a function the module calls with new
  (function scan(n) { if (!n || typeof n.type !== 'string') return;                     // review 1a L1: no this, no .constructor chains
    const isFn = n.type === 'FunctionDeclaration' || n.type === 'FunctionExpression';
    if (isFn) fnStack.push(n.id ? n.id.name : '');
    if (n.type === 'ThisExpression' && !(fnStack.length && ctors.has(fnStack[fnStack.length - 1]))) bad(`${where}:${n.loc.start.line} uses this outside a constructor`);
    if (n.type === 'MetaProperty') bad(`${where}:${n.loc.start.line} uses ${n.meta.name}.${n.property.name}`);
    if (n.type === 'MemberExpression' && !n.computed && n.property.name === 'constructor') bad(`${where}:${n.loc.start.line} uses .constructor`);
    if ((n.type === 'Literal' && typeof n.value === 'string' && /constr|uctor/.test(n.value)) || (n.type === 'TemplateElement' && /constr|uctor/.test(n.value.cooked || '')) ||
        (n.type === 'Property' && !n.computed && (n.key.name === 'constructor' || n.key.value === 'constructor'))) bad(`${where}:${n.loc.start.line} names "constructor" (reaches Function)`);
    if (n.type === 'Identifier' && n.name === 'Reflect') bad(`${where}:${n.loc.start.line} uses Reflect`);
    if (n.type === 'TaggedTemplateExpression' && !/Function/.test((n.tag || {}).type || '')) { /* inside functions only: checked by free identifiers */ }
    for (const k of Object.keys(n)) { if (k === 'loc') continue; const v = n[k]; if (Array.isArray(v)) v.forEach(scan); else if (v && typeof v.type === 'string') scan(v); }
    if (isFn) fnStack.pop(); })(prog);
  const free = freeIds(prog);
  for (const [n, line] of free) {
    if (BUILTINS.has(n)) continue;
    if (n === 'this') continue;                                                          // reported by the scan above
    if (n === 'globalThis' || n === 'eval' || n === 'Function') { bad(`${where}:${line} uses ${n}`); continue; }
    if (SERVICES.includes(n)) { if (!new RegExp('\\b' + n + '\\b').test(c.services)) bad(`${where}:${line} uses Apps Script service ${n}, not listed in its contract`); continue; }
    const own = owner.get(n);
    if (own && own !== m) { if (!c.deps.includes(own)) bad(`${where}:${line} uses ${own}.${n} but "Depends on" does not list ${own}`);
      else if (C[own] && !C[own].pub.has(n)) bad(`${where}:${line} uses ${own}.${n}, which is not Public in ${own}'s contract`); continue; }
    for (const [proj, names] of Object.entries(consumerTop)) if (names.has(n)) { bad(`${where}:${line} uses ${proj} global ${n} (pass it as an argument)`); break; }
    if (!own && !Object.values(consumerTop).some(s => s.has(n))) bad(`${where}:${line} free identifier ${n} is not a built-in, service or module name`);
  }
  for (const n of modTop[m]) if (!c.pub.has(n) && !c.internal.has(n)) bad(`${where}: top-level ${n} is neither Public nor Internal in CONTRACT.md`);
}
for (const [proj, files] of Object.entries(PROJECTS)) {
  const seen = new Map(); const add = (n, where) => { if (seen.has(n)) bad(`${proj}: top-level ${n} declared in ${seen.get(n)} and ${where}`); else seen.set(n, where); };
  const pl = PLIST.find(p => p.name === proj);
  for (const m of (pl ? pl.modules : MODS)) for (const n of (modTop[m] || [])) add(n, `modules/${m}`);
  for (const f of files) for (const n of topNames(parse(f))) add(n, f);
}
// 3.9.2: a project bundles exactly the modules it uses plus their Depends-on closure (an unlisted used module fails live
// with a ReferenceError; an unused one adds code and services the project never asked for).
for (const p of PLIST) {
  const used = new Set(); for (const f of p.own) for (const [n] of freeIds(parse(f))) if (owner.has(n)) used.add(owner.get(n));
  const need = new Set(); const addDeps = m => { if (need.has(m)) return; need.add(m); for (const d of (C[m] ? C[m].deps : [])) addDeps(d); }; used.forEach(addDeps);
  for (const m of need) if (!p.modules.includes(m)) bad(`${p.list}: ${p.name} uses ${m} (directly or as a dependency) but does not bundle it`);
  for (const m of p.modules) if (!need.has(m)) bad(`${p.list}: bundles ${m}, which ${p.name} does not use`);
}

// ---- (c)
// Consumers come from actual use as well as from the contract (re-review: a renamed header, a '*' bullet or a 'planned'
// note could empty the list): any project whose code uses a name the module owns is a consumer and needs a test.
for (const [proj, files] of Object.entries(PROJECTS)) { const used = new Set(); for (const f of files) for (const [n] of freeIds(parse(f))) if (owner.has(n)) used.add(owner.get(n));
  for (const m of used) if (C[m] && !C[m].consumers.includes(proj)) { bad(`modules/${m}: ${proj} uses it but its contract does not list ${proj} as a consumer`); C[m].consumers.push(proj); } }
for (const m of MODS) { const c = C[m]; if (!c) continue;
  for (const cons of c.consumers) {
    const tf = `tests/contract/${m}.${cons.toLowerCase()}.test.js`;
    if (!fs.existsSync(path.join(D, tf))) { bad(`modules/${m}: consumer ${cons} has no ${tf}`); continue; }
    // review 1a M2/M4: read the test's AST — a name in a comment or in the load() list does not count; any reference to
    // an Internal helper (identifier, member, string) fails.
    const tast = parse(tf), exercised = new Set(), mentioned = new Set();
    (function scan(n, parent) { if (!n || typeof n.type !== 'string') return;
      if (n.type === 'MemberExpression') { const nm = n.computed ? (n.property.type === 'Literal' ? String(n.property.value) : null) : n.property.name; if (nm) { exercised.add(nm); mentioned.add(nm); } }
      if (n.type === 'CallExpression' && n.callee.type === 'Identifier') exercised.add(n.callee.name);
      if (n.type === 'Identifier') mentioned.add(n.name);
      if (n.type === 'Literal' && typeof n.value === 'string') mentioned.add(n.value);
      if (n.type === 'TemplateLiteral' && !n.expressions.length) mentioned.add(n.quasis.map(q => q.value.cooked).join(''));
      if (n.type === 'MemberExpression' && n.computed && n.property.type === 'TemplateLiteral' && !n.property.expressions.length) { const nm = n.property.quasis[0].value.cooked; exercised.add(nm); mentioned.add(nm); }
      for (const k of Object.keys(n)) { if (k === 'loc') continue; const v = n[k]; if (Array.isArray(v)) v.forEach(x => scan(x, n)); else if (v && typeof v.type === 'string') scan(v, n); } })(tast, null);
    if (PROJECTS[cons]) { const used = new Set(); for (const f of PROJECTS[cons]) for (const [n] of freeIds(parse(f))) if (c.pub.has(n) && owner.get(n) === m) used.add(n);
      for (const n of used) if (!exercised.has(n)) bad(`${tf}: ${cons} uses ${m}.${n} but its contract test never exercises it (call or member access)`); }
    for (const n of c.internal) if (mentioned.has(n)) bad(`${tf}: references Internal helper ${n}`);
  } }
out.forEach(l => console.log(l));
console.log(out.length ? `${out.length} module guard problem(s)` : `OK module guards: ${MODS.length} modules`);
process.exit(out.length ? 1 : 0);
