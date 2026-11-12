// AST helpers for tools/guards.js (copied unchanged from the source project, apart from this line).
// freeIds(node) → Map(name → first line) of identifiers not bound inside node; topNames(program) → top-level names.
'use strict';
function freeIds(root) {
  const free = new Map();                                   // name → first line
  const scopes = [];
  const bind = (pat, sc) => { if (!pat) return; switch (pat.type) {
    case 'Identifier': sc.add(pat.name); break;
    case 'ObjectPattern': pat.properties.forEach(p => bind(p.type === 'RestElement' ? p.argument : p.value, sc)); break;
    case 'ArrayPattern': pat.elements.forEach(e => bind(e, sc)); break;
    case 'RestElement': bind(pat.argument, sc); break;
    case 'AssignmentPattern': bind(pat.left, sc); break; } };
  const hoistVars = (node, sc) => {                          // var + function declarations hoist to the function scope
    const visit = n => { if (!n || typeof n.type !== 'string') return;
      if (n.type === 'VariableDeclaration' && n.kind === 'var') n.declarations.forEach(d => bind(d.id, sc));
      if (n.type === 'FunctionDeclaration') { if (n.id) sc.add(n.id.name); return; }
      if (/Function/.test(n.type) || n.type === 'ClassExpression') return;
      for (const k of Object.keys(n)) { const v = n[k]; if (k === 'loc') continue; if (Array.isArray(v)) v.forEach(visit); else if (v && typeof v.type === 'string') visit(v); } };
    visit(node); };
  const blockDecls = (stmts, sc) => stmts.forEach(s => {
    if (s.type === 'VariableDeclaration' && s.kind !== 'var') s.declarations.forEach(d => bind(d.id, sc));
    if (s.type === 'ClassDeclaration' && s.id) sc.add(s.id.name);
    if (s.type === 'FunctionDeclaration' && s.id) sc.add(s.id.name); });
  const isBound = n => scopes.some(s => s.has(n));
  const ref = (id) => { if (!isBound(id.name) && !free.has(id.name)) free.set(id.name, id.loc.start.line); };
  const walk = (n, parent, key) => {
    if (!n || typeof n.type !== 'string') return;
    switch (n.type) {
      case 'Identifier': ref(n); return;
      case 'ThisExpression': if (!scopes.some(s => s.fn)) free.set('this', n.loc.start.line); return;
      case 'MemberExpression': walk(n.object); if (n.computed) walk(n.property); return;
      case 'Property': if (n.computed) walk(n.key); if (n.shorthand) walk(n.value); else walk(n.value); return;
      case 'MethodDefinition': case 'PropertyDefinition': if (n.computed) walk(n.key); walk(n.value); return;
      case 'LabeledStatement': walk(n.body); return;
      case 'BreakStatement': case 'ContinueStatement': return;
      case 'FunctionDeclaration': case 'FunctionExpression': case 'ArrowFunctionExpression': {
        const sc = new Set(); sc.fn = n.type !== 'ArrowFunctionExpression';
        if (n.type === 'FunctionExpression' && n.id) sc.add(n.id.name);
        n.params.forEach(p => bind(p, sc)); scopes.push(sc);
        n.params.forEach(p => walkPattern(p));
        if (n.body.type === 'BlockStatement') { hoistVars(n.body, sc); blockDecls(n.body.body, sc); n.body.body.forEach(s => walk(s)); }
        else walk(n.body);
        scopes.pop(); return; }
      case 'ClassDeclaration': case 'ClassExpression': walk(n.superClass); n.body.body.forEach(b => walk(b)); return;
      case 'BlockStatement': case 'StaticBlock': { const sc = new Set(); blockDecls(n.body, sc); scopes.push(sc); n.body.forEach(s => walk(s)); scopes.pop(); return; }
      case 'ForStatement': case 'ForInStatement': case 'ForOfStatement': { const sc = new Set(); const init = n.init || n.left;
        if (init && init.type === 'VariableDeclaration' && init.kind !== 'var') init.declarations.forEach(d => bind(d.id, sc));
        scopes.push(sc); for (const k of ['init', 'left', 'test', 'update', 'right', 'body']) walk(n[k]); scopes.pop(); return; }
      case 'CatchClause': { const sc = new Set(); bind(n.param, sc); scopes.push(sc); walkPattern(n.param); walk(n.body); scopes.pop(); return; }
      case 'VariableDeclaration': n.declarations.forEach(d => { walkPattern(d.id); walk(d.init); }); return;
      case 'SwitchStatement': { walk(n.discriminant); const sc = new Set(); n.cases.forEach(c => blockDecls(c.consequent, sc)); scopes.push(sc);
        n.cases.forEach(c => { walk(c.test); c.consequent.forEach(s => walk(s)); }); scopes.pop(); return; }
    }
    for (const k of Object.keys(n)) { if (k === 'loc' || k === 'type' || k === 'start' || k === 'end') continue; const v = n[k];
      if (Array.isArray(v)) v.forEach(x => walk(x)); else if (v && typeof v.type === 'string') walk(v); }
  };
  const walkPattern = p => { if (!p) return; if (p.type === 'AssignmentPattern') { walkPattern(p.left); walk(p.right); }
    else if (p.type === 'ObjectPattern') p.properties.forEach(q => { if (q.type === 'RestElement') return; if (q.computed) walk(q.key); walkPattern(q.value); });
    else if (p.type === 'ArrayPattern') p.elements.forEach(walkPattern); };
  const top = new Set(); top.fn = false;
  if (root.type === 'Program') { hoistVars(root, top); blockDecls(root.body, top); scopes.push(top); root.body.forEach(s => walk(s)); }
  else { scopes.push(top); walk(root); }
  return free;
}
const topNames = prog => { const s = []; for (const st of prog.body) {
  if (st.type === 'FunctionDeclaration') s.push(st.id.name);
  else if (st.type === 'VariableDeclaration') st.declarations.forEach(d => d.id.type === 'Identifier' && s.push(d.id.name)); } return s; };

module.exports = { freeIds, topNames };
