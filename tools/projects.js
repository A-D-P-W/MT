// Project registry. A consumer project has one list file project/<name>.files:
//   # @project <ProjectName>     the consumer name used in CONTRACT.md "Consumers" and tests/contract/<Module>.<name>.test.js
//   modules/<Name>/<Name>.gs ... the modules the project uses plus their Depends-on modules, in registry order
//   example/<File>.gs            the project's own file(s), last
// project/modules.order is the registry order of every module (one source of truth for the contract-test loader).
// The source project has three consumers (three Apps Script projects); this extract has one, Example.
'use strict';
const fs = require('fs'), path = require('path');
const lines = f => fs.readFileSync(f, 'utf8').split('\n').map(l => l.trim());
function moduleOrder(root) {
  const f = path.join(root, 'project', 'modules.order');
  return fs.existsSync(f) ? lines(f).filter(l => l && !l.startsWith('#')) : [];
}
function projects(root) {
  const dir = path.join(root, 'project');
  const res = (fs.existsSync(dir) ? fs.readdirSync(dir) : []).filter(f => f.endsWith('.files')).sort().map(f => {
    const all = lines(path.join(dir, f)), list = 'project/' + f;
    const x = all.map(l => /^#\s*@project\s+(\S+)\s*$/.exec(l)).filter(Boolean);
    if (x.length !== 1) throw new Error(list + ': needs exactly one "# @project <Name>" line');
    const name = x[0][1];
    if (!/^[A-Z][A-Za-z]+$/.test(name)) throw new Error(list + ': @project ' + name + ' is not a plain CamelCase name');
    const files = all.filter(l => l && !l.startsWith('#'));
    const modules = files.filter(l => l.startsWith('modules/')).map(l => l.split('/')[1]);
    const own = files.filter(l => !l.startsWith('modules/'));
    if (!own.length) throw new Error(list + ': lists no project file');
    for (const o of own) if (!fs.existsSync(path.join(root, o))) throw new Error(list + ': ' + o + ' does not exist');
    return { name, lname: name.toLowerCase(), list, files, modules, own };
  });
  const seen = new Map(); for (const p of res) { if (seen.has(p.lname)) throw new Error(p.list + ': @project ' + p.name + ' is also used by ' + seen.get(p.lname)); seen.set(p.lname, p.list); }
  return res;
}
module.exports = { projects, moduleOrder };
