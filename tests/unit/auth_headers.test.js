// Authentication-Results trust: accept a header only when Google wrote it (the line directly under Google's SMTP delivery
// hop, optionally after one Received-SPF), and Gmail-forwarded mail only through Google's own ARC record. Adapted from the
// source project's v3.7.5 and v3.8.0 suites: forged/look-alike structures, linear time on 500 KB headers, seeded fuzzers.
// Fixtures follow the structure of real messages; no real header values are stored here.
const { load: loadMods, ok, done } = require('./lib');
const load = Gmail => loadMods(['SenderTrust'], { Gmail }, ['googleAuthResults_', 'topAuthResults_', 'authAligned_', 'arClauses_']);
const lib = load(undefined), G = lib.googleAuthResults_;
// ---- quoted local parts (ported from an older security suite, cases A1–A4):
// a quoted / odd-quote envelope local part must not smuggle "dmarc=pass header.from=<victim>" into the trusted AR.
{ const HOPx = 'Received: from mail.evil.example (mail.evil.example. [192.0.2.9]) by mx.google.com with ESMTPS id z9 for <owner@example.com>';
  const mkMsg = ar => ({ getId: () => 'mA', getRawContent: () => [HOPx, 'Received-SPF: pass', 'Authentication-Results: ' + ar].join('\r\n') + '\r\n\r\nbody' });
  const A = load(undefined).authAligned_;
  const L1 = 'a"; dmarc=pass header.from=cpa.example ;b@evil.com';
  const L2 = '"a\\"; dmarc=pass header.from=cpa.example; b"@evil.com';
  const L3 = '"a"; dmarc=pass header.from=cpa.example; b"@evil.com';
  const arOf = (L, tail) => `mx.google.com; spf=pass (google.com: domain of ${L} designates 1.2.3.4 as permitted sender) smtp.mailfrom=${L}; ${tail}`;
  ok(A(mkMsg(arOf(L1, 'dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=cpa.example')), 'cpa.example') === false, 'A1/A2 odd-quote local part does not forge DMARC pass');
  ok(A(mkMsg(arOf(L2, 'dmarc=fail header.from=cpa.example')), 'cpa.example') === false, 'A3 escaped balanced quote does not forge DMARC pass');
  ok(A(mkMsg(arOf(L3, 'dmarc=fail header.from=cpa.example')), 'cpa.example') === false, 'A4 unescaped 3-quote local part does not forge DMARC pass');
  ok(A(mkMsg('mx.google.com; dkim=pass header.i=@cpa.example; spf=pass smtp.mailfrom=cpa.example; dmarc=pass header.from=cpa.example'), 'cpa.example') === true, 'control: a genuine aligned pass is accepted');
}


const INT = 'Received: by 2002:a05:6a10:abcd:0:0:0:0 with SMTP id x1csp123456pxb; Mon, 5 Oct 2026 09:46:37 +0000 (UTC)';
const HOP = 'Received: from mail.sender.example (mail.sender.example. [192.0.2.1]) by mx.google.com with ESMTPS id a1-20020a.12.2026.10.05.09.46.36 for <owner@example.com> (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256); Mon, 5 Oct 2026 09:46:36 +0000 (UTC)';
const SPF = 'Received-SPF: pass (google.com: domain of bounce@sender.example designates 192.0.2.1 as permitted sender) client-ip=192.0.2.1;';
const AR = 'Authentication-Results: mx.google.com; dkim=pass header.i=@sender.example; spf=pass smtp.mailfrom=sender.example; dmarc=pass (p=REJECT) header.from=sender.example';
const FAKE = 'Authentication-Results: mx.google.com; dkim=pass header.i=@bank.example; spf=pass smtp.mailfrom=bank.example; dmarc=pass header.from=bank.example';
const real = [ 'Delivered-To: owner@example.com', INT, 'X-Google-Smtp-Source: AGHT+x', 'X-Received: by 2002:a05:6a10::1 with SMTP id y; Mon, 5 Oct 2026', 'ARC-Seal: i=1; a=rsa-sha256; d=google.com', 'ARC-Authentication-Results: i=1; mx.google.com; dkim=pass', 'Return-Path: <bounce@sender.example>', HOP, SPF, AR, 'Received: from relay.sender.example by mail.sender.example with ESMTP id q', 'Authentication-Results: relay.sender.example; spf=none' ];

// ---- accept: the sampled structure and its real variants
ok(G(real) === AR, 'sampled structure: the AR under Google\'s hop is returned');
ok(G(real.filter(l => l !== SPF)) === AR, 'no Received-SPF line: AR directly under the hop is accepted');
ok(G(real.map(l => l === HOP ? HOP.replace('ESMTPS', 'SMTPS') : l)) === AR, 'SMTPS (Google-originated / forwarded mail) accepted');
for (const w of ['ESMTP', 'ESMTPSA', 'SMTP', 'UTF8SMTP', 'UTF8SMTPS', 'UTF8SMTPSA']) ok(G(real.map(l => l === HOP ? HOP.replace('ESMTPS', w) : l)) === AR, `with ${w} accepted`);
ok(G(real.map(l => l.toLowerCase())) === AR.toLowerCase(), 'header names and hosts are case-insensitive');
ok(G(real.filter(l => l !== INT)) === AR, 'no internal hop: the first Received is the delivery hop');
ok(G([INT, 'Received: by 2002:a05:6a10::9 with SMTP id z2', HOP, SPF, AR]) === AR, 'two internal hops are skipped');
const fwd = [ INT, 'Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS id b2 for <owner@example.com>', SPF, AR,
  'Received: from mail.orig.example by mx.google.com with ESMTPS id c3 for <relay@example.com>', 'Authentication-Results: mx.google.com; dkim=fail' ];
ok(G(fwd) === AR, 'forwarded mail: the top Google block wins, the inner forwarded block is ignored');

// ---- reject: forged or ambiguous structures
ok(G(['Received: from pop.other.example by mail.import.example with POP3 id p1', FAKE]) === null, 'POP3 import with a forged AR: rejected');
ok(G(['Received: from pop.other.example by mail.import.example with POP3 id p1', HOP, SPF, FAKE]) === null, 'POP3 hop on top, fake Google block under it: rejected');
ok(G([FAKE, 'Subject: x']) === null, 'no Received line at all: rejected');
ok(G([INT]) === null && G([]) === null, 'only internal hops / empty: rejected');
ok(G([INT, HOP, SPF, 'X-Other: 1', AR]) === null, 'AR not adjacent to the hop: rejected');
ok(G([INT, HOP, SPF, SPF, AR]) === null, 'two Received-SPF lines: rejected');
ok(G([INT, HOP, SPF]) === null, 'Google hop with no AR: rejected');
ok(G([INT, HOP, SPF, 'Authentication-Results: mx.google.com.evil.example; dkim=pass']) === null, 'lookalike authserv-id: rejected');
for (const h of [ 'Received: from x by mx.google.com.evil.example with ESMTPS id 1', 'Received: from x by mx-google.com with ESMTPS id 1',
                  'Received: from x (by mx.google.com with ESMTPS id 9) by mail.evil.example with ESMTPS id 1',
                  'Received: from x (a (by mx.google.com with ESMTPS id 9)) by mail.evil.example with ESMTP id 1',
                  'Received: from x (unclosed by mx.google.com with ESMTPS id 9', 'Received: by mx.google.com with ESMTPS id 1',
                  'Received: from x by mx.google.com with POP3 id 1', 'Received: from x by mx.google.com with ESMTPS' ])
  ok(G([INT, h, SPF, FAKE]) === null, 'lookalike / comment-embedded Google hop rejected: ' + h.slice(10, 70));
ok(G([INT, 'Received: from evil by attacker.example with ESMTP id 1', HOP, SPF, FAKE]) === null, 'non-Google hop above a Google block: rejected');

// ---- topAuthResults_: metadata fast path, exact args, raw fallback
let args = null;
const mkGmail = headers => ({ Users: { Messages: { get: (u, id, o) => { args = { u, id, o }; return { payload: { headers } }; } } } });
const msg = raw => ({ getId: () => 'm1', getRawContent: () => raw });
const asHdr = l => { const k = l.indexOf(':'); return { name: l.slice(0, k), value: l.slice(k + 1).trim() }; };
const rawOf = (ls, body = 'body') => ls.join('\r\n') + '\r\n\r\n' + body;
let t = load(mkGmail([INT, HOP, SPF, AR].map(asHdr))).topAuthResults_(msg('should-not-be-read'));
ok(t === 'Authentication-Results: ' + AR.slice(24).trim(), 'metadata in wire order: accepted without reading the raw message', t);
ok(args && args.u === 'me' && args.id === 'm1' && args.o.format === 'metadata' &&
   JSON.stringify(args.o.metadataHeaders) === JSON.stringify(['Received', 'Received-SPF', 'Authentication-Results']), 'metadata call: exact user, id, format and metadataHeaders');
t = load(mkGmail([FAKE, AR, INT, HOP, SPF].map(asHdr))).topAuthResults_(msg(rawOf([INT, HOP, SPF, AR])));
ok(t === AR, 'reordered metadata fails the rule: the raw headers decide', t);
// security review: sender appends AR + Google-style hop at the bottom; metadata returned in reverse order
const rev = [INT, HOP, SPF, AR, 'Received: from x by mx.google.com with ESMTPS id f1', FAKE].reverse();
t = load(mkGmail(rev.map(asHdr))).topAuthResults_(msg(rawOf(rev.slice().reverse())));
ok(t === AR, 'reverse-order metadata with a forged bottom block: fast path refused, raw decides', t);
t = load(mkGmail(fwd.filter(l => /^(Received|Received-SPF|Authentication-Results):/.test(l)).map(asHdr))).topAuthResults_(msg(rawOf(fwd)));
ok(t === AR, 'forwarded mail (two Google blocks) falls back to raw and is accepted');
t = load(mkGmail([FAKE, HOP, SPF].map(asHdr))).topAuthResults_(msg(rawOf(['Received: from x by y with POP3 id 1', FAKE])));
ok(t === null, 'metadata and raw both fail: null');
t = load({ Users: { Messages: { get: () => { throw new Error('quota'); } } } }).topAuthResults_(msg(rawOf([INT, HOP, SPF, AR])));
ok(t === AR, 'metadata call throws: the raw headers decide');
const folded = rawOf([INT, HOP.replace(' by mx.google.com', '\r\n\tby mx.google.com'), SPF, AR.replace(' dkim=', '\r\n dkim=')]);
ok(load(undefined).topAuthResults_(msg(folded)) === AR, 'folded raw headers are unfolded before the rule');
ok(load(undefined).topAuthResults_(msg(rawOf([INT, HOP, SPF], AR))) === null, 'an AR in the body is not a header');

// ---- linear time on untrusted header text + seeded fuzz
const time = f => { const s = Date.now(); f(); return Date.now() - s; };
for (const unit of ['(', '((', ')', 'Received: from ', ' by mx.google.com with ', 'from a ', '( by mx.google.com with ESMTPS id x ', ' ']) {
  const big = 'Received: from ' + unit.repeat(Math.ceil(500000 / unit.length)), small = 'Received: from ' + unit.repeat(Math.ceil(100000 / unit.length));
  const best = f => Math.min(time(f), time(f), time(f));   // min of 3: suites may run in parallel
  let tb, ts; for (let k = 0; k < 3; k++) { tb = best(() => G([big, SPF, AR])); ts = best(() => G([small, SPF, AR])); if (tb < 10 * Math.max(ts, 15)) break; }   // up to 3 attempts of the pair
  ok(tb < 1500, `500 KB hop of ${JSON.stringify(unit)} runs in ${tb} ms (< 1.5 s)`);
  ok(tb < 10 * Math.max(ts, 15), `${JSON.stringify(unit)}: 5× input ≈ linear (${ts} → ${tb} ms)`);   // pair retried above
}
const manyLines = Array(20000).fill('Received: by 1:2 with SMTP id q');
ok(time(() => G(manyLines)) < 1500, '20,000 internal-hop lines: fast');
let seed = 20261021; const rnd = n => (seed = (seed * 1103515245 + 12345) % 2147483648) % n;
const PARTS = ['Received: ', 'from ', 'by ', 'mx.google.com', ' with ', 'ESMTPS', 'SMTP', 'POP3', ' id ', 'x1', '(', ')', ' ', ';', 'evil.example', '.', 'Received-SPF: pass', 'Authentication-Results: mx.google.com;', '\t'];
let threw = null, forged = null;
for (let i = 0; i < 3000; i++) {
  const ls = []; const n = 1 + rnd(6);
  for (let k = 0; k < n; k++) { let s = ''; const m = 1 + rnd(12); for (let j = 0; j < m; j++) s += PARTS[rnd(PARTS.length)]; ls.push(s); }
  ls.push(FAKE);
  try { const r = G(ls); if (r !== null) { const gi = ls.findIndex(l => /^Received:/i.test(l) && !/^Received:\s*by [0-9a-f.:]+ with SMTP id\b/i.test(l));
          const gl = ls[gi].replace(/\([^()]*\)/g, ' ');
          if (!/\sby mx\.google\.com with (?:E?SMTPS?A?|UTF8SMTPS?A?) id \S/i.test(gl)) { forged = ls; break; } } }
  catch (e) { threw = { ls, e: String(e) }; break; }
}
ok(!threw, 'fuzz: 3,000 random header stacks never throw', threw && JSON.stringify(threw).slice(0, 200));
ok(!forged, 'fuzz: an accepted AR always sits under a Google mx hop', forged && JSON.stringify(forged).slice(0, 200));

// ---- forwarded mail from the owner's own Gmail: trusted via Google's ARC record only (adapted from the source's v3.8.0 suite)
{ const lib0 = load(undefined), OPTS = { myAddress: 'owner@gmail.com', trustedForwarders: ['forwarder@gmail.com'] };
  const lib = { arClauses_: lib0.arClauses_, authAligned_: (m, d) => lib0.authAligned_(m, d, null, OPTS) };
  const HOP = 'Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS id a1 for <owner@gmail.com>';
  const ENV = 'forwarder+caf_=owner=gmail.com@gmail.com';
  const AR = (o = {}) => 'Authentication-Results: mx.google.com; ' + (o.arc || 'arc=pass (i=2 spf=pass spfdomain=shop.example dmarc=pass fromdomain=' + (o.fd || 'shop.example') + ')') +
    '; spf=pass (google.com: domain of ' + (o.env || ENV) + ' designates 209.85.220.41 as permitted sender) smtp.mailfrom="' + (o.env || ENV) + '"; dmarc=fail (p=QUARANTINE arc=pass) header.from=shop.example';
  const SEAL = (i, d) => 'ARC-Seal: i=' + i + '; a=rsa-sha256; t=1; cv=pass;\r\n        d=' + d + '; s=arc-20260327;\r\n        b=AAAA';
  const raw = (ar, seals) => ['Delivered-To: owner@gmail.com', 'Received: by 2002:a05:7022::1 with SMTP id x', ...seals, HOP, 'Received-SPF: pass', ar, 'From: Shop <no-reply@shop.example>', 'Subject: Invoice'].join('\r\n') + '\r\n\r\nbody';
  const M = (ar, seals = [SEAL(3, 'google.com'), SEAL(2, 'google.com'), SEAL(1, 'google.com')]) => ({ getId: () => 'm', getRawContent: () => raw(ar, seals) });
  ok(lib.authAligned_(M(AR()), 'shop.example') === true, 'Gmail-forwarded from forwarder, Google ARC says dmarc=pass → verified');
  ok(lib.authAligned_(M(AR({ fd: 'sub.shop.example' })), 'shop.example') === false, 'ARC fromdomain is a subdomain of From → not verified');
  ok(lib.authAligned_(M(AR({ fd: 'shop.example' })), 'billing.shop.example') === false, 'ARC fromdomain is a parent of From → not verified (exact From domain only, review L3)');
  ok(lib.authAligned_(M(AR(), [SEAL(3, 'evil.example'), SEAL(2, 'google.com'), SEAL(1, 'google.com')]), 'shop.example') === false, 'a re-sealed chain (latest set by another domain) → not verified');
  ok(lib.authAligned_(M(AR(), [SEAL(3, 'google.com'), SEAL(1, 'google.com')]), 'shop.example') === false, 'a gap in the seal instances → not verified');
  ok(lib.authAligned_(M(AR(), ['ARC-Seal: i=2; a=rsa-sha256; d=evil.example; s=x; d=google.com; b=AAAA', SEAL(1, 'google.com')]), 'shop.example') === false, 'duplicate d= tag in a seal → not verified');
  ok(lib.authAligned_(M('Authentication-Results: mx.google.com; arc=none; arc=pass (i=2 spf=pass dmarc=pass fromdomain=shop.example); spf=pass smtp.mailfrom="' + ENV + '"; dmarc=fail header.from=shop.example'), 'shop.example') === false, 'two arc= clauses → not verified');
  ok(lib.authAligned_(M(AR({ fd: 'evil.example' })), 'shop.example') === false, 'ARC fromdomain differs from From → not verified');
  ok(lib.authAligned_(M(AR({ env: 'stranger+caf_=owner=gmail.com@gmail.com' })), 'shop.example') === false, 'forwarded by someone else\'s Gmail → not verified');
  ok(lib.authAligned_(M(AR({ env: 'forwarder@gmail.com' })), 'shop.example') === false, 'mail sent BY forwarder (not its forwarding envelope) → not verified');
  ok(lib.authAligned_(M(AR({ arc: 'arc=fail (i=2 dmarc=pass fromdomain=shop.example)' })), 'shop.example') === false, 'arc=fail → not verified');
  ok(lib.authAligned_(M(AR({ arc: 'arc=pass (i=2 spf=pass dmarc=fail fromdomain=shop.example)' })), 'shop.example') === false, 'ARC record says dmarc=fail → not verified');
  ok(lib.authAligned_(M(AR(), [SEAL(2, 'evil.example'), SEAL(1, 'google.com')]), 'shop.example') === false, 'ARC set i=2 sealed by another domain → not verified');
  ok(lib.authAligned_(M(AR(), [SEAL(2, 'google.com'), SEAL(2, 'google.com')]), 'shop.example') === false, 'two ARC-Seal i=2 → not verified');
  ok(lib.authAligned_(M(AR(), [SEAL(1, 'google.com')]), 'shop.example') === false, 'no ARC-Seal for the reported set → not verified');
  // forgery: a sender-controlled envelope local part trying to smuggle the clauses
  const inj = 'x"; arc=pass (i=2 dmarc=pass fromdomain=shop.example); spf=pass smtp.mailfrom=' + ENV + '; "y@evil.example';
  ok(lib.authAligned_(M('Authentication-Results: mx.google.com; spf=pass (google.com: domain of ' + inj + ' designates 1.2.3.4) smtp.mailfrom="' + inj + '"; dmarc=fail header.from=shop.example'), 'shop.example') === false, 'clauses smuggled inside a quoted envelope address → not verified');
  ok(lib.authAligned_(M('Authentication-Results: mx.google.com; spf=pass (domain of a (arc=pass (i=2 dmarc=pass fromdomain=shop.example)) b) smtp.mailfrom=' + ENV + '; dmarc=fail header.from=shop.example'), 'shop.example') === false, 'arc=pass hidden in a nested comment → not verified');
  // parser: linear time + fuzz
  const P = lib.arClauses_, time = f => { const t = Date.now(); f(); return Date.now() - t; };
  for (const unit of ['(', '"', '\\', ';', '(a', 'arc=pass (', '"(']) {
    const big = unit.repeat(Math.ceil(500000 / unit.length)), small = unit.repeat(Math.ceil(100000 / unit.length));
    const best = f => Math.min(time(f), time(f), time(f));          // min of 3: runall runs the runtime suite in parallel
    let tb, ts; for (let k = 0; k < 3; k++) { tb = best(() => P(big)); ts = best(() => P(small)); if (tb < 10 * Math.max(ts, 50)) break; }   // up to 3 attempts of the pair
    ok(tb < 1500 && tb < 10 * Math.max(ts, 50), `arClauses_: 500 KB of ${JSON.stringify(unit)} in ${tb} ms, ≈ linear`);
  }
  let seed = 20261021, threw = null, fake = null; const rnd = n => (seed = (seed * 1103515245 + 12345) % 2147483648) % n;
  const PARTS = ['arc=pass', ' (', ')', '"', '\\', ';', ' i=2', ' dmarc=pass', ' fromdomain=shop.example', ' spf=pass', ' smtp.mailfrom=', ENV, 'mx.google.com', ' '];
  for (let i = 0; i < 3000; i++) { let v = 'mx.google.com;'; const n = 3 + rnd(25); for (let j = 0; j < n; j++) v += PARTS[rnd(PARTS.length)];
    try { const r = lib.authAligned_(M('Authentication-Results: ' + v), 'shop.example');
          if (r && !/;\s*arc=pass \(i=2[^()]*dmarc=pass[^()]*fromdomain=shop\.example[^()]*\)/.test(v)) { fake = v; break; } }
    catch (e) { threw = String(e); break; } }
  ok(!threw && !fake, 'fuzz: 3,000 random AR values never throw and never verify without a genuine top-level arc=pass record', String(threw || fake || '').slice(0, 200)); }

done();
