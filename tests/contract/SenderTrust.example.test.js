// Contract test: what the Example consumer relies on from SenderTrust 1.0.0
// (parseFrom_, effectiveSender_, matchesAny_, authAligned_, platformIdOk_, isMisdirected_).
// Merged from the source project's two consumer tests; every address and domain is a placeholder.
const load = require('./load'), { ok, done } = require('./_h');
const S = load(['SenderTrust'], { Gmail: undefined }, ['parseFrom_', 'effectiveSender_', 'matchesAny_', 'authAligned_', 'platformIdOk_', 'isMisdirected_']);
const OPTS = { myAddress: 'owner@gmail.com', trustedForwarders: ['forwarder@gmail.com'] };   // the Example consumer's options
// ---- parseFrom_
ok(JSON.stringify(S.parseFrom_('Shop <Billing@Shop.example>')) === '{"addr":"billing@shop.example","domain":"shop.example","ambiguous":false}', 'parseFrom_: last <addr>, lower-cased');
ok(S.parseFrom_('"a" <x@evil.com> <tax@cpa.example>').ambiguous === true && S.parseFrom_('a@b@c').ambiguous === true, 'parseFrom_: two addresses or odd syntax → ambiguous (the consumer holds these)');
let r = S.parseFrom_('"notifications@mg.platform.example" <n@mg.platform.co>');
ok(r.addr === 'n@mg.platform.co', 'parseFrom_: a look-alike display name does not become the address (uses the last <addr>)');
r = S.parseFrom_('NOTIFICATIONS@MG.PLATFORM.EXAMPLE');
ok(r.addr === 'notifications@mg.platform.example' && !r.ambiguous, 'parseFrom_: case is normalized');
r = S.parseFrom_('"Shop <x@a.com>" <office@biz.example>');
ok(r.ambiguous && r.domain === '', 'parseFrom_: two angle addresses → ambiguous, domain empty (fails closed)');
ok(S.parseFrom_('a@b.com, c@d.com').ambiguous, 'parseFrom_: a list of addresses → ambiguous');
r = S.parseFrom_('');
ok(r.ambiguous && r.domain === '', 'parseFrom_: missing header → ambiguous');
// ---- effectiveSender_, matchesAny_
const rel = S.effectiveSender_(S.parseFrom_('<help_at_vendor_example_abc123xyz9_def45678@icloud.com>'));
ok(rel.relay === true && rel.addr === 'help@vendor.example' && rel.domain === 'vendor.example', 'effectiveSender_ unwraps an iCloud Hide-My-Email relay address');
ok(S.matchesAny_({ addr: 'a@mail.shop.com', domain: 'mail.shop.com' }, ['shop.com']) && !S.matchesAny_({ addr: 'a@evilshop.com', domain: 'evilshop.com' }, ['shop.com']) && S.matchesAny_({ addr: 'x@y.com', domain: 'y.com' }, ['x@y.com']), 'matchesAny_: domain or subdomain; exact address entries');
// ---- authAligned_: only Google's own Authentication-Results counts
const msg = ar => ({ getId: () => 'm', getRawContent: () => ['Received: from mx.s (mx.s [192.0.2.1]) by mx.google.com with ESMTPS id a for <owner@gmail.com>', 'Authentication-Results: ' + ar, 'From: x', '', ''].join('\r\n') });
ok(S.authAligned_(msg('mx.google.com; dmarc=pass header.from=shop.com'), 'shop.com', null, OPTS) === true, 'authAligned_: DMARC pass for the From domain → true');
ok(S.authAligned_(msg('mx.google.com; dkim=pass header.d=evil.com; dmarc=fail header.from=shop.com'), 'shop.com', null, OPTS) === false, 'authAligned_: unaligned DKIM → false');
ok(S.authAligned_(msg('evil.example; dmarc=pass header.from=shop.com'), 'shop.com', null, OPTS) === false, 'authAligned_: AR not written by mx.google.com → false');
ok(S.authAligned_(msg('mx.google.com; dmarc=pass header.from=evil.com'), 'shop.com', null, OPTS) === false, 'authAligned_: DMARC pass for another domain → false');
ok(S.authAligned_(msg('mx.google.com; dmarc=pass header.from=shop.com'), '', null, OPTS) === false, 'authAligned_: empty From domain → false');
let why = {};
ok(S.authAligned_(msg('mx.google.com; dkim=pass header.i=@mg.platform.example header.s=s1 header.b=AAAA+BBB; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=mg.platform.example'), 'mg.platform.example', why, {}) === true && why.via === 'dmarc', 'authAligned_: DMARC pass → true, why.via = dmarc');
why = {}; ok(S.authAligned_(msg('mx.google.com; dkim=pass header.i=@platform.example; dmarc=fail header.from=mg.platform.example'), 'mg.platform.example', why, {}) === true && why.via === 'parent', 'authAligned_: only a parent-domain DKIM pass → why.via = parent');
why = {}; ok(S.authAligned_(msg('mx.google.com; dkim=pass header.i=@x.mg.platform.example; dmarc=fail header.from=mg.platform.example'), 'mg.platform.example', why, {}) === true && why.via === 'sub', 'authAligned_: a subdomain DKIM pass → why.via = sub, never exact');
why = {}; ok(S.authAligned_(msg('mx.google.com; dmarc=pass header.from=evil.example'), 'mg.platform.example', why, {}) === false && !why.via, 'authAligned_: another domain → false, why.via unset');
const w = {}; S.authAligned_(msg('mx.google.com; dkim=pass header.d=evil.co.uk'), 'co.uk', w, OPTS);
ok(w.via === 'sub', 'authAligned_: why.via reports a subdomain-only pass (the open public-suffix item in CONTRACT.md)');
// ---- platformIdOk_, isMisdirected_
ok(S.platformIdOk_('Q7XK 29PF M3', () => 'Ref: q7xk  29pf m3') === true && S.platformIdOk_('12345', () => '12345') === false, 'platformIdOk_: case/space-insensitive; < 6 chars never passes');
ok(S.isMisdirected_({ getTo: () => '"Me" <o.wner@gmail.com>', getCc: () => '' }, 'owner') === true && S.isMisdirected_({ getTo: () => 'o.wner@gmail.com, owner@gmail.com', getCc: () => '' }, 'owner') === false, 'isMisdirected_: dotted only → true; exact also present → false');
ok(S.isMisdirected_({ getTo: () => 'someone@x.com', getCc: () => 'o.wner@gmail.com' }, 'owner') === true && S.isMisdirected_({ getTo: () => 'o.wner@gmail.com', getCc: () => 'owner@gmail.com' }, 'owner') === false, 'isMisdirected_ reads Cc as well as To');
// ---- forwarding: verified ONLY through Google-written ARC/AR from a trusted Gmail forwarder
const HOP = 'Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS id a1 for <owner@gmail.com>';
const ENV = 'forwarder+caf_=owner=gmail.com@gmail.com';
const AR = (o = {}) => 'Authentication-Results: mx.google.com; ' + (o.arc || 'arc=pass (i=2 spf=pass spfdomain=shop.example dmarc=pass fromdomain=' + (o.fd || 'shop.example') + ')') +
  '; spf=pass (google.com: domain of ' + (o.env || ENV) + ' designates 209.85.220.41 as permitted sender) smtp.mailfrom="' + (o.env || ENV) + '"; dmarc=fail (p=QUARANTINE arc=pass) header.from=shop.example';
const SEAL = (i, d) => 'ARC-Seal: i=' + i + '; a=rsa-sha256; t=1; cv=pass;\r\n        d=' + d + '; s=arc-20260327;\r\n        b=AAAA';
const FW = (ar, seals = [SEAL(3, 'google.com'), SEAL(2, 'google.com'), SEAL(1, 'google.com')]) => ({ getId: () => 'm', getRawContent: () => ['Delivered-To: owner@gmail.com', 'Received: by 2002:a05:7022::1 with SMTP id x', ...seals, HOP, 'Received-SPF: pass', ar, 'From: Shop <no-reply@shop.example>'].join('\r\n') + '\r\n\r\nbody' });
const fw = (m, d = 'shop.example', o = OPTS) => S.authAligned_(m, d, null, o);
ok(fw(FW(AR())) === true, 'forwarded by the trusted Gmail account, Google ARC dmarc=pass → verified');
ok(fw(FW(AR(), [SEAL(3, 'evil.example'), SEAL(2, 'google.com'), SEAL(1, 'google.com')])) === false, 'a Google chain re-sealed by another domain → not verified');
ok(fw(FW(AR(), [SEAL(3, 'google.com'), SEAL(1, 'google.com')])) === false && fw(FW(AR(), [SEAL(2, 'google.com'), SEAL(2, 'google.com')])) === false, 'gap or duplicate in seal instances → not verified');
ok(fw(FW(AR({ fd: 'sub.shop.example' }))) === false && fw(FW(AR({ fd: 'shop.example' })), 'billing.shop.example') === false, 'ARC fromdomain must equal the From domain exactly');
ok(fw(FW(AR({ env: 'stranger+caf_=owner=gmail.com@gmail.com' }))) === false && fw(FW(AR({ env: 'forwarder@gmail.com' }))) === false, 'another forwarder, or mail sent BY the forwarder → not verified');
ok(fw(FW(AR({ arc: 'arc=fail (i=2 dmarc=pass fromdomain=shop.example)' }))) === false && fw(FW(AR({ arc: 'arc=pass (i=2 spf=pass dmarc=fail fromdomain=shop.example)' }))) === false, 'arc=fail or ARC dmarc=fail → not verified');
ok(fw(FW(AR()), 'shop.example', { myAddress: 'owner@gmail.com', trustedForwarders: ['forwarder@icloud.com'] }) === false && fw(FW(AR()), 'shop.example', { trustedForwarders: ['forwarder@gmail.com'] }) === false && S.authAligned_(FW(AR()), 'shop.example', null, undefined) === false, 'non-Gmail forwarder entry, missing myAddress or no opts → not verified');
done();
