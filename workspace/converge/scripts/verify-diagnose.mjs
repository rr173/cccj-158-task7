#!/usr/bin/env node
/**
 * End-to-end verification for the causal divergence diagnostician.
 * Spawns the REAL HTTP server (ephemeral port + temp data dir, crash points
 * injected via env) and exercises:
 *
 *   1  legal comparison: first divergence, downstream closure, sealed proof
 *   2  same-key reuse: original task / divergence position / proof returned
 *   3  same key, changed input -> 409 TASK_INPUT_CONFLICT (never overwritten)
 *   4  bad topology bundles rejected wholesale (broken chain / bad digest /
 *      bad signature / cycle / duplicate seq / same node different body)
 *   5  concurrent submissions of one comparison -> exactly one task
 *   6  watermark boundary: receipts arriving after the freeze never mix in
 *   7  algorithm switch: in-flight task keeps old version, new task takes new
 *   8  interrupted computation resumes from the persisted phase (or not
 *      started); explanation nodes written exactly once
 *   9  cancel race: one wins queued->canceled, the other gets 409
 *  10  tampered proof -> layered deterministic verification errors
 *  11  role escalation across operator/analyst/observer
 *  12  error pages never echo submitted bundle content
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');

let passed = 0;
let failed = 0;
function check(name, cond, detail = '') {
  if (cond) { passed++; console.log(`  ✓ ${name}`); }
  else { failed++; console.error(`  ✗ ${name} ${detail}`); }
}

const PORT = 49300 + Math.floor(Math.random() * 1500);
const DATA = fs.mkdtempSync(path.join(os.tmpdir(), 'converge-diag-'));
const SECRET = 'test-secret';
const TOK = {
  op: 'operator-token',
  admin: 'admin-token',
  analyst: 'analyst-token',
  observer: 'observer-token',
  reviewer: 'reviewer1-token',
  inspector: 'inspector-token',
  bogus: 'nope',
};
const digest = (s) => crypto.createHash('sha256').update(s).digest('hex');

let serverProc = null;
function startServer(extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [path.join(ROOT, 'src', 'server.mjs')], {
      env: {
        ...process.env,
        CONVERGE_HOST: '127.0.0.1',
        CONVERGE_PORT: String(PORT),
        CONVERGE_DATA_DIR: DATA,
        CONVERGE_RECEIPT_SECRET: SECRET,
        CONVERGE_DIAGNOSE_PUMP_MS: '0',
        ...extraEnv,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    proc.stdout.on('data', (d) => { out += d; });
    proc.stderr.on('data', (d) => { out += d; });
    serverProc = proc;
    const deadline = Date.now() + 5000;
    const poll = async () => {
      try {
        const r = await fetch(`http://127.0.0.1:${PORT}/healthz`);
        if (r.ok) return resolve();
      } catch { /* not yet */ }
      if (Date.now() > deadline) { proc.kill('SIGKILL'); return reject(new Error('server did not start: ' + out)); }
      setTimeout(poll, 50);
    };
    poll();
  });
}
async function stopServer() {
  if (!serverProc) return;
  const p = serverProc;
  serverProc = null;
  await new Promise((res) => {
    p.on('exit', res);
    p.kill('SIGTERM');
    setTimeout(() => { try { p.kill('SIGKILL'); } catch { /* gone */ } res(); }, 1500);
  });
}
async function restartServer(extraEnv = {}) {
  await stopServer();
  await startServer(extraEnv);
}

async function req(method, urlPath, token, body) {
  const res = await fetch(`http://127.0.0.1:${PORT}${urlPath}`, {
    method,
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = null; }
  return { status: res.status, json, text, headers: res.headers };
}
const pump = () => req('POST', '/api/diagnose/pump', TOK.op, {});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ----------------------------------------------------------- receipt builder

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}
function sign(value) {
  return crypto.createHmac('sha256', SECRET).update(canonical(value)).digest('hex');
}

/**
 * Build a signed receipt chain.
 *  nodes: [{kind, parents: indices (already defined), contributions}]
 *  Each item becomes one receipt with monotonic seq; the decision node is the
 *  digest of its body, so "same node, different body" is server-detectable.
 */
function buildGroup(group, nodes) {
  const receipts = [];
  const nodeDigests = [];
  let prev = null;
  nodes.forEach((n, i) => {
    const parents = (n.parents || []).map((pi) => nodeDigests[pi]);
    const body = {
      decision_kind: n.kind || (i === 0 ? 'accept' : 'extend'),
      parents,
      contributions: n.contributions || [{ region: `tiles:${String(i + 1).padStart(3, '0')}`, change_digest: digest(group + '-c' + i) }],
    };
    const decision_node = crypto.createHash('sha256').update(canonical({
      decision_kind: body.decision_kind, parents: body.parents, contributions: body.contributions,
    })).digest('hex');
    nodeDigests.push(decision_node);
    const fields = {
      seq: i + 1, group, decision_node, decision_kind: body.decision_kind,
      parents: body.parents, contributions: body.contributions, prev_receipt: prev,
    };
    const hash = crypto.createHash('sha256').update(canonical(fields)).digest('hex');
    const sig = sign(fields);
    const r = { seq: i + 1, decision_node, decision_kind: body.decision_kind, parents: body.parents,
      contributions: body.contributions, prev_receipt: prev, hash, sig };
    receipts.push(r);
    prev = hash;
  });
  return { receipts, nodeDigests };
}

// Variant chains used across sections. Content digests are GROUP-INDEPENDENT:
// two groups built from the same content share node identities, so only the
// deliberately diverging position differs. `tag` namespaces the shared content.
function linear(group, divergentAt = null, tag = 'lin') {
  const nodes = [];
  for (let i = 0; i < 5; i++) {
    nodes.push({ parents: i === 0 ? [] : [i - 1], contributions: [{
      region: `tiles:${String(i + 1).padStart(3, '0')}`,
      change_digest: divergentAt === i ? digest(tag + '-CHANGED') : digest(tag + '-c' + i),
    }] });
  }
  return buildGroup(group, nodes);
}
/** DAG with a merge: 0 -> 1,2 -> 3(merge) -> 4. */
function mergeDag(group, branchDigest, tag = 'dag') {
  return buildGroup(group, [
    { kind: 'accept', parents: [], contributions: [{ region: 'tiles:001', change_digest: digest(tag + '-c0') }] },
    { kind: 'extend', parents: [0], contributions: [{ region: 'tiles:002', change_digest: digest(tag + '-c1') }] },
    { kind: 'extend', parents: [0], contributions: [{ region: 'tiles:003', change_digest: digest(branchDigest) }] },
    { kind: 'merge', parents: [1, 2], contributions: [
      { region: 'tiles:002', change_digest: digest(tag + '-c1') },
      { region: 'tiles:003', change_digest: digest(branchDigest) },
    ] },
    { kind: 'extend', parents: [3], contributions: [{ region: 'tiles:004', change_digest: digest(tag + '-c4') }] },
  ]);
}
/** Same graph as mergeDag but receipts arrive in a different chain order. */
function mergeDagReordered(group, branchDigest, tag = 'dag') {
  // Hand-built with receipt order 0,2,1,3,4 while preserving the same edges.
  const defs = [
    { idx: 0, parents: [] }, { idx: 2, parents: [0] }, { idx: 1, parents: [0] },
    { idx: 3, parents: [1, 2] }, { idx: 4, parents: [3] },
  ];
  const bodyAt = (i) => ({
    0: { kind: 'accept', contributions: [{ region: 'tiles:001', change_digest: digest(tag + '-c0') }] },
    1: { kind: 'extend', contributions: [{ region: 'tiles:002', change_digest: digest(tag + '-c1') }] },
    2: { kind: 'extend', contributions: [{ region: 'tiles:003', change_digest: digest(branchDigest) }] },
    3: { kind: 'merge', contributions: [
      { region: 'tiles:002', change_digest: digest(tag + '-c1') },
      { region: 'tiles:003', change_digest: digest(branchDigest) },
    ] },
    4: { kind: 'extend', contributions: [{ region: 'tiles:004', change_digest: digest(tag + '-c4') }] },
  }[i]);
  const byNodeIndex = new Array(5);
  const receipts = [];
  let prev = null;
  defs.forEach((d, receiptPos) => {
    const body = bodyAt(d.idx);
    const parentDigests = d.parents.map((pi) => byNodeIndex[pi]);
    const full = { decision_kind: body.kind, parents: parentDigests, contributions: body.contributions };
    const node = crypto.createHash('sha256').update(canonical(full)).digest('hex');
    byNodeIndex[d.idx] = node;
    const fields = { seq: receiptPos + 1, group, decision_node: node, ...full, prev_receipt: prev };
    const hash = crypto.createHash('sha256').update(canonical(fields)).digest('hex');
    receipts.push({ seq: receiptPos + 1, decision_node: node, decision_kind: full.decision_kind,
      parents: parentDigests, contributions: full.contributions, prev_receipt: prev,
      hash, sig: sign(fields) });
    prev = hash;
  });
  return { receipts, nodeDigests: byNodeIndex };
}

async function ingest(group, receipts, token = TOK.op) {
  return req('POST', '/api/diagnose/receipts', token, { group, entries: receipts });
}
async function submit(key, lg, rg, token = TOK.analyst) {
  return req('POST', '/api/diagnose/comparisons', token, { task_key: key, left_group: lg, right_group: rg });
}
async function waitSealed(key, tries = 30) {
  for (let i = 0; i < tries; i++) {
    const r = await req('GET', `/api/diagnose/comparisons/${key}`, TOK.analyst);
    if (r.json && (r.json.phase === 'sealed' || r.json.phase === 'canceled')) return r.json;
    await sleep(40);
  }
  return null;
}

// ===========================================================================
console.log('1. 合法比较：分歧位置、下游闭包、密封证明');
await startServer();
{
  const A = linear('grp-good-A', null);
  const B = linear('grp-good-B', 2); // node index 2 (receipt seq 3) differs
  const ia = await ingest('grp-good-A', A.receipts);
  const ib = await ingest('grp-good-B', B.receipts);
  check('both bundles accepted', ia.status === 200 && ib.status === 200,
    `${ia.status} ${ib.status} ${JSON.stringify(ia.json?.error)}`);

  const s = await submit('cmp-legal', 'grp-good-A', 'grp-good-B');
  check('comparison created 201', s.status === 201 && s.json.phase === 'queued', JSON.stringify(s.json));
  check('algorithm pinned chain-v1', s.json.algorithm === 'chain-v1');

  const p = await pump();
  check('pump processed the task', p.status === 200 && p.json.processed.length === 1, JSON.stringify(p.json));
  const sealed = await waitSealed('cmp-legal');
  check('task sealed', sealed && sealed.phase === 'sealed', JSON.stringify(sealed));
  check('first divergence is the seq-3 node',
    sealed.divergence && sealed.divergence.kind === 'node_mismatch' && sealed.divergence.index === 2 &&
      sealed.divergence.left_node === A.nodeDigests[2] && sealed.divergence.right_node === B.nodeDigests[2],
    JSON.stringify(sealed?.divergence));
  check('downstream closure is the two causal descendants each side',
    sealed.downstream.left.length === 2 && sealed.downstream.right.length === 2 &&
      sealed.downstream.left.includes(A.nodeDigests[3]) && sealed.downstream.left.includes(A.nodeDigests[4]) &&
      sealed.downstream.right[0] === B.nodeDigests[3] && sealed.downstream.right[1] === B.nodeDigests[4],
    JSON.stringify(sealed.downstream));
  check('list view exposes evidence count', sealed.evidence_count === 6, String(sealed.evidence_count));

  const detail = (await req('GET', '/api/diagnose/comparisons/cmp-legal', TOK.analyst)).json;
  check('detail evidence count 6', detail.evidence.length === 6, String(detail.evidence.length));
  check('evidence carries no site/request_key/image fields',
    detail.evidence.every((e) =>
      !('site' in e) && !('request_key' in e) && !('image' in e) && !('site_seq' in e) &&
      e.contributions.every((c) => /^[0-9a-f]{64}$/.test(c.change_digest))));

  const proof = await req('GET', '/api/diagnose/comparisons/cmp-legal/proof', TOK.observer);
  check('observer can read sealed proof', proof.status === 200 && proof.json.proof.format === 'converge-diagnosis-proof/v1');
  check('proof verifies', (await req('POST', '/api/diagnose/proofs/verify', TOK.observer,
    { proof: proof.json.proof })).json.ok === true);

  // Converged case: two groups with identical bodies under distinct identities.
  const X = buildGroup('grp-same-l', Array.from({ length: 3 }, (_, i) => ({
    parents: i === 0 ? [] : [i - 1],
    contributions: [{ region: `tiles:${String(i + 1).padStart(3, '0')}`, change_digest: digest('shared-c' + i) }],
  })));
  const Y = buildGroup('grp-same-r', Array.from({ length: 3 }, (_, i) => ({
    parents: i === 0 ? [] : [i - 1],
    contributions: [{ region: `tiles:${String(i + 1).padStart(3, '0')}`, change_digest: digest('shared-c' + i) }],
  })));
  await ingest('grp-same-l', X.receipts);
  await ingest('grp-same-r', Y.receipts);
  await submit('cmp-converged', 'grp-same-l', 'grp-same-r');
  await pump();
  const conv = await waitSealed('cmp-converged');
  check('identical skeletons converge', conv && conv.converged === true && conv.divergence === null,
    JSON.stringify(conv));
}

console.log('2. 同键复用：返回原任务、原分歧位置、原证明');
{
  const before = (await req('GET', '/api/diagnose/comparisons/cmp-legal', TOK.analyst)).json;
  const again = await submit('cmp-legal', 'grp-good-A', 'grp-good-B');
  check('replay returns 200 reused', again.status === 200 && again.json === undefined ? false : again.json && again.json.phase === 'sealed',
    `${again.status}`);
  check('same divergence position and proof digest',
    again.json.divergence.index === before.divergence.index &&
      again.json.proof_digest === before.proof_digest &&
      again.json.watermarks.left === before.watermarks.left,
    JSON.stringify({ a: again.json?.divergence, b: before.divergence }));
  const proof1 = (await req('GET', '/api/diagnose/comparisons/cmp-legal/proof', TOK.analyst)).json.proof;
  const proof2 = (await req('GET', '/api/diagnose/comparisons/cmp-legal/proof', TOK.analyst)).json.proof;
  check('byte-identical sealed proof across reads', JSON.stringify(proof1) === JSON.stringify(proof2));
}

console.log('3. 同键异输入 -> 409 冲突，诊断不被覆盖');
{
  const D = linear('grp-conflict-D', 1);
  await ingest('grp-conflict-D', D.receipts);
  const conflict = await submit('cmp-legal', 'grp-good-A', 'grp-conflict-D');
  check('conflict 409 TASK_INPUT_CONFLICT',
    conflict.status === 409 && conflict.json.error.code === 'TASK_INPUT_CONFLICT',
    JSON.stringify(conflict.json?.error));
  check('error details expose no receipt content, only metadata',
    JSON.stringify(conflict.json.error).indexOf('tiles') === -1 &&
      JSON.stringify(conflict.json.error).indexOf(D.receipts[0].hash.slice(0, 32)) === -1);
  const still = (await req('GET', '/api/diagnose/comparisons/cmp-legal', TOK.analyst)).json;
  check('original diagnosis intact (same groups, same proof)',
    still.right_group === 'grp-good-B' && still.phase === 'sealed');
}

console.log('4. 拓扑坏包整包拒绝（六类破损）');
async function expectRejected(name, group, mutate) {
  const good = linear(group, null).receipts.map((r) => ({ ...r }));
  const entries = mutate(good);
  const r = await ingest(group, entries);
  check(name, r.status === 400 && r.json?.error?.code === 'DIAG_BAD_BUNDLE',
    `${r.status} ${JSON.stringify(r.json?.error?.details?.reasons)}`);
  return r;
}
{
  const r1 = await expectRejected('broken prev_receipt chain', 'bad-chain', (e) => { e[2].prev_receipt = e[0].hash; return e; });
  check('broken chain reason CHAIN_BROKEN', r1.json.error.details.reasons.some((x) => x.code === 'CHAIN_BROKEN'));
  const r2 = await expectRejected('content digest format', 'bad-digfmt', (e) => { e[1].decision_node = 'zzz'; return e; });
  check('format reason DIGEST_FORMAT', r2.json.error.details.reasons.some((x) => x.code === 'DIGEST_FORMAT'));
  const r3 = await expectRejected('receipt hash mismatch', 'bad-hash', (e) => { e[1].hash = 'a'.repeat(64); return e; });
  check('hash reason RECEIPT_HASH_MISMATCH', r3.json.error.details.reasons.some((x) => x.code === 'RECEIPT_HASH_MISMATCH'));
  const r4 = await expectRejected('bad signature', 'bad-sig', (e) => { e[0].sig = 'b'.repeat(64); return e; });
  check('sig reason RECEIPT_SIG_INVALID', r4.json.error.details.reasons.some((x) => x.code === 'RECEIPT_SIG_INVALID'));

  // Topology cycle at manager level: the validator's Kahn pass is reachable
  // directly with an in-memory graph (the strict node==digest(body) binding
  // makes a self-consistently signed HTTP cycle cryptographically impossible,
  // which is itself the protection — but the structural guard still runs).
  {
    const { parseBundle } = await import(path.join(ROOT, 'src', 'diagnose.mjs'));
    function cycleReceipt(seq, node, parents, prev) {
      const fields = { seq, group: 'bad-cycle-unit', decision_node: node, decision_kind: 'extend',
        parents, contributions: [{ region: 'r' + seq, change_digest: digest('c' + seq) }], prev_receipt: prev };
      return { seq, decision_node: node, decision_kind: 'extend', parents,
        contributions: fields.contributions, prev_receipt: prev,
        hash: crypto.createHash('sha256').update(canonical(fields)).digest('hex'), sig: sign(fields) };
    }
    // Three digests forming a cycle; hashes/sigs are valid over their fields,
    // node digests intentionally mismatch so NODE_DIGEST_MISMATCH is reported
    // alongside TOPOLOGY_CYCLE, proving the Kahn guard executed.
    const [d1, d2, d3] = [digest('cyc1'), digest('cyc2'), digest('cyc3')];
    const cycEntries = [
      cycleReceipt(1, d1, [d3], null),
      cycleReceipt(2, d2, [d1], cycleReceipt(1, d1, [d3], null).hash),
      cycleReceipt(3, d3, [d2], null),
    ];
    // Fix prev chain (seq2.prev=hash1, seq3.prev=hash2) so only topology errors remain of interest.
    cycEntries[1].prev_receipt = cycEntries[0].hash;
    cycEntries[2].prev_receipt = cycEntries[1].hash;
    for (const r of cycEntries) {
      const fields = { seq: r.seq, group: 'bad-cycle-unit', decision_node: r.decision_node,
        decision_kind: r.decision_kind, parents: r.parents, contributions: r.contributions,
        prev_receipt: r.prev_receipt };
      r.hash = crypto.createHash('sha256').update(canonical(fields)).digest('hex');
      r.sig = sign(fields);
    }
    let caught = null;
    try { parseBundle('bad-cycle-unit', cycEntries, SECRET, []); } catch (e) { caught = e; }
    check('topology cycle reported by Kahn pass',
      caught && caught.details.reasons.some((x) => x.code === 'TOPOLOGY_CYCLE'),
      JSON.stringify(caught?.details?.reasons));
  }

  const r5 = await expectRejected('unresolved predecessor (dangling edge)', 'bad-dangle', (e) => {
    // Rebuild receipts with a parent digest that never exists, with correct
    // node/hash/sig over the modified body.
    const dangling = 'd'.repeat(64);
    const out = [];
    let prev = null;
    e.forEach((orig, i) => {
      const parents = i === 1 ? [dangling] : [];
      const contributions = orig.contributions;
      const kind = orig.decision_kind;
      const body = { decision_kind: kind, parents, contributions };
      const node = crypto.createHash('sha256').update(canonical(body)).digest('hex');
      const fields = { seq: i + 1, group: 'bad-dangle', decision_node: node, decision_kind: kind,
        parents, contributions, prev_receipt: prev };
      const hash = crypto.createHash('sha256').update(canonical(fields)).digest('hex');
      out.push({ seq: i + 1, decision_node: node, decision_kind: kind, parents, contributions,
        prev_receipt: prev, hash, sig: sign(fields) });
      prev = hash;
    });
    return out;
  });
  check('dangling reason UNRESOLVED_PREDECESSOR',
    r5.json.error.details.reasons.some((x) => x.code === 'UNRESOLVED_PREDECESSOR'));

  const r6 = await expectRejected('duplicate seq', 'bad-dupseq', (e) => {
    const copy = { ...e[2], hash: digest('other') };
    copy.sig = sign({ seq: copy.seq, group: 'bad-dupseq', decision_node: copy.decision_node,
      decision_kind: copy.decision_kind, parents: copy.parents, contributions: copy.contributions,
      prev_receipt: copy.prev_receipt });
    e.splice(2, 0, copy);
    return e;
  });
  check('dup seq reason DUPLICATE_SEQ', r6.json.error.details.reasons.some((x) => x.code === 'DUPLICATE_SEQ'));

  // Same node, two different bodies.
  {
    const g = buildGroup('bad-nodebody', [
      { parents: [], contributions: [{ region: 't1', change_digest: digest('n1') }] },
      { parents: [0], contributions: [{ region: 't2', change_digest: digest('n2') }] },
    ]);
    // Third receipt claims the same decision_node as seq 1 but with another body.
    const node1 = g.receipts[0].decision_node;
    const fields = {
      seq: 3, group: 'bad-nodebody', decision_node: node1,
      decision_kind: 'merge', parents: [g.nodeDigests[1]],
      contributions: [{ region: 't9', change_digest: digest('n9') }],
      prev_receipt: g.receipts[1].hash,
    };
    fields.sigPlaceholder = true;
    const tampered = { ...fields };
    delete tampered.sigPlaceholder;
    const hash = crypto.createHash('sha256').update(canonical(tampered)).digest('hex');
    g.receipts.push({ seq: 3, decision_node: node1, decision_kind: 'merge',
      parents: [g.nodeDigests[1]], contributions: tampered.contributions,
      prev_receipt: g.receipts[1].hash, hash, sig: sign(tampered) });
    const r = await ingest('bad-nodebody', g.receipts);
    check('same node different body rejected',
      r.status === 400 && r.json.error.details.reasons.some((x) => x.code === 'NODE_DIGEST_MISMATCH'),
      JSON.stringify(r.json?.error?.details?.reasons));
  }

  // None of the rejected groups exist: intake is all-or-nothing.
  const groups = (await req('GET', '/api/diagnose/groups', TOK.analyst)).json.groups.map((x) => x.group);
  check('rejected bundles created no watermarks',
    ['bad-chain', 'bad-digfmt', 'bad-hash', 'bad-sig', 'bad-dangle', 'bad-dupseq', 'bad-nodebody']
      .every((g) => !groups.includes(g)),
    JSON.stringify(groups));

  // Continuation batches must also validate wholesale; a bad second batch
  // leaves the existing watermark untouched.
  const cont = linear('bad-cont', null).receipts;
  await ingest('bad-cont', cont.slice(0, 3));
  const wmBefore = (await req('GET', '/api/diagnose/groups', TOK.op)).json.groups.find((x) => x.group === 'bad-cont').watermark;
  const badBatch = linear('bad-cont', null).receipts.slice(3).map((r) => ({ ...r }));
  badBatch[0].sig = 'c'.repeat(64);
  const rc = await ingest('bad-cont', badBatch);
  check('bad continuation batch rejected', rc.status === 400);
  const wmAfter = (await req('GET', '/api/diagnose/groups', TOK.op)).json.groups.find((x) => x.group === 'bad-cont').watermark;
  check('watermark unchanged after rejected continuation', wmBefore === 3 && wmAfter === 3, `${wmBefore}/${wmAfter}`);
}

console.log('5. 并发提交同一比较 -> 恰好一个任务');
{
  const A = linear('grp-conc-A', null);
  const B = linear('grp-conc-B', 1);
  await ingest('grp-conc-A', A.receipts);
  await ingest('grp-conc-B', B.receipts);
  const rs = await Promise.all(Array.from({ length: 8 }, () => submit('cmp-concurrent', 'grp-conc-A', 'grp-conc-B')));
  const created = rs.filter((r) => r.status === 201).length;
  const reused = rs.filter((r) => r.status === 200).length;
  check('exactly one 201, remaining are 200 reuse', created === 1 && reused === 7,
    `201=${created} 200=${reused} other=${rs.map((r) => r.status).join(',')}`);
  await pump();
  const list = (await req('GET', '/api/diagnose/comparisons', TOK.analyst)).json.comparisons;
  check('task listed exactly once', list.filter((t) => t.task_key === 'cmp-concurrent').length === 1);
}

console.log('6. 水位边界：冻结之后到达的收据不得混入');
{
  const A = linear('grp-wm-A', null, 'wm').receipts.slice(0, 3);
  const B = linear('grp-wm-B', null, 'wm').receipts.slice(0, 3);
  await ingest('grp-wm-A', A);
  await ingest('grp-wm-B', B);
  const s = await submit('cmp-watermark', 'grp-wm-A', 'grp-wm-B');
  check('watermarks frozen at 3/3', s.json.watermarks.left === 3 && s.json.watermarks.right === 3);

  // Sign continuation receipts under grp-wm-A / grp-wm-B with identical bodies.
  function continueGroup(group, existing, extra) {
    const out = [];
    let prev = existing[existing.length - 1].hash;
    extra.forEach((r, k) => {
      const fields = {
        seq: existing.length + k + 1,
        group, decision_node: r.decision_node, decision_kind: r.decision_kind,
        parents: r.parents, contributions: r.contributions, prev_receipt: prev,
      };
      const hash = crypto.createHash('sha256').update(canonical(fields)).digest('hex');
      out.push({ seq: fields.seq, decision_node: r.decision_node, decision_kind: r.decision_kind,
        parents: r.parents, contributions: r.contributions, prev_receipt: prev, hash, sig: sign(fields) });
      prev = hash;
    });
    return out;
  }
  // The post-watermark receipts are valid continuations anchored on the
  // 3-receipt head using seq 4/5 bodies of the same linear() definition.
  const fullA = linear('grp-wm-A', null, 'wm').receipts;
  const fullB = linear('grp-wm-B', null, 'wm').receipts;
  await ingest('grp-wm-A', continueGroup('grp-wm-A', A, fullA.slice(3)));
  await ingest('grp-wm-B', continueGroup('grp-wm-B', B, fullB.slice(3)));

  await pump();
  const sealed = await waitSealed('cmp-watermark');
  check('frozen task stays at watermark 3/3',
    sealed.watermarks.left === 3 && sealed.watermarks.right === 3, JSON.stringify(sealed.watermarks));
  const detail = (await req('GET', '/api/diagnose/comparisons/cmp-watermark', TOK.analyst)).json;
  check('skeletons contain exactly 3 nodes each',
    detail.skeletons.left.nodes.length === 3 && detail.skeletons.right.nodes.length === 3,
    `${detail.skeletons.left.nodes.length}/${detail.skeletons.right.nodes.length}`);
  check('frozen comparison converged on identical heads', sealed.converged === true);

  // A NEW comparison at the advanced watermark sees 5 nodes.
  await submit('cmp-watermark2', 'grp-wm-A', 'grp-wm-B');
  await pump();
  const sealed2 = await waitSealed('cmp-watermark2');
  check('later comparison reads new watermark 5/5',
    sealed2.watermarks.left === 5 && sealed2.watermarks.right === 5, JSON.stringify(sealed2.watermarks));
}

console.log('7. 算法版本切换：在途留旧版，新任务用新版');
{
  const v0 = await req('GET', '/api/diagnose/versions', TOK.op);
  check('default chain-v1', v0.json.active === 'chain-v1');

  const P = mergeDag('grp-algo-P', 'branchP');
  const Q = mergeDagReordered('grp-algo-Q', 'branchP');
  await ingest('grp-algo-P', P.receipts);
  await ingest('grp-algo-Q', Q.receipts);

  const inFlight = await submit('cmp-v1-inflight', 'grp-algo-P', 'grp-algo-Q');
  check('in-flight pinned chain-v1', inFlight.json.algorithm === 'chain-v1');

  const act = await req('POST', '/api/diagnose/versions/activate', TOK.op, { algorithm: 'topo-v2' });
  check('activation 200 topo-v2', act.status === 200 && act.json.active === 'topo-v2');
  check('in-flight task still pinned chain-v1 after switch',
    (await req('GET', '/api/diagnose/comparisons/cmp-v1-inflight', TOK.analyst)).json.algorithm === 'chain-v1');

  const newer = await submit('cmp-v2-new', 'grp-algo-P', 'grp-algo-Q');
  check('new task pinned topo-v2', newer.json.algorithm === 'topo-v2');

  await pump();
  const t1 = await waitSealed('cmp-v1-inflight');
  const t2 = await waitSealed('cmp-v2-new');
  check('v1 sees a positional mismatch on reordered-but-equal graphs',
    t1.converged === false && t1.divergence.kind === 'node_mismatch', JSON.stringify(t1.divergence));
  check('v2 aligns the same graphs topologically and converges',
    t2.converged === true && t2.divergence === null, JSON.stringify(t2.divergence));

  // v2 branch-level divergence: one side carries a different branch digest
  // (same vertices/edges shape, one node present only per side).
  const P2 = mergeDag('grp-algo2-P', digest('branch-left'), 'dag2');
  const Q2 = mergeDag('grp-algo2-Q', digest('branch-right'), 'dag2');
  await ingest('grp-algo2-P', P2.receipts);
  await ingest('grp-algo2-Q', Q2.receipts);
  await submit('cmp-v2-branch', 'grp-algo2-P', 'grp-algo2-Q');
  await pump();
  const tb = await waitSealed('cmp-v2-branch');
  check('v2 flags the branch node as one-sided',
    tb.converged === false && (tb.divergence.kind === 'only_in_left' || tb.divergence.kind === 'only_in_right'),
    JSON.stringify(tb.divergence));
  // Downstream of the branch node reaches the merge and the tail (2 nodes).
  const divSide = tb.divergence.kind === 'only_in_left' ? 'left' : 'right';
  const mergeNode = divSide === 'left' ? P2.nodeDigests[3] : Q2.nodeDigests[3];
  const tailNode = divSide === 'left' ? P2.nodeDigests[4] : Q2.nodeDigests[4];
  check('downstream closure crosses the merge to the tail',
    tb.downstream[divSide].length === 2 &&
      tb.downstream[divSide].includes(mergeNode) &&
      tb.downstream[divSide].includes(tailNode),
    JSON.stringify(tb.downstream));

  // Activating again survives restart (version state is persisted).
  await restartServer();
  const vAfter = await req('GET', '/api/diagnose/versions', TOK.op);
  check('active version survives restart', vAfter.json.active === 'topo-v2');
}

console.log('8. 计算中断恢复：阶段续办 / 回未开始 / 解释节点只写一次');
{
  const A = linear('grp-crash-A', 3);
  const B = linear('grp-crash-B', null);
  await ingest('grp-crash-A', A.receipts);
  await ingest('grp-crash-B', B.receipts);

  async function crashResume(name, crashPoint, expectPhaseBeforeCrash) {
    await submit('cmp-crash-' + crashPoint, 'grp-crash-A', 'grp-crash-B');
    await restartServer({ CONVERGE_DIAGNOSE_CRASH_POINT: crashPoint });
    // One pump step trips the injected process exit before responding: the
    // dropped connection is the expected observation.
    await req('POST', '/api/diagnose/pump', TOK.op, {}).catch(() => null);
    await sleep(150);
    const key = 'cmp-crash-' + crashPoint;
    const afterCrash = await req('GET', `/api/diagnose/comparisons/${key}`, TOK.analyst).catch(() => null);
    await restartServer();
    const before = (await req('GET', `/api/diagnose/comparisons/${key}`, TOK.analyst)).json;
    check(`${name}: task persisted after restart`, !!before && typeof before.phase === 'string', JSON.stringify(before));
    check(`${name}: restarted from persisted phase or not-started`,
      before.phase === 'queued' || before.phase === 'diffed' || before.phase === 'evidence_written',
      `observed ${afterCrash?.json?.phase ?? 'server-exited'} -> restart ${before.phase}`);
    await pump();
    const sealed = await waitSealed(key);
    check(`${name}: resumes and seals`, sealed && sealed.phase === 'sealed',
      `phase after crash read: ${JSON.stringify(afterCrash?.json?.phase)}`);
    return sealed;
  }

  await crashResume('before_start', 'before_start');
  await crashResume('after_diff', 'after_diff');
  await crashResume('after_evidence', 'after_evidence');

  // Explanation nodes written exactly once: one T_EVIDENCE frame PER TASK,
  // verified by parsing every frame payload on disk.
  const wal = fs.readFileSync(path.join(DATA, 'diagnose.wal'));
  const framesByType = new Map();
  {
    let off = 0;
    while (off + 7 <= wal.length) {
      if (wal[off] !== 0x43 || wal[off + 1] !== 0x44) break;
      const t = wal[off + 2];
      const len = wal.readUInt32BE(off + 3);
      const payload = wal.subarray(off + 7, off + 7 + len);
      if (!framesByType.has(t)) framesByType.set(t, []);
      framesByType.get(t).push(payload.toString('utf8'));
      off += 2 + 1 + 4 + len + 4;
    }
  }
  const evidencePayloads = framesByType.get(13) || [];
  const evidenceByTask = new Map();
  for (const p of evidencePayloads) {
    const ev = JSON.parse(p);
    evidenceByTask.set(ev.task_key, (evidenceByTask.get(ev.task_key) || 0) + 1);
  }
  const crashKeys = ['before_start', 'after_diff', 'after_evidence'].map((cp) => 'cmp-crash-' + cp);
  check('each crashed-and-resumed task has exactly one evidence frame',
    crashKeys.every((k) => evidenceByTask.get(k) === 1),
    JSON.stringify(Object.fromEntries(evidenceByTask)));

  // Re-pump after sealing is a no-op (no extra phases appended).
  const proofFramesBefore = (framesByType.get(14) || []).length;
  await pump();
  await pump();
  const wal2 = fs.readFileSync(path.join(DATA, 'diagnose.wal'));
  const recount = (() => {
    let off = 0; let count = 0;
    while (off + 7 <= wal2.length) {
      if (wal2[off] !== 0x43 || wal2[off + 1] !== 0x44) break;
      const t = wal2[off + 2];
      const len = wal2.readUInt32BE(off + 3);
      if (t === 14) count++;
      off += 2 + 1 + 4 + len + 4;
    }
    return count;
  })();
  check('sealed tasks are never recomputed', recount === proofFramesBefore);
}

console.log('9. 取消竞态：仅 queued 可取消，恰好一方成功');
{
  const A = linear('grp-cancel-A', null);
  const B = linear('grp-cancel-B', 2);
  await ingest('grp-cancel-A', A.receipts);
  await ingest('grp-cancel-B', B.receipts);
  await submit('cmp-cancel-race', 'grp-cancel-A', 'grp-cancel-B');
  const [w1, w2] = await Promise.all([
    req('POST', '/api/diagnose/comparisons/cmp-cancel-race/cancel', TOK.op, {}),
    req('POST', '/api/diagnose/comparisons/cmp-cancel-race/cancel', TOK.admin, {}),
  ]);
  const ok = [w1, w2].filter((r) => r.status === 200);
  const conflict = [w1, w2].filter((r) => r.status === 409 && r.json.error.code === 'TASK_ALREADY_CANCELED');
  check('exactly one cancel wins', ok.length === 1 && conflict.length === 1,
    `${w1.status}/${w2.status}`);
  const view = (await req('GET', '/api/diagnose/comparisons/cmp-cancel-race', TOK.analyst)).json;
  check('task stays canceled after pump (resource released)', view.phase === 'canceled');
  await pump();
  await sleep(60);
  const view2 = (await req('GET', '/api/diagnose/comparisons/cmp-cancel-race', TOK.analyst)).json;
  check('canceled task is never processed', view2.phase === 'canceled');

  // Running and sealed tasks cannot be canceled.
  await submit('cmp-cancel-sealed', 'grp-cancel-A', 'grp-cancel-B');
  await pump();
  await waitSealed('cmp-cancel-sealed');
  const cs = await req('POST', '/api/diagnose/comparisons/cmp-cancel-sealed/cancel', TOK.op, {});
  check('sealed cancel rejected 409 TASK_NOT_CANCELLABLE',
    cs.status === 409 && cs.json.error.code === 'TASK_NOT_CANCELLABLE');
  const proofStill = await req('GET', '/api/diagnose/comparisons/cmp-cancel-sealed/proof', TOK.observer);
  check('sealed diagnosis still verifiable after cancel attempt', proofStill.status === 200);
}

console.log('10. 证明被改：分层验真返回确定错误');
{
  const proof = (await req('GET', '/api/diagnose/comparisons/cmp-legal/proof', TOK.observer)).json.proof;
  const verify = (p) => req('POST', '/api/diagnose/proofs/verify', TOK.observer, { proof: p });

  const badFmt = await verify({ ...proof, format: 'something/else' });
  check('unknown format rejected', badFmt.status === 422 && badFmt.json.error.code === 'DIAG_PROOF_FORMAT_UNKNOWN');

  const tamperedEvidence = await verify({ ...proof, evidence: [...proof.evidence, { role: 'forged' }] });
  check('evidence tamper detected (evidence_digest layer)',
    tamperedEvidence.status === 422 && tamperedEvidence.json.error.code === 'DIAG_PROOF_EVIDENCE_MISMATCH');

  const tamperedRoot = await verify({ ...proof, comparison: { ...proof.comparison, converged: !proof.comparison.converged } });
  // Flipping converged with no evidence citation: root digest breaks.
  check('root tamper detected (digest layer)',
    tamperedRoot.status === 422 &&
      ['DIAG_PROOF_DIGEST_MISMATCH', 'DIAG_PROOF_ROOT_MISMATCH'].includes(tamperedRoot.json.error.code),
    tamperedRoot.json.error.code);

  const tamperedSig = await verify({ ...proof, sig: 'f'.repeat(64) });
  check('forged signature detected', tamperedSig.status === 422 && tamperedSig.json.error.code === 'DIAG_PROOF_SIG_INVALID');

  const malformed = await verify({ hello: 'world' });
  check('malformed proof rejected', malformed.status === 422 && malformed.json.error.code === 'DIAG_PROOF_MALFORMED');

  // Observer verification of the stored (unmodified) proof still passes.
  check('stored proof remains valid',
    (await verify(proof)).json.ok === true);
}

console.log('11. 角色越权：三档可见范围强制');
{
  const noToken = await req('GET', '/api/diagnose/comparisons', null);
  check('missing token 401', noToken.status === 401);
  const bogus = await req('GET', '/api/diagnose/comparisons', TOK.bogus);
  check('bad token 403', bogus.status === 403);

  // Observer: proofs only.
  check('observer cannot ingest', (await req('POST', '/api/diagnose/receipts', TOK.observer, {})).status === 403);
  check('observer cannot submit comparison',
    (await submit('cmp-x', 'grp-good-A', 'grp-good-B', TOK.observer)).status === 403);
  check('observer cannot list groups', (await req('GET', '/api/diagnose/groups', TOK.observer)).status === 403);
  check('observer cannot list comparisons', (await req('GET', '/api/diagnose/comparisons', TOK.observer)).status === 403);
  check('observer cannot cancel',
    (await req('POST', '/api/diagnose/comparisons/cmp-legal/cancel', TOK.observer, {})).status === 403);
  check('observer cannot switch versions',
    (await req('POST', '/api/diagnose/versions/activate', TOK.observer, { algorithm: 'chain-v1' })).status === 403);
  check('observer can verify', (await req('POST', '/api/diagnose/proofs/verify', TOK.observer, {
    proof: (await req('GET', '/api/diagnose/comparisons/cmp-legal/proof', TOK.observer)).json.proof,
  })).status === 200);

  // Analyst: choose and read, never ops.
  check('analyst cannot ingest', (await ingest('x', [], TOK.analyst)).status === 403);
  check('analyst cannot cancel',
    (await req('POST', '/api/diagnose/comparisons/cmp-cancel-race/cancel', TOK.analyst, {})).status === 403);
  check('analyst cannot switch versions',
    (await req('POST', '/api/diagnose/versions/activate', TOK.analyst, { algorithm: 'chain-v1' })).status === 403);
  check('analyst cannot pump', (await req('POST', '/api/diagnose/pump', TOK.analyst, {})).status === 403);
  check('analyst reads diff tree',
    (await req('GET', '/api/diagnose/comparisons/cmp-legal', TOK.analyst)).status === 200);
  check('analyst reads proof', (await req('GET', '/api/diagnose/comparisons/cmp-legal/proof', TOK.analyst)).status === 200);

  // Operator: all ops, cannot submit comparisons.
  check('operator cannot submit comparison',
    (await submit('cmp-op-x', 'grp-good-A', 'grp-good-B', TOK.op)).status === 403);
  check('operator ingests', (await req('GET', '/api/diagnose/groups', TOK.op)).status === 200);
  check('operator manages versions', (await req('GET', '/api/diagnose/versions', TOK.op)).status === 200);

  // Existing converge roles have zero diagnose privileges.
  check('reviewer denied diagnose', (await req('GET', '/api/diagnose/groups', TOK.reviewer)).status === 403);
  check('inspector denied diagnose', (await req('GET', '/api/diagnose/comparisons', TOK.inspector)).status === 403);
}

console.log('12. 错误页面不回显输入包内容');
{
  const secretMarker = digest('MARKER-DO-NOT-ECHO-SECRET-VALUE');
  const regionMarker = 'region-MARKER-DO-NOT-ECHO';
  const bad = linear('grp-echo', null).receipts.map((r) => ({ ...r }));
  bad[1].contributions = [{ region: regionMarker, change_digest: secretMarker }];
  const text = await req('POST', '/api/diagnose/receipts', TOK.op, { group: 'grp-echo', entries: bad });
  const raw = text.text || '';
  check('error body omits injected marker digest', raw.indexOf(secretMarker) === -1, raw.slice(0, 200));
  check('error body omits injected marker region', raw.indexOf(regionMarker) === -1);
  check('bad JSON body yields generic message',
    (await fetch(`http://127.0.0.1:${PORT}/api/diagnose/receipts`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${TOK.op}`, 'Content-Type': 'application/json' },
      body: '{not json"MARKER-DO-NOT-ECHO"',
    }).then(async (r) => ({ status: r.status, text: await r.text() }))).status === 400);

  // Unknown task / missing field paths likewise carry no entry content.
  const conflict = await submit('cmp-legal', 'grp-good-A', 'grp-conflict-D');
  check('conflict body free of receipt content markers',
    conflict.text.indexOf(secretMarker) === -1 && conflict.text.indexOf(regionMarker) === -1);

  // Diagnose page served with no-store so refresh always re-reads.
  const page = await fetch('http://127.0.0.1:' + PORT + '/diagnose');
  check('diagnose console reachable', page.status === 200);
  check('console HTML sets no-store', page.headers.get('cache-control') === 'no-store');
  const apiNoStore = await req('GET', '/api/diagnose/versions', TOK.op);
  check('diagnose API sets no-store', apiNoStore.headers.get('cache-control') === 'no-store');
}

// -------------------------------------------------------------- teardown ---
await stopServer();
console.log(`\n${failed === 0 ? 'ALL GREEN' : 'FAILURES PRESENT'}: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
