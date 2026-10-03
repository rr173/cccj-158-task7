import fs from 'node:fs';
import { Wal } from './wal.mjs';
import { Mutex } from './mutex.mjs';
import { canonical, digestOf, sign } from './crypto-util.mjs';

/**
 * Causal divergence diagnostician for converge.
 *
 * Two groups of already-desensitised DECISION RECEIPTS are frozen at a
 * server-side read watermark, rebuilt into comparable causal skeletons by their
 * predecessor edges, and compared asynchronously. Output is the first
 * divergence, the affected downstream nodes, and desensitised explanation
 * evidence (the strict receipt schema admits no station id, request key or
 * image content — only pseudonymous digests and synthetic region coordinates).
 *
 * Durability: a dedicated append-only log diagnose.wal (magic 'CD') with these
 * frames:
 *   1  group receipt accepted (watermark stream)
 *   10 task created (frozen inputs, watermarks, pinned algorithm, fingerprints)
 *   11 task phase marker
 *   12 comparison result
 *   13 explanation evidence
 *   14 sealed proof
 *   15 cancellation (only from QUEUED)
 *   16 active algorithm version changed
 *
 * Each work stage appends its product frame and its phase marker in ONE
 * write+fsync batch, so a crash either leaves both (resume past the stage) or
 * neither (torn tail truncation -> stage effectively never started). Evidence
 * is therefore written at most once per task.
 */

export const DIAGNOSE_MAGIC = Buffer.from([0x43, 0x44]); // 'CD'

const T_GROUP_RECEIPT = 1;
const T_TASK = 10;
const T_PHASE = 11;
const T_RESULT = 12;
const T_EVIDENCE = 13;
const T_PROOF = 14;
const T_CANCEL = 15;
const T_ALGO = 16;

export const ALGORITHMS = ['chain-v1', 'topo-v2'];
const DEFAULT_ALGORITHM = 'chain-v1';

const TOKEN_RE = /^[A-Za-z0-9:._-]{1,128}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const DECISION_KINDS = ['accept', 'extend', 'merge', 'adjudicate'];
// The exact set of keys a signed decision receipt may carry. Nothing that can
// hold a station id, request key or image byte is representable.
const RECEIPT_KEYS = ['seq', 'decision_node', 'decision_kind', 'parents', 'contributions', 'prev_receipt', 'hash', 'sig'];
const SIGNED_KEYS = ['seq', 'group', 'decision_node', 'decision_kind', 'parents', 'contributions', 'prev_receipt'];

export class DiagnoseError extends Error {
  constructor(status, code, message, details = undefined) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function nowIso() {
  return new Date().toISOString();
}

// ============================================================ bundle parsing

/**
 * Parse and fully validate one submitted bundle: {group, entries:[receipt...]}.
 * `history` is the already-accepted stream for that group (validated earlier),
 * used when appending a new batch (chain continuation, topology closure).
 *
 * Everything wrong with the bundle is collected as stable reason codes and the
 * WHOLE bundle is rejected by the caller: no diagnosis, no partial append.
 * No receipt content is ever placed in error messages.
 */
export function parseBundle(group, entries, secret, history = []) {
  const reasons = [];
  const err = (code, seq) => reasons.push(seq === undefined ? { code } : { code, seq });

  if (typeof group !== 'string' || !TOKEN_RE.test(group)) {
    throw new DiagnoseError(400, 'DIAG_BAD_BUNDLE', 'group must be a 1-128 char token');
  }
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new DiagnoseError(400, 'DIAG_BAD_BUNDLE', 'entries must be a non-empty array');
  }

  // ---- per-receipt format + digest format + chain signature ---------------
  const bySeq = new Map();
  let malformed = 0;
  for (const r of entries) {
    if (!r || typeof r !== 'object' || Array.isArray(r)) { err('RECEIPT_MALFORMED'); malformed++; continue; }
    const keys = Object.keys(r).sort();
    if (keys.join(',') !== [...RECEIPT_KEYS].sort().join(',')) { err('RECEIPT_MALFORMED', r.seq); malformed++; continue; }

    let seqOk = true;
    if (!Number.isInteger(r.seq) || r.seq < 1) { err('SEQ_MALFORMED'); seqOk = false; }
    if (typeof r.decision_node !== 'string' || !HEX64_RE.test(r.decision_node)) { err('DIGEST_FORMAT', r.seq); }
    if (!DECISION_KINDS.includes(r.decision_kind)) { err('DECISION_KIND_UNKNOWN', r.seq); }
    if (typeof r.hash !== 'string' || !HEX64_RE.test(r.hash)) { err('DIGEST_FORMAT', r.seq); }
    if (typeof r.sig !== 'string' || !HEX64_RE.test(r.sig)) { err('DIGEST_FORMAT', r.seq); }
    if (r.prev_receipt !== null && (typeof r.prev_receipt !== 'string' || !HEX64_RE.test(r.prev_receipt))) {
      err('DIGEST_FORMAT', r.seq);
    }
    if (!Array.isArray(r.parents)) { err('BODY_MALFORMED', r.seq); }
    else {
      if (new Set(r.parents).size !== r.parents.length) err('DUPLICATE_PARENT', r.seq);
      for (const p of r.parents) if (typeof p !== 'string' || !HEX64_RE.test(p)) err('DIGEST_FORMAT', r.seq);
    }
    if (!Array.isArray(r.contributions)) { err('BODY_MALFORMED', r.seq); }
    else {
      const regs = new Set();
      for (const c of r.contributions) {
        if (!c || typeof c !== 'object' || Array.isArray(c)) { err('BODY_MALFORMED', r.seq); continue; }
        if (Object.keys(c).sort().join(',') !== 'change_digest,region') { err('BODY_MALFORMED', r.seq); continue; }
        if (typeof c.region !== 'string' || !TOKEN_RE.test(c.region)) err('REGION_MALFORMED', r.seq);
        else if (regs.has(c.region)) err('DUPLICATE_REGION', r.seq);
        regs.add(c.region);
        if (typeof c.change_digest !== 'string' || !HEX64_RE.test(c.change_digest)) err('DIGEST_FORMAT', r.seq);
      }
    }
    if (seqOk) {
      if (bySeq.has(r.seq)) err('DUPLICATE_SEQ', r.seq);
      bySeq.set(r.seq, r);
    }
  }
  if (malformed) throw bundleRejected(reasons);

  // ---- sequence window + prev-receipt chain linkage -----------------------
  const sorted = [...bySeq.values()].sort((a, b) => a.seq - b.seq);
  const historyLen = history.length; // history is contiguous 1..historyLen
  const historyByHash = new Map(history.map((r) => [r.hash, r]));
  const batchByHash = new Map(sorted.map((r) => [r.hash, r]));

  const expectedStart = historyLen + 1;
  sorted.forEach((r, i) => {
    if (r.seq !== expectedStart + i) { err('SEQ_NOT_CONTIGUOUS', r.seq); return; }
    if (historyByHash.has(r.hash) || (i > 0 && sorted.slice(0, i).some((x) => x.hash === r.hash))) {
      err('DUPLICATE_RECEIPT', r.seq);
    }
    const wantPrev = i === 0 ? (history[history.length - 1]?.hash ?? null) : sorted[i - 1].hash;
    if (r.prev_receipt !== wantPrev) err('CHAIN_BROKEN', r.seq);
  });

  // ---- signature / content hash over every receipt ------------------------
  for (const r of sorted) {
    const fields = signedFields(group, r);
    if (digestOf(fields) !== r.hash) err('RECEIPT_HASH_MISMATCH', r.seq);
    if (sign(secret, fields) !== r.sig) err('RECEIPT_SIG_INVALID', r.seq);
    // The node digest binds the body: the same decision node can never carry
    // two different bodies (here or against history).
    if (digestOf(bodyFields(r)) !== r.decision_node) err('NODE_DIGEST_MISMATCH', r.seq);
  }

  // ---- topology over history + batch: resolved predecessors + acyclic ------
  const all = [...history, ...sorted];
  const nodeToReceipt = new Map();
  for (const r of all) {
    if (!nodeToReceipt.has(r.decision_node)) nodeToReceipt.set(r.decision_node, r);
  }
  const indegree = new Map();
  const children = new Map();
  for (const r of all) {
    indegree.set(r.decision_node, (indegree.get(r.decision_node) || 0));
    for (const p of r.parents) {
      if (!nodeToReceipt.has(p)) { err('UNRESOLVED_PREDECESSOR', r.seq); continue; }
      indegree.set(r.decision_node, (indegree.get(r.decision_node) || 0) + 1);
      if (!children.has(p)) children.set(p, []);
      children.get(p).push(r.decision_node);
    }
  }
  // Kahn: any node left after draining closes a cycle.
  const queue = [];
  for (const [node, d] of indegree) if (d === 0) queue.push(node);
  queue.sort();
  let visited = 0;
  while (queue.length) {
    const n = queue.shift();
    visited++;
    for (const c of [...(children.get(n) || [])].sort()) {
      indegree.set(c, indegree.get(c) - 1);
      if (indegree.get(c) === 0) queue.push(c);
    }
  }
  if (visited !== indegree.size) err('TOPOLOGY_CYCLE');

  if (reasons.length) throw bundleRejected(reasons);
  return sorted;
}

function bundleRejected(reasons) {
  return new DiagnoseError(400, 'DIAG_BAD_BUNDLE', 'receipt bundle rejected; no diagnosis produced', {
    reasons: dedupeReasons(reasons),
  });
}
function dedupeReasons(reasons) {
  const seen = new Set();
  const out = [];
  for (const r of reasons) {
    const k = JSON.stringify(r);
    if (!seen.has(k)) { seen.add(k); out.push(r); }
  }
  return out;
}

function bodyFields(r) {
  return { decision_kind: r.decision_kind, parents: r.parents, contributions: r.contributions };
}
function signedFields(group, r) {
  return {
    seq: r.seq, group, decision_node: r.decision_node, decision_kind: r.decision_kind,
    parents: r.parents, contributions: r.contributions, prev_receipt: r.prev_receipt,
  };
}

/** Sign one decision receipt the way the reporting pipeline would. */
export function sealReceipt(secret, group, r) {
  const fields = signedFields(group, r);
  const hash = digestOf(fields);
  return { ...r, hash, sig: sign(secret, fields) };
}

// ================================================================ skeletons

/**
 * Build a causal skeleton from a validated receipt stream (sorted by seq).
 * Nodes are keyed by decision_node (a repeated identical node collapses to
 * one vertex; its first receipt position anchors chain order).
 */
export function buildSkeleton(receipts) {
  const nodes = new Map(); // node -> {parents, body, seq}
  receipts.forEach((r) => {
    if (!nodes.has(r.decision_node)) {
      nodes.set(r.decision_node, {
        node: r.decision_node,
        parents: [...r.parents],
        decision_kind: r.decision_kind,
        contributions: r.contributions.map((c) => ({ ...c })),
        seq: r.seq,
      });
    }
  });
  const children = new Map();
  for (const n of nodes.values()) {
    for (const p of n.parents) {
      if (!nodes.has(p)) continue;
      if (!children.has(p)) children.set(p, []);
      children.get(p).push(n.node);
    }
  }
  const level = new Map();
  const computeLevel = (n) => {
    if (level.has(n)) return level.get(n);
    const parents = [...nodes.get(n).parents].filter((p) => nodes.has(p));
    const v = parents.length ? 1 + Math.max(...parents.map(computeLevel)) : 0;
    level.set(n, v);
    return v;
  };
  for (const n of nodes.keys()) computeLevel(n);

  // v1: receipt chain order; v2: topological order (longest-path level, then
  // node digest ascending — order independent of receipt arrival sequence).
  const chainOrder = [...nodes.values()].sort((a, b) =>
    (a.seq - b.seq) || (a.node < b.node ? -1 : a.node > b.node ? 1 : 0)).map((n) => n.node);
  const topoOrder = [...nodes.values()].sort((a, b) =>
    (level.get(a.node) - level.get(b.node)) ||
    (a.node < b.node ? -1 : a.node > b.node ? 1 : 0)).map((n) => n.node);

  return { nodes, children, level, chainOrder, topoOrder };
}

function descendants(skeleton, node) {
  const out = [];
  const seen = new Set();
  const queue = [...(skeleton.children.get(node) || [])];
  while (queue.length) {
    const n = queue.shift();
    if (seen.has(n)) continue;
    seen.add(n);
    out.push(n);
    for (const c of skeleton.children.get(n) || []) queue.push(c);
  }
  const lvl = skeleton.level;
  return out.sort((a, b) =>
    (lvl.get(a) - lvl.get(b)) || (a < b ? -1 : a > b ? 1 : 0));
}

function lcsAlign(a, b) {
  // Classic LCS table; returns the aligned walk as steps
  // {op:'match'|'only_left'|'only_right', node, indexA, indexB}.
  const n = a.length;
  const m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j]
        ? dp[i + 1][j + 1] + 1
        : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const steps = [];
  let i = 0;
  let j = 0;
  while (i < n || j < m) {
    if (i < n && j < m && a[i] === b[j]) { steps.push({ op: 'match', node: a[i], indexA: i, indexB: j }); i++; j++; }
    else if (j === m || (i < n && dp[i + 1][j] >= dp[i][j + 1])) { steps.push({ op: 'only_left', node: a[i], indexA: i, indexB: j - 1 }); i++; }
    else { steps.push({ op: 'only_right', node: b[j], indexA: i - 1, indexB: j }); j++; }
  }
  return steps;
}

/**
 * Compare two skeletons under the pinned algorithm version. Returns the FIRST
 * divergence only (later ones are causally downstream of it) plus the affected
 * downstream closure on each side.
 */
export function compareSkeletons(skelA, skelB, algorithm) {
  const orderFor = (s) => (algorithm === 'topo-v2' ? s.topoOrder : s.chainOrder);
  const a = orderFor(skelA);
  const b = orderFor(skelB);
  const steps = algorithm === 'topo-v2' ? lcsAlign(a, b) : null;

  let divergence = null;
  if (algorithm === 'topo-v2') {
    const first = steps.find((s) => s.op !== 'match');
    if (first) {
      if (first.op === 'only_left') {
        divergence = { kind: 'only_in_left', index: first.indexA, left_node: first.node, right_node: null };
      } else {
        divergence = { kind: 'only_in_right', index: first.indexB, left_node: null, right_node: first.node };
      }
    }
  } else {
    const len = Math.max(a.length, b.length);
    for (let i = 0; i < len && !divergence; i++) {
      if (i >= a.length) divergence = { kind: 'only_in_right', index: i, left_node: null, right_node: b[i] };
      else if (i >= b.length) divergence = { kind: 'only_in_left', index: i, left_node: a[i], right_node: null };
      else if (a[i] !== b[i]) divergence = { kind: 'node_mismatch', index: i, left_node: a[i], right_node: b[i] };
    }
  }

  let downstream = { left: [], right: [] };
  if (divergence) {
    downstream = {
      left: divergence.left_node ? descendants(skelA, divergence.left_node) : [],
      right: divergence.right_node ? descendants(skelB, divergence.right_node) : [],
    };
  }
  return { algorithm, converged: divergence === null, divergence, downstream };
}

// ================================================================ evidence

function evidenceRow(role, side, node, skeleton) {
  const n = skeleton.nodes.get(node);
  return {
    role, side, node,
    decision_kind: n.decision_kind,
    parents: [...n.parents],
    contributions: n.contributions.map((c) => ({ ...c })),
  };
}

/**
 * Deterministic explanation nodes: divergence vertex (vertices) first, then
 * affected downstream vertices per side. Strictly desensitised — the receipt
 * schema contains no station / request key / image field to leak.
 */
export function buildEvidence(comparison, skelA, skelB) {
  const rows = [];
  const d = comparison.divergence;
  if (!d) return rows;
  if (d.left_node) rows.push(evidenceRow('divergence', 'left', d.left_node, skelA));
  if (d.right_node) rows.push(evidenceRow('divergence', 'right', d.right_node, skelB));
  for (const n of comparison.downstream.left) rows.push(evidenceRow('downstream', 'left', n, skelA));
  for (const n of comparison.downstream.right) rows.push(evidenceRow('downstream', 'right', n, skelB));
  return rows;
}

// ============================================================= manager

export class DiagnoseManager {
  constructor(config) {
    this.config = config;
    this.wal = new Wal(config.diagnoseWalPath, DIAGNOSE_MAGIC);
    this.lock = new Mutex();
    this.groups = new Map(); // group -> receipts[] (contiguous seq from 1)
    this.tasks = new Map(); // task_key -> doc
    this.activeAlgorithm = DEFAULT_ALGORITHM;
    this._timer = null;
  }

  // ------------------------------------------------------------- lifecycle --

  open() {
    this.wal.open();
    const { events, truncatedBytes } = this.wal.readAll();
    if (truncatedBytes > 0) {
      // Torn stage batch (process died mid write): drop it; the phase marker
      // went down with the product frame, so work resumes from the last
      // durable phase (or never started).
      const { size } = fs.statSync(this.config.diagnoseWalPath);
      this.wal.truncate(size - truncatedBytes);
    }
    for (const ev of events) this._replay(ev.type, ev.payload);
    this._startPump();
  }

  close() {
    if (this._timer) clearInterval(this._timer);
    this._timer = null;
    this.wal.close();
  }

  _replay(type, payloadBuf) {
    const ev = JSON.parse(payloadBuf.toString('utf8'));
    if (type === T_GROUP_RECEIPT) {
      const list = this.groups.get(ev.group) || [];
      list.push(ev.receipt);
      this.groups.set(ev.group, list);
      return;
    }
    if (type === T_ALGO) { this.activeAlgorithm = ev.active; return; }
    if (type === T_TASK) {
      this.tasks.set(ev.task_key, {
        key: ev.task_key,
        groups: [ev.left_group, ev.right_group],
        left_group: ev.left_group,
        right_group: ev.right_group,
        watermarks: ev.watermarks,
        algorithm: ev.algorithm,
        fingerprints: ev.fingerprints,
        created_at: ev.created_at,
        sealed_at: null,
        phase: 'queued',
        result: null,
        evidence: null,
        proof: null,
      });
      return;
    }
    const doc = this.tasks.get(ev.task_key);
    if (!doc) return; // defensively ignore frames for an unknown task
    if (type === T_PHASE) doc.phase = ev.phase;
    else if (type === T_RESULT) doc.result = ev.result;
    else if (type === T_EVIDENCE) doc.evidence = ev.evidence;
    else if (type === T_PROOF) { doc.proof = ev.proof; doc.sealed_at = ev.proof.sealed_at; }
    else if (type === T_CANCEL) doc.phase = 'canceled';
  }

  _startPump() {
    const ms = this.config.diagnosePumpMs ?? 250;
    if (ms > 0) {
      this._timer = setInterval(() => { this.pumpCycle().catch(() => {}); }, ms);
      this._timer.unref?.();
    }
  }

  // -------------------------------------------------------------- ingest ----

  /**
   * Operator intake for one batch of signed receipts. The whole batch is
   * validated (chain signature against current head, digest format, topology)
   * before ANY frame is appended, so a broken batch changes no watermark.
   */
  async appendReceipts(body) {
    return this.lock.runExclusive(() => {
      const group = body?.group;
      const history = this.groups.get(group) || [];
      const accepted = parseBundle(group, body?.entries, this.config.receiptSecret, history);
      const frames = accepted.map((r) => [T_GROUP_RECEIPT, JSON.stringify({ group, receipt: r })]);
      this.wal.appendBatch(frames);
      this.groups.set(group, [...history, ...accepted]);
      return {
        group,
        accepted: accepted.length,
        watermark: (this.groups.get(group)).length,
        head_receipt: accepted[accepted.length - 1].hash,
      };
    });
  }

  async listGroups() {
    return this.lock.runExclusive(() =>
      [...this.groups.entries()]
        .map(([group, receipts]) => ({
          group,
          watermark: receipts.length,
          head_receipt: receipts[receipts.length - 1]?.hash ?? null,
        }))
        .sort((x, y) => (x.group < y.group ? -1 : 1)));
  }

  // --------------------------------------------------------- submissions ----

  _fingerprint(group, receipts) {
    return digestOf({ group, receipts: receipts.map((r) => r.hash) });
  }

  /**
   * Fix BOTH inputs server-side: current watermark (head seq) per group and the
   * active comparison algorithm are pinned at creation. Same task key + same
   * inputs returns the original task; same key + any changed input conflicts;
   * the mutex makes concurrent submissions of one comparison collapse to the
   * single existing task.
   */
  async submitComparison(body) {
    return this.lock.runExclusive(() => this._submitLocked(body));
  }

  _submitLocked(body) {
    const key = body?.task_key;
    if (typeof key !== 'string' || !TOKEN_RE.test(key)) {
      throw new DiagnoseError(400, 'DIAG_BAD_REQUEST', 'task_key must be a 1-128 char token');
    }
    for (const side of ['left_group', 'right_group']) {
      if (typeof body[side] !== 'string' || !TOKEN_RE.test(body[side])) {
        throw new DiagnoseError(400, 'DIAG_BAD_REQUEST', `${side} must be a 1-128 char token`);
      }
    }
    if (body.left_group === body.right_group) {
      throw new DiagnoseError(400, 'DIAG_BAD_REQUEST', 'left_group and right_group must differ');
    }
    const left = this.groups.get(body.left_group);
    const right = this.groups.get(body.right_group);
    if (!left || !right || !left.length || !right.length) {
      throw new DiagnoseError(404, 'DIAG_GROUP_EMPTY', 'both groups must carry receipts at or before the watermark');
    }

    const fingerprints = {
      left: this._fingerprint(body.left_group, left),
      right: this._fingerprint(body.right_group, right),
    };

    const existing = this.tasks.get(key);
    if (existing) {
      if (existing.fingerprints.left !== fingerprints.left ||
        existing.fingerprints.right !== fingerprints.right) {
        // An existing diagnosis must never be silently overwritten.
        throw new DiagnoseError(409, 'TASK_INPUT_CONFLICT',
          'task key already exists with different inputs', {
            task_key: key,
            existing_phase: existing.phase,
            existing_watermarks: existing.watermarks,
          });
      }
      return { status: 200, reused: true, task: this._view(existing, false) };
    }

    const watermarks = { left: left.length, right: right.length };
    const created = nowIso();
    const doc = {
      key,
      groups: [body.left_group, body.right_group],
      left_group: body.left_group,
      right_group: body.right_group,
      watermarks,
      algorithm: this.activeAlgorithm,
      fingerprints,
      created_at: created,
      sealed_at: null,
      phase: 'queued',
      result: null,
      evidence: null,
      proof: null,
    };
    this.wal.append(T_TASK, JSON.stringify({
      task_key: key,
      left_group: body.left_group,
      right_group: body.right_group,
      watermarks,
      algorithm: doc.algorithm,
      fingerprints,
      created_at: created,
    }));
    this.tasks.set(key, doc);
    return { status: 201, reused: false, task: this._view(doc, false) };
  }

  async listComparisons() {
    return this.lock.runExclusive(() =>
      [...this.tasks.values()].sort((a, b) => (a.created_at < b.created_at ? -1 : 1))
        .map((d) => this._view(d, false)));
  }

  async getComparison(key) {
    return this.lock.runExclusive(() => {
      const doc = this.tasks.get(key);
      if (!doc) throw new DiagnoseError(404, 'TASK_NOT_FOUND', 'unknown comparison task');
      return this._view(doc, true);
    });
  }

  // ------------------------------------------------------------ cancelling --

  /**
   * Only a not-started task can be canceled (resource release). Running and
   * sealed tasks reject deterministically; under the mutex exactly one of two
   * concurrent cancels can win the queued -> canceled transition.
   */
  async cancelComparison(key) {
    return this.lock.runExclusive(() => {
      const doc = this.tasks.get(key);
      if (!doc) throw new DiagnoseError(404, 'TASK_NOT_FOUND', 'unknown comparison task');
      if (doc.phase === 'canceled') {
        throw new DiagnoseError(409, 'TASK_ALREADY_CANCELED', 'task was already canceled', { phase: doc.phase });
      }
      if (doc.phase !== 'queued') {
        throw new DiagnoseError(409, 'TASK_NOT_CANCELLABLE',
          'only a not-started task can be canceled', { phase: doc.phase });
      }
      this.wal.append(T_CANCEL, JSON.stringify({ task_key: key, canceled_at: nowIso() }));
      doc.phase = 'canceled';
      return { task_key: key, phase: 'canceled' };
    });
  }

  // ------------------------------------------------------------ versions ----

  async versions() {
    return this.lock.runExclusive(() => ({
      active: this.activeAlgorithm,
      available: [...ALGORITHMS],
      pinning: 'algorithm is pinned per task at creation; switching affects later tasks only',
    }));
  }

  async activateAlgorithm(version) {
    return this.lock.runExclusive(() => {
      if (!ALGORITHMS.includes(version)) {
        throw new DiagnoseError(400, 'DIAG_BAD_REQUEST', 'unknown algorithm version', { available: [...ALGORITHMS] });
      }
      const previous = this.activeAlgorithm;
      if (previous !== version) {
        this.wal.append(T_ALGO, JSON.stringify({ active: version, previous, changed_at: nowIso() }));
        this.activeAlgorithm = version;
      }
      return { active: this.activeAlgorithm, previous, in_flight_keep: 'tasks already created keep their pinned version' };
    });
  }

  // -------------------------------------------------------------- worker ----

  /** Drive processing deterministically (tests set pump interval to 0). */
  async pumpCycle(maxTasks = 1000) {
    return this.lock.runExclusive(() => {
      const processed = [];
      for (let i = 0; i < maxTasks; i++) {
        const doc = [...this.tasks.values()]
          .find((d) => d.phase === 'queued' || d.phase === 'skeletons_built' ||
            d.phase === 'diffed' || d.phase === 'evidence_written');
        if (!doc) break;
        processed.push(this._process(doc));
      }
      return { processed };
    });
  }

  /**
   * Resume semantics: every durable phase is a commit point the worker skips;
   * a crash before the first marker leaves the task at 'queued' (not started).
   */
  _process(doc) {
    const crash = this.config.diagnoseCrashPoint || null;

    const leftAll = this.groups.get(doc.left_group);
    const rightAll = this.groups.get(doc.right_group);
    // Watermark boundary: receipts arriving after the frozen read must never
    // enter the computation.
    const left = leftAll.slice(0, doc.watermarks.left);
    const right = rightAll.slice(0, doc.watermarks.right);

    let skelA = null;
    let skelB = null;
    if (doc.phase === 'queued') {
      if (crash === 'before_start') process.exit(17);
      // Frozen inputs are re-validated before use; a sealed task is impossible
      // to tamper with via later intake anyway (fingerprint pinned).
      parseBundle(doc.left_group, left, this.config.receiptSecret, []);
      parseBundle(doc.right_group, right, this.config.receiptSecret, []);
      skelA = buildSkeleton(left);
      skelB = buildSkeleton(right);
      this.wal.append(T_PHASE, JSON.stringify({ task_key: doc.key, phase: 'skeletons_built', at: nowIso() }));
      doc.phase = 'skeletons_built';
    }

    if (doc.phase === 'skeletons_built') {
      skelA = buildSkeleton(left);
      skelB = buildSkeleton(right);
      const result = compareSkeletons(skelA, skelB, doc.algorithm);
      this.wal.appendBatch([
        [T_RESULT, JSON.stringify({ task_key: doc.key, result })],
        [T_PHASE, JSON.stringify({ task_key: doc.key, phase: 'diffed', at: nowIso() })],
      ]);
      doc.result = result;
      doc.phase = 'diffed';
      if (crash === 'after_diff') process.exit(17);
    }

    if (doc.phase === 'diffed') {
      skelA = buildSkeleton(left);
      skelB = buildSkeleton(right);
      // Phase-guarded: a resumed task never reaches this write twice.
      const evidence = buildEvidence(doc.result, skelA, skelB);
      this.wal.appendBatch([
        [T_EVIDENCE, JSON.stringify({ task_key: doc.key, evidence })],
        [T_PHASE, JSON.stringify({ task_key: doc.key, phase: 'evidence_written', at: nowIso() })],
      ]);
      doc.evidence = evidence;
      doc.phase = 'evidence_written';
      if (crash === 'after_evidence') process.exit(17);
    }

    if (doc.phase === 'evidence_written') {
      const sealedAt = nowIso();
      const proof = this._sealProof(doc, sealedAt);
      this.wal.appendBatch([
        [T_PROOF, JSON.stringify({ task_key: doc.key, proof })],
        [T_PHASE, JSON.stringify({ task_key: doc.key, phase: 'sealed', at: sealedAt })],
      ]);
      doc.proof = proof;
      doc.sealed_at = sealedAt;
      doc.phase = 'sealed';
    }

    return { task_key: doc.key, phase: doc.phase };
  }

  // ---------------------------------------------------------------- proofs --

  _sealProof(doc, sealedAt) {
    const evidenceDigest = digestOf(doc.evidence || []);
    const root = {
      format: 'converge-diagnosis-proof/v1',
      task_key: doc.key,
      groups: [doc.left_group, doc.right_group],
      algorithm: doc.algorithm,
      watermarks: doc.watermarks,
      input_fingerprints: doc.fingerprints,
      comparison: {
        converged: doc.result.converged,
        divergence: doc.result.divergence,
        downstream: doc.result.downstream,
      },
      evidence: doc.evidence || [],
      evidence_digest: evidenceDigest,
      sealed_at: sealedAt,
    };
    return { ...root, digest: digestOf(root), sig: sign(this.config.receiptSecret, root) };
  }

  async getProof(key) {
    return this.lock.runExclusive(() => {
      const doc = this.tasks.get(key);
      if (!doc) throw new DiagnoseError(404, 'TASK_NOT_FOUND', 'unknown comparison task');
      if (doc.phase !== 'sealed' || !doc.proof) {
        throw new DiagnoseError(409, 'PROOF_NOT_SEALED', 'task has no sealed proof yet', { phase: doc.phase });
      }
      // Deliver only after re-verifying the stored seal.
      verifyProof(doc.proof, this.config.receiptSecret, { allowUnsealedShape: false });
      return { proof: doc.proof, verification: { ok: true, verified_at: nowIso() } };
    });
  }

  // ----------------------------------------------------------------- views --

  _skeletonView(group, receipts) {
    const skel = buildSkeleton(receipts);
    return {
      group,
      order: skel.chainOrder,
      topo_order: skel.topoOrder,
      nodes: [...skel.nodes.values()].map((n) => ({
        node: n.node, parents: [...n.parents], level: skel.level.get(n.node),
        decision_kind: n.decision_kind, contributions: n.contributions,
      })),
    };
  }

  _view(doc, detail) {
    const out = {
      task_key: doc.key,
      groups: [doc.left_group, doc.right_group],
      left_group: doc.left_group,
      right_group: doc.right_group,
      phase: doc.phase,
      algorithm: doc.algorithm,
      watermarks: doc.watermarks,
      input_fingerprints: doc.fingerprints,
      created_at: doc.created_at,
      sealed_at: doc.sealed_at,
      converged: doc.result ? doc.result.converged : null,
      divergence: doc.result ? doc.result.divergence : null,
      downstream: doc.result ? doc.result.downstream : null,
      evidence_count: doc.evidence ? doc.evidence.length : 0,
      proof_digest: doc.proof ? doc.proof.digest : null,
    };
    if (detail) {
      const leftAll = this.groups.get(doc.left_group) || [];
      const rightAll = this.groups.get(doc.right_group) || [];
      out.skeletons = {
        left: this._skeletonView(doc.left_group, leftAll.slice(0, doc.watermarks.left)),
        right: this._skeletonView(doc.right_group, rightAll.slice(0, doc.watermarks.right)),
      };
      out.evidence = doc.evidence;
    }
    return out;
  }
}

/**
 * Verify a (possibly external / tampered) proof. Layered checks return stable
 * reason codes; the proof carries no station id / request key / image content.
 */
export function verifyProof(proof, secret) {
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
    throw new DiagnoseError(400, 'DIAG_PROOF_MALFORMED', 'proof must be an object');
  }
  const rootKeys = ['format', 'task_key', 'groups', 'algorithm', 'watermarks',
    'input_fingerprints', 'comparison', 'evidence', 'evidence_digest', 'sealed_at'];
  for (const k of rootKeys) if (!(k in proof)) {
    throw new DiagnoseError(422, 'DIAG_PROOF_MALFORMED', `missing field ${k}`);
  }
  if (proof.format !== 'converge-diagnosis-proof/v1') {
    throw new DiagnoseError(422, 'DIAG_PROOF_FORMAT_UNKNOWN', 'unknown proof format');
  }
  if (!ALGORITHMS.includes(proof.algorithm)) {
    throw new DiagnoseError(422, 'DIAG_PROOF_FORMAT_UNKNOWN', 'unknown algorithm in proof');
  }

  // Layer 1: evidence list still hashes to its claimed root digest.
  if (digestOf(proof.evidence || []) !== proof.evidence_digest) {
    throw new DiagnoseError(422, 'DIAG_PROOF_EVIDENCE_MISMATCH', 'evidence digest does not match evidence nodes');
  }
  // Layer 2: divergence/downstream must cite the evidence nodes present.
  const evidenceNodes = new Set((proof.evidence || []).map((e) => e?.node).filter(Boolean));
  const d = proof.comparison?.divergence;
  if (!proof.comparison || typeof proof.comparison.converged !== 'boolean') {
    throw new DiagnoseError(422, 'DIAG_PROOF_ROOT_MISMATCH', 'comparison section invalid');
  }
  if (d) {
    const cited = [d.left_node, d.right_node,
      ...(proof.comparison.downstream?.left || []),
      ...(proof.comparison.downstream?.right || [])].filter(Boolean);
    for (const n of cited) {
      if (!evidenceNodes.has(n)) throw new DiagnoseError(422, 'DIAG_PROOF_ROOT_MISMATCH', 'cited node missing from evidence');
    }
  }
  // Layer 3: root digest.
  const root = Object.fromEntries(rootKeys.map((k) => [k, proof[k]]));
  if (digestOf(root) !== proof.digest) {
    throw new DiagnoseError(422, 'DIAG_PROOF_DIGEST_MISMATCH', 'proof digest does not match its contents');
  }
  // Layer 4: server HMAC over the same root.
  if (sign(secret, root) !== proof.sig) {
    throw new DiagnoseError(422, 'DIAG_PROOF_SIG_INVALID', 'proof signature is invalid');
  }
  return {
    ok: true,
    task_key: proof.task_key,
    algorithm: proof.algorithm,
    converged: proof.comparison.converged,
    watermarks: proof.watermarks,
    evidence_count: (proof.evidence || []).length,
    evidence_digest: proof.evidence_digest,
  };
}
