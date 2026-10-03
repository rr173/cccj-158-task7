import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { constantTimeEqual } from './crypto-util.mjs';
import { loadConfig } from './config.mjs';
import { ConvergenceStore, ApiError } from './store.mjs';
import { DiagnoseManager, DiagnoseError, verifyProof } from './diagnose.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const MAX_BODY = 1024 * 1024;

/** role -> allowed (method, route). Prefix entries end with '/'. */
const POLICY = {
  operator: [
    'POST /api/envelopes',
    'POST /api/envelopes/digest',
    'GET /api/objects',
    'GET /api/objects/',
    'GET /api/cases',
    'GET /api/cases/',
    'GET /api/receipts',
    'GET /api/receipts/',
    'POST /api/receipts/verify',
    'POST /api/archive/checkpoints',
    'POST /api/archive/restore',
    'GET /api/archive/status',
    'GET /api/archive/proofs',
    'GET /api/archive/segments/',
  ],
  reviewer: [
    'GET /api/objects',
    'GET /api/objects/',
    'GET /api/cases',
    'GET /api/cases/',
    'POST /api/reviews/',
    'GET /api/receipts',
    'GET /api/receipts/',
    'POST /api/receipts/verify',
    'GET /api/archive/status',
  ],
  // Inspectors never see station ids, request keys or sequences: only the
  // desensitised receipt stream, integrity verification and desensitised
  // archive proofs. They can never start a compression or a restore.
  inspector: [
    'GET /api/receipts',
    'GET /api/receipts/',
    'POST /api/receipts/verify',
    'GET /api/archive/proofs',
    'GET /api/archive/segments/',
    'GET /api/subscriptions/proofs',
  ],
  // Administrators own the downstream subscription lifecycle (callback
  // registration, pause/resume, signing-key rotation, dead-letter resend). They
  // may also read the operational views; the inspector-safe proofs remain the
  // only thing an inspector can read about notifications.
  admin: [
    'GET /api/objects',
    'GET /api/objects/',
    'GET /api/cases',
    'GET /api/cases/',
    'GET /api/receipts',
    'GET /api/receipts/',
    'POST /api/receipts/verify',
    'GET /api/archive/status',
    'GET /api/archive/proofs',
    'GET /api/archive/segments/',
    'POST /api/subscriptions',
    'GET /api/subscriptions',
    'GET /api/subscriptions/',
    'POST /api/subscriptions/pump',
  ],
};

/** Exact admin-only mutating actions (beyond the prefix policy). */
const ADMIN_SUB_ACTIONS = new Set(['pause', 'resume', 'rotate-key', 'redeliver']);

function isAdminSubPath(pathname) {
  return /^\/api\/subscriptions\/[^/]+\/(pause|resume|rotate-key|redeliver)$/.test(pathname);
}
function isInspectorProofPath(pathname) {
  return pathname === '/api/subscriptions/proofs' ||
    /^\/api\/subscriptions\/[^/]+\/proofs$/.test(pathname);
}

function routeAllowed(role, method, pathname) {
  const key = `${method} ${pathname}`;
  if (role === 'inspector' && method === 'GET' && /^\/api\/objects\/[^/]+\/receipts\/download$/.test(pathname)) return true;
  // The raw (identity-bearing) segment dump is operator-only; /pack and /proof
  // are the desensitised inspector-safe routes on the same prefix.
  if (role !== 'operator' && role !== 'admin' && /^\/api\/archive\/segments\/[^/]+\/raw$/.test(pathname)) return false;

  // Reliable subscriptions:
  //  - admin manages subscriptions and resends dead letters
  //  - operator sees only the operational status (read-only)
  //  - inspector reads only desensitised notification proofs
  if (pathname.startsWith('/api/subscriptions')) {
    if (pathname === '/api/subscriptions/pump') return role === 'admin' && method === 'POST';
    if (pathname === '/api/subscriptions/proofs') return role === 'inspector' && method === 'GET';
    if (/^\/api\/subscriptions\/[^/]+\/proofs$/.test(pathname)) return role === 'inspector' && method === 'GET';
    if (isAdminSubPath(pathname)) return role === 'admin' && method === 'POST';
    if (pathname === '/api/subscriptions') {
      if (method === 'POST') return role === 'admin';
      if (method === 'GET') return role === 'admin' || role === 'operator';
      return false;
    }
    if (/^\/api\/subscriptions\/[^/]+$/.test(pathname)) {
      return method === 'GET' && (role === 'admin' || role === 'operator');
    }
    if (/^\/api\/subscriptions\/[^/]+\/items$/.test(pathname)) {
      return method === 'GET' && role === 'admin';
    }
    return false;
  }

  return POLICY[role].some((p) => {
    const [pm, pp] = p.split(' ');
    if (pm !== method) return false;
    if (pp.endsWith('/')) return pathname.startsWith(pp);
    return pathname === pp;
  });
}

export function createServer(config = loadConfig()) {
  const store = new ConvergenceStore(config);
  store.open();
  const diagnose = new DiagnoseManager(config);
  diagnose.open();

  const server = http.createServer(async (req, res) => {
    try {
      await handle(req, res, config, store, diagnose);
    } catch (err) {
      sendError(res, err);
    }
  });

  server.on('close', () => { diagnose.close(); store.close(); });
  return { server, store, diagnose };
}

async function handle(req, res, config, store, diagnose) {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname;

  if (pathname === '/healthz') return sendJson(res, 200, { ok: true });
  if (pathname === '/' || pathname === '/console' || pathname === '/index.html') {
    return serveFile(res, path.join(PUBLIC_DIR, 'index.html'), 'text/html; charset=utf-8');
  }
  if (pathname === '/app.js') return serveFile(res, path.join(PUBLIC_DIR, 'app.js'), 'application/javascript; charset=utf-8');
  if (pathname === '/diagnose' || pathname === '/diagnose.html') {
    return serveFile(res, path.join(PUBLIC_DIR, 'diagnose.html'), 'text/html; charset=utf-8', true);
  }
  if (pathname === '/diagnose.js') {
    return serveFile(res, path.join(PUBLIC_DIR, 'diagnose.js'), 'application/javascript; charset=utf-8', true);
  }
  if (pathname.startsWith('/api/')) return handleApi(req, res, url, config, store, diagnose);
  sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'not found' } });
}

function authenticate(req, config) {
  const header = req.headers.authorization || '';
  const m = /^Bearer (.+)$/.exec(header);
  if (!m) throw new ApiError(401, 'UNAUTHENTICATED', 'bearer token required');
  const token = m[1];
  let matchedRole = null;
  for (const [known, role] of Object.entries(config.tokens)) {
    if (constantTimeEqual(token, known)) {
      matchedRole = role;
      break;
    }
  }
  if (!matchedRole) throw new ApiError(403, 'FORBIDDEN', 'token not recognized');
  const reviewerName = config.reviewerIdentities[token] || null;
  return { role: matchedRole, reviewerId: reviewerName ? `anon-${matchedRole}-${reviewerName.slice(-2)}` : null, reviewerName };
}

async function handleApi(req, res, url, config, store, diagnose) {
  const auth = authenticate(req, config);

  // Role self-identification for the console: any authenticated token may ask
  // who it is (needed because admin and operator share most read routes, so the
  // UI cannot reliably infer the role from a single probe).
  if (url.pathname === '/api/whoami' && req.method === 'GET') {
    return sendJson(res, 200, { role: auth.role, reviewer_id: auth.reviewerId, reviewer_name: auth.reviewerName });
  }

  // ----------------------------------------------- causal divergence diagnose
  // Dedicated three-tier visibility:
  //   operator/admin  intake, algorithm versions, cancel, worker pump, reads
  //   analyst         choose two groups, submit comparisons, read diff tree +
  //                   desensitised evidence
  //   observer        verify/inspect sealed proofs only (never chooses inputs,
  //                   sees no watermark table or skeleton beyond a proof)
  if (url.pathname.startsWith('/api/diagnose')) {
    return handleDiagnoseApi(req, res, url, config, auth, diagnose);
  }

  if (!routeAllowed(auth.role, req.method, url.pathname)) {
    throw new ApiError(403, 'ROLE_NOT_PERMITTED', `${auth.role} may not ${req.method} ${url.pathname}`);
  }

  const body = req.method === 'POST' ? await readJson(req) : null;
  const p = url.pathname;

  if (p === '/api/envelopes' && req.method === 'POST') {
    const result = await store.submitEnvelope(body);
    return sendJson(res, 200, result);
  }
  if (p === '/api/envelopes/digest' && req.method === 'POST') {
    return sendJson(res, 200, await store.previewEnvelopeDigest(body));
  }
  if (p === '/api/objects' && req.method === 'GET') {
    return sendJson(res, 200, { objects: await store.listObjects() });
  }
  if (p === '/api/cases' && req.method === 'GET') {
    return sendJson(res, 200, { cases: await store.listCases() });
  }
  if (p === '/api/receipts' && req.method === 'GET') {
    const objectKey = url.searchParams.get('object_key') || null;
    return sendJson(res, 200, { receipts: await store.listReceipts(objectKey) });
  }
  if (p === '/api/receipts/verify' && req.method === 'POST') {
    return sendJson(res, 200, await store.verifyReceipt(body?.receipt ?? body));
  }

  // ------------------------------------------------- history compression ----
  if (p === '/api/archive/checkpoints' && req.method === 'POST') {
    return sendJson(res, 200, await store.createCheckpoint(body));
  }
  if (p === '/api/archive/restore' && req.method === 'POST') {
    return sendJson(res, 200, await store.restoreObject(body));
  }
  if (p === '/api/archive/status' && req.method === 'GET') {
    return sendJson(res, 200, await store.archiveStatus());
  }
  if (p === '/api/archive/proofs' && req.method === 'GET') {
    return sendJson(res, 200, { proofs: await store.listProofs() });
  }

  // --------------------------------------------- reliable subscriptions ----
  if (p === '/api/subscriptions' && req.method === 'POST') {
    return sendJson(res, 200, await store.outbox.createSubscription(body));
  }
  if (p === '/api/subscriptions' && req.method === 'GET') {
    return sendJson(res, 200, { subscriptions: await store.outbox.listSubscriptions() });
  }
  if (p === '/api/subscriptions/pump' && req.method === 'POST') {
    // Admin-triggered delivery cycle (deterministic for ops/tests). Runs
    // entirely outside the business mutex: callbacks can never block the
    // convergence API.
    const target = body?.subscription_id || null;
    const result = target
      ? await store.outbox.pumpSubscription(target)
      : (await Promise.all((await store.outbox.pumpAllSubscriptions())));
    return sendJson(res, 200, target ? result : { results: result });
  }
  if (p === '/api/subscriptions/proofs' && req.method === 'GET') {
    return sendJson(res, 200, { subscriptions: await store.outbox.listProofs() });
  }

  let subMatch;
  if ((subMatch = /^\/api\/subscriptions\/([^/]+)\/(pause|resume|rotate-key|redeliver)$/.exec(p)) && req.method === 'POST') {
    const [, id, action] = subMatch;
    if (action === 'pause') return sendJson(res, 200, await store.outbox.pauseSubscription(id));
    if (action === 'resume') return sendJson(res, 200, await store.outbox.resumeSubscription(id));
    if (action === 'rotate-key') return sendJson(res, 200, await store.outbox.rotateKey(id, body));
    const eventSeq = body?.event_seq;
    if (!Number.isInteger(eventSeq)) throw Object.assign(new Error('event_seq required'), {
      status: 400, code: 'BAD_REQUEST', message: 'event_seq must be an integer', details: undefined,
    });
    return sendJson(res, 200, await store.outbox.redeliver(id, eventSeq));
  }
  if ((subMatch = /^\/api\/subscriptions\/([^/]+)\/proofs$/.exec(p)) && req.method === 'GET') {
    const limit = Math.min(500, Number(url.searchParams.get('limit')) || 100);
    return sendJson(res, 200, { subscription_id: subMatch[1], notifications: await store.outbox.listProofItems(subMatch[1], limit) });
  }
  if ((subMatch = /^\/api\/subscriptions\/([^/]+)\/items$/.exec(p)) && req.method === 'GET') {
    const stateFilter = url.searchParams.get('state') || null;
    const limit = Math.min(500, Number(url.searchParams.get('limit')) || 100);
    return sendJson(res, 200, { items: await store.outbox.listItems(subMatch[1], { state: stateFilter, limit }) });
  }
  if ((subMatch = /^\/api\/subscriptions\/([^/]+)$/.exec(p)) && req.method === 'GET') {
    return sendJson(res, 200, await store.outbox.getSubscription(subMatch[1]));
  }

  let m;
  if ((m = /^\/api\/objects\/([^/]+)$/.exec(p)) && req.method === 'GET') {
    return sendJson(res, 200, await store.getObject(decodeURIComponent(m[1])));
  }
  if ((m = /^\/api\/objects\/([^/]+)\/receipts\/download$/.exec(p)) && req.method === 'GET') {
    const objectKey = decodeURIComponent(m[1]);
    const receipts = await store.listReceipts(objectKey);
    if (!receipts.length) throw new ApiError(404, 'RECEIPT_NOT_FOUND', 'no receipts for object');
    // Inspector-safe: listReceipts already strips request_key/site/site_seq.
    const payload = JSON.stringify({ object_key: objectKey, receipts });
    res.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': `attachment; filename="receipts-${objectKey.replace(/[^A-Za-z0-9_.-]/g, '_')}.json"`,
    });
    return res.end(payload);
  }
  if ((m = /^\/api\/receipts\/([^/]+)$/.exec(p)) && req.method === 'GET') {
    return sendJson(res, 200, await store.getReceipt(decodeURIComponent(m[1])));
  }
  if ((m = /^\/api\/archive\/segments\/([^/]+)\/pack$/.exec(p)) && req.method === 'GET') {
    // Inspector-safe desensitised proof pack; tamper is detected before delivery.
    const pack = await store.downloadProofPack(decodeURIComponent(m[1]));
    const payload = JSON.stringify(pack, null, 2);
    res.writeHead(200, {
      'content-type': 'application/json; charset=utf-8',
      'content-disposition': `attachment; filename="archive-proof-${m[1].slice(0, 16)}.json"`,
    });
    return res.end(payload);
  }
  if ((m = /^\/api\/archive\/segments\/([^/]+)\/raw$/.exec(p)) && req.method === 'GET') {
    // Operator-only raw segment (contains station ids and request keys).
    const seg = await store.readSegmentRaw(decodeURIComponent(m[1]));
    res.writeHead(200, {
      'content-type': 'application/octet-stream',
      'content-disposition': `attachment; filename="segment-${m[1].slice(0, 16)}.seg"`,
      'x-segment-frames': String(seg.frame_count),
    });
    return res.end(seg.buffer);
  }
  if ((m = /^\/api\/cases\/([^/]+)$/.exec(p)) && req.method === 'GET') {
    const view = await store.getCase(m[1]);
    return sendJson(res, 200, view);
  }
  if ((m = /^\/api\/reviews\/([^/]+)$/.exec(p)) && req.method === 'POST') {
    if (auth.role !== 'reviewer') throw new ApiError(403, 'ROLE_NOT_PERMITTED', 'only reviewers adjudicate');
    const result = await store.submitReview(decodeURIComponent(m[1]), auth.reviewerId, auth.reviewerName, body?.choices);
    return sendJson(res, 200, result);
  }

  throw new ApiError(404, 'NOT_FOUND', 'no such route');
}

/**
 * Causal-divergence diagnose API. Visibility tiers are enforced here, separate
 * from the convergence POLICY table:
 *   operator/admin — intake, version management, cancel, pump, all reads
 *   analyst        — group list, submit comparisons, read diff + evidence
 *   observer       — sealed proofs and verification only
 *
 * Error responses carry stable reason codes but never echo submitted content.
 */
async function handleDiagnoseApi(req, res, url, config, auth, diagnose) {
  const p = url.pathname;
  const role = auth.role;
  const isOps = role === 'operator' || role === 'admin';
  const isAnalyst = role === 'analyst';
  const isObserver = role === 'observer';

  const deny = () => {
    throw new ApiError(403, 'ROLE_NOT_PERMITTED', `${role} may not ${req.method} ${p}`);
  };

  // GET (and POST verify) routes are read first; POST bodies parsed only when
  // the role may actually use the route.
  if (req.method === 'GET' && p === '/api/diagnose/versions') {
    if (!isOps && !isAnalyst && !isObserver) deny();
    return sendJson(res, 200, await diagnose.versions());
  }
  if (req.method === 'GET' && p === '/api/diagnose/groups') {
    if (!isOps && !isAnalyst) deny();
    return sendJson(res, 200, { groups: await diagnose.listGroups() });
  }
  if (req.method === 'GET' && p === '/api/diagnose/comparisons') {
    if (!isOps && !isAnalyst) deny();
    return sendJson(res, 200, { comparisons: await diagnose.listComparisons() });
  }
  let m;
  if ((m = /^\/api\/diagnose\/comparisons\/([^/]+)$/.exec(p)) && req.method === 'GET') {
    if (!isOps && !isAnalyst) deny();
    return sendJson(res, 200, await diagnose.getComparison(decodeURIComponent(m[1])));
  }
  if ((m = /^\/api\/diagnose\/comparisons\/([^/]+)\/proof$/.exec(p)) && req.method === 'GET') {
    // The observer's one door: sealed desensitised proofs only.
    if (!isOps && !isAnalyst && !isObserver) deny();
    return sendJson(res, 200, await diagnose.getProof(decodeURIComponent(m[1])));
  }

  const body = req.method === 'POST' ? await readJson(req) : null;

  if (p === '/api/diagnose/receipts' && req.method === 'POST') {
    if (!isOps) deny();
    return sendJson(res, 200, await diagnose.appendReceipts(body));
  }
  if (p === '/api/diagnose/comparisons' && req.method === 'POST') {
    if (!isAnalyst) deny();
    const result = await diagnose.submitComparison(body);
    return sendJson(res, result.status, result.task);
  }
  if (p === '/api/diagnose/pump' && req.method === 'POST') {
    if (!isOps) deny();
    return sendJson(res, 200, await diagnose.pumpCycle());
  }
  if (p === '/api/diagnose/versions/activate' && req.method === 'POST') {
    if (!isOps) deny();
    return sendJson(res, 200, await diagnose.activateAlgorithm(body?.algorithm));
  }
  if (p === '/api/diagnose/proofs/verify' && req.method === 'POST') {
    // Read-only observers verify proofs; every authenticated tier may verify.
    if (!isOps && !isAnalyst && !isObserver) deny();
    // Recompute from the externally supplied proof; nothing is stored or echoed
    // beyond the layered verification verdict.
    const verdict = verifyProof(body?.proof ?? body, config.receiptSecret);
    return sendJson(res, 200, verdict);
  }
  if ((m = /^\/api\/diagnose\/comparisons\/([^/]+)\/cancel$/.exec(p)) && req.method === 'POST') {
    if (!isOps) deny();
    return sendJson(res, 200, await diagnose.cancelComparison(decodeURIComponent(m[1])));
  }

  throw new ApiError(404, 'NOT_FOUND', 'no such route');
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) {
        reject(new ApiError(413, 'BODY_TOO_LARGE', 'request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      } catch {
        reject(new ApiError(400, 'BAD_JSON', 'body must be valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function serveFile(res, filePath, contentType, noStore = false) {
  fs.readFile(filePath, (err, data) => {
    if (err) return sendJson(res, 404, { error: { code: 'NOT_FOUND', message: 'not found' } });
    res.writeHead(200, {
      'content-type': contentType,
      ...(noStore ? { 'cache-control': 'no-store' } : {}),
    });
    res.end(data);
  });
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  // Diagnose responses are role-filtered operational state: never cache them,
  // so a refresh always re-reads task phase, watermarks and proof digests.
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(body);
}

function sendError(res, err) {
  // Both store.ApiError and outbox.OutboxError carry status/code/details; duck
  // typing keeps the web layer decoupled from either concrete class.
  if (err && typeof err.status === 'number' && err.code) {
    return sendJson(res, err.status, { error: { code: err.code, message: err.message, details: err.details } });
  }
  // Never leak internals; log server-side.
  console.error('unhandled error:', err);
  sendJson(res, 500, { error: { code: 'INTERNAL', message: 'internal error' } });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const config = loadConfig();
  const { server } = createServer(config);
  server.listen(config.port, config.host, () => {
    console.log(`converge service listening on http://${config.host}:${config.port} (data: ${config.dataDir})`);
  });
  const shutdown = () => {
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1000).unref();
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}
