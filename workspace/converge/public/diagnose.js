'use strict';

// Causal divergence diagnose console.
//
// State discipline: the token lives in sessionStorage ONLY (tab-scoped, never
// localStorage/cookie). The page holds no derived business state between
// actions: every load, every "刷新" click and every poll re-reads groups,
// phases, watermarks and proof digests from the server. Logout clears the
// token and empties every DOM region, including the verification paste box.

const $ = (id) => document.getElementById(id);
const state = {
  token: sessionStorage.getItem('converge-diagnose-token') || '',
  role: '',
  selectedTask: null,
};

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
function short(h, n = 12) { return typeof h === 'string' ? h.slice(0, n) : h; }

function toast(message, kind = '') {
  const box = document.createElement('div');
  if (kind) box.className = kind === 'ok' ? 'okbox' : 'errbox';
  box.textContent = message;
  $('toast').appendChild(box);
  setTimeout(() => box.remove(), 6000);
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${state.token}`,
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!res.ok) {
    // Error rendering never inserts submitted content; the server response
    // itself only carries stable codes/messages.
    const err = new Error((data && data.error && `${data.error.code}: ${data.error.message}`) || `HTTP ${res.status}`);
    err.status = res.status;
    err.payload = data;
    throw err;
  }
  return data;
}

// ---------------------------------------------------------------- session --

function clearAllDom() {
  for (const id of ['ingestResult', 'compareResult', 'verifyResult']) {
    const el = $(id);
    el.hidden = true;
    el.textContent = '';
  }
  $('inEntries').value = '';
  $('verifyInput').value = '';
  $('groupsList').textContent = '';
  $('tasksTable').querySelector('tbody').innerHTML = '';
  $('taskDetail').innerHTML = '';
  $('proofBody').textContent = '';
  $('versionInfo').textContent = '';
}

async function applyRole() {
  let role = '';
  try {
    const me = await api('GET', '/api/whoami');
    role = me.role;
  } catch {
    role = '';
  }
  state.role = role;
  $('rolepill').textContent = role ? `角色：${role}` : '未认证';
  const isOps = role === 'operator' || role === 'admin';
  const isAnalyst = role === 'analyst';
  const isObserver = role === 'observer';

  $('ingestPanel').hidden = !isOps;
  $('opsPanel').hidden = !isOps;
  $('cancelPanel').hidden = !isOps;
  $('comparePanel').hidden = !isAnalyst;
  $('verifyPanel').hidden = !isObserver;
  $('groupsPanel').hidden = !isOps && !isAnalyst;
  $('tasksPanel').hidden = !isOps && !isAnalyst;
  $('proofPanel').hidden = !isOps && !isAnalyst;

  document.querySelectorAll('header select, header input, header button').forEach((el) => {
    if (el.id === 'logoutBtn') el.disabled = !role;
  });

  if (!role) { clearAllDom(); return; }
  await refreshAll();
}

// ----------------------------------------------------------------- reads ---

async function loadGroups() {
  const isOps = state.role === 'operator' || state.role === 'admin';
  if (!isOps && state.role !== 'analyst') return;
  const { groups } = await api('GET', '/api/diagnose/groups');
  if (!groups.length) {
    $('groupsList').innerHTML = '<span class="muted">还没有收据组。</span>';
    if (isOps) {
      $('cmpLeft').value = ''; $('cmpRight').value = '';
    }
    return;
  }
  $('groupsList').innerHTML = `<table><thead><tr><th>组</th><th>读取水位（最新序号）</th><th>链头收据</th></tr></thead><tbody>${
    groups.map((g) => `<tr><td class="mono">${esc(g.group)}</td><td>${g.watermark}</td><td class="mono muted">${esc(short(g.head_receipt))}</td></tr>`).join('')
  }</tbody></table>`;
  // Analyst convenience: click a row fills the next empty group input.
  [...document.querySelectorAll('#groupsList tbody tr')].forEach((tr) => {
    const key = tr.firstChild.textContent;
    tr.classList.add('clickable');
    if (state.role === 'analyst') {
      tr.onclick = () => {
        if (!$('cmpLeft').value) $('cmpLeft').value = key;
        else $('cmpRight').value = key;
      };
    }
  });
}

function phaseTag(phase) {
  return `<span class="tag ${esc(phase)}">${esc(phase)}</span>`;
}

async function loadTasks() {
  if (state.role !== 'operator' && state.role !== 'admin' && state.role !== 'analyst') return;
  const { comparisons } = await api('GET', '/api/diagnose/comparisons');
  const tbody = $('tasksTable').querySelector('tbody');
  tbody.innerHTML = comparisons.map((t) => {
    const verdict = t.phase === 'sealed'
      ? (t.converged ? '<span class="ok">已收敛</span>' : '<span class="err">存在分歧</span>')
      : '<span class="muted">—</span>';
    return `<tr class="clickable" data-key="${esc(t.task_key)}">
      <td class="mono">${esc(t.task_key)}</td>
      <td class="mono muted">${esc(t.left_group)} ⇄ ${esc(t.right_group)}</td>
      <td>${phaseTag(t.phase)}</td>
      <td class="mono">${esc(t.algorithm)}</td>
      <td>${t.watermarks.left}/${t.watermarks.right}</td>
      <td>${verdict}</td>
    </tr>`;
  }).join('');
  [...tbody.querySelectorAll('tr')].forEach((tr) => {
    tr.onclick = () => { state.selectedTask = tr.dataset.key; loadTaskDetail(); };
  });
  if (state.selectedTask) await loadTaskDetail();
}

function renderTree(view) {
  const d = view.divergence;
  const rows = [];
  const nodeLine = (cls, side, node, kind) =>
    `<div class="node ${cls}">${side === 'left' ? '◧ 左' : side === 'right' ? '◨ 右' : '　'} ${esc(kind)} <span title="${esc(node)}">${esc(short(node))}</span></div>`;
  if (view.phase === 'sealed' && !view.converged && d) {
    rows.push('<div class="muted" style="margin:6px 0">第一处分歧：</div>');
    if (d.left_node) rows.push(nodeLine('div', 'left', d.left_node, d.kind));
    if (d.right_node) rows.push(nodeLine('div', 'right', d.right_node, d.kind));
    rows.push('<div class="muted" style="margin:8px 0 4px">受影响下游（因果可达闭包，按拓扑层序）：</div>');
    for (const n of view.downstream.left) rows.push(nodeLine('down', 'left', n, 'downstream'));
    for (const n of view.downstream.right) rows.push(nodeLine('down', 'right', n, 'downstream'));
  } else if (view.phase === 'sealed' && view.converged) {
    rows.push('<div class="ok" style="margin:6px 0">两组在该水位下逐节点一致，无分歧。</div>');
  }
  return rows.join('');
}

function renderEvidence(view) {
  if (!view.evidence || !view.evidence.length) return '';
  return `<div class="muted" style="margin:10px 0 4px">脱敏解释证据（决定类别 / 父边 / 区段-变更摘要；无站点、请求键、图像内容）：</div>
  <pre>${esc(view.evidence.map((e) => JSON.stringify(e)).join('\n'))}</pre>`;
}

async function loadTaskDetail() {
  const key = state.selectedTask;
  if (!key) return;
  const view = await api('GET', `/api/diagnose/comparisons/${encodeURIComponent(key)}`);
  const skelRows = (s) => s.nodes.map((n) =>
    `<tr><td class="mono">${esc(short(n.node))}</td><td>${n.level}</td><td>${esc(n.decision_kind)}</td>
     <td class="mono muted">${n.parents.map((p) => esc(short(p, 8))).join(', ') || '—'}</td>
     <td>${n.contributions.map((c) => esc(c.region)).join(', ')}</td></tr>`).join('');
  $('taskDetail').innerHTML = `
    <div class="row">
      <div class="panel" style="margin:0">
        <h2>左因果骨架 · ${esc(view.left_group)}（水位 ${view.watermarks.left}）</h2>
        <table><thead><tr><th>节点</th><th>层</th><th>决定</th><th>前驱</th><th>区段</th></tr></thead><tbody>${skelRows(view.skeletons.left)}</tbody></table>
      </div>
      <div class="panel" style="margin:0">
        <h2>右因果骨架 · ${esc(view.right_group)}（水位 ${view.watermarks.right}）</h2>
        <table><thead><tr><th>节点</th><th>层</th><th>决定</th><th>前驱</th><th>区段</th></tr></thead><tbody>${skelRows(view.skeletons.right)}</tbody></table>
      </div>
    </div>
    <div class="panel" style="margin:12px 0 0"><h2>差异树 · ${esc(view.algorithm)}</h2><div class="tree">${renderTree(view)}</div>${renderEvidence(view)}</div>`;

  if (view.phase === 'sealed') {
    if (state.role === 'operator' || state.role === 'admin') $('cancelKey').value = view.task_key;
    try {
      const pp = await api('GET', `/api/diagnose/comparisons/${encodeURIComponent(key)}/proof`);
      $('proofPanel').hidden = false;
      $('proofBody').innerHTML = `<table>
        <tr><th>证明格式</th><td class="mono">${esc(pp.proof.format)}</td></tr>
        <tr><th>根摘要 digest</th><td class="mono">${esc(pp.proof.digest)}</td></tr>
        <tr><th>证据摘要 evidence_digest</th><td class="mono">${esc(pp.proof.evidence_digest)}</td></tr>
        <tr><th>输入指纹 L/R</th><td class="mono">${esc(short(pp.proof.input_fingerprints.left))} / ${esc(short(pp.proof.input_fingerprints.right))}</td></tr>
        <tr><th>密封时间</th><td>${esc(pp.proof.sealed_at)}</td></tr>
        <tr><th>交付前验真</th><td class="ok">${pp.verification.ok ? `通过 @ ${esc(pp.verification.verified_at)}` : '失败'}</td></tr>
      </table>`;
    } catch (e) {
      $('proofBody').textContent = `证明尚不可读：${e.message}`;
    }
  }
}

async function loadVersions() {
  if (state.role !== 'operator' && state.role !== 'admin') return;
  const v = await api('GET', '/api/diagnose/versions');
  $('versionInfo').innerHTML = `当前算法：<b class="mono">${esc(v.active)}</b> <span class="muted">（${
    v.available.map(esc).join(' / ')}）— ${esc(v.pinning)}</span>`;
  $('algoSelect').value = v.active === 'topo-v2' ? 'topo-v2' : 'chain-v1';
}

async function refreshAll() {
  try {
    await Promise.all([loadGroups(), loadTasks(), loadVersions()]);
  } catch (e) {
    toast(e.message, 'err');
  }
}

// --------------------------------------------------------------- actions ---

function wire() {
  $('tokenSelect').onchange = (e) => {
    if (e.target.value) { $('tokenInput').value = e.target.value; }
  };
  $('tokenInput').onchange = async () => {
    state.token = $('tokenInput').value.trim();
    if (state.token) sessionStorage.setItem('converge-diagnose-token', state.token);
    await applyRole();
  };
  $('logoutBtn').onclick = () => {
    state.token = '';
    sessionStorage.removeItem('converge-diagnose-token');
    clearAllDom();
    state.selectedTask = null;
    $('rolepill').textContent = '未认证';
  };
  $('refreshBtn').onclick = () => applyRole();

  $('ingestBtn').onclick = async () => {
    let entries;
    try { entries = JSON.parse($('inEntries').value); }
    catch { toast('本地 JSON 解析失败：未发送任何内容', 'err'); return; }
    try {
      const r = await api('POST', '/api/diagnose/receipts', { group: $('inGroup').value.trim(), entries });
      $('ingestResult').hidden = false;
      $('ingestResult').textContent = JSON.stringify(r, null, 2);
      toast(`已接收 ${r.accepted} 条，水位 ${r.watermark}`, 'ok');
      await loadGroups();
    } catch (e) {
      // Show only the stable reason codes; never the submitted entries.
      const reasons = e.payload?.error?.details?.reasons?.map((x) => x.code + (x.seq ? `@${x.seq}` : '')).join(', ');
      toast(`${e.message}${reasons ? ` [${reasons}]` : ''}（整包拒绝，未写入）`, 'err');
    }
  };

  $('compareBtn').onclick = async () => {
    try {
      const body = {
        task_key: $('cmpKey').value.trim(),
        left_group: $('cmpLeft').value.trim(),
        right_group: $('cmpRight').value.trim(),
      };
      const t = await api('POST', '/api/diagnose/comparisons', body);
      $('compareResult').hidden = false;
      $('compareResult').textContent = JSON.stringify(t, null, 2);
      state.selectedTask = body.task_key;
      toast('任务已登记，服务端固定水位与算法版本', 'ok');
      await loadTasks();
    } catch (e) {
      toast(e.message, 'err');
    }
  };

  $('algoBtn').onclick = async () => {
    try {
      const r = await api('POST', '/api/diagnose/versions/activate', { algorithm: $('algoSelect').value });
      toast(`激活 ${r.active}；进行中任务保持 ${esc(r.previous)}`, 'ok');
      await loadVersions();
    } catch (e) { toast(e.message, 'err'); }
  };
  $('pumpBtn').onclick = async () => {
    try { await api('POST', '/api/diagnose/pump', {}); toast('已推进一轮', 'ok'); await refreshAll(); }
    catch (e) { toast(e.message, 'err'); }
  };
  $('cancelBtn').onclick = async () => {
    try {
      const r = await api('POST', `/api/diagnose/comparisons/${encodeURIComponent($('cancelKey').value.trim())}/cancel`, {});
      toast(`任务 ${r.phase}`, 'ok');
      await loadTasks();
    } catch (e) { toast(e.message, 'err'); }
  };

  $('verifyBtn').onclick = async () => {
    let proof;
    try { proof = JSON.parse($('verifyInput').value); }
    catch { toast('本地 JSON 解析失败：未发送', 'err'); return; }
    try {
      const r = await api('POST', '/api/diagnose/proofs/verify', { proof });
      $('verifyResult').hidden = false;
      $('verifyResult').textContent = JSON.stringify(r, null, 2);
      toast('证明验真通过', 'ok');
    } catch (e) {
      $('verifyResult').hidden = false;
      $('verifyResult').textContent = JSON.stringify(e.payload?.error || { code: 'HTTP', message: e.message }, null, 2);
      toast(e.message, 'err');
    }
  };

  // Polling also re-reads everything from the server (no local assumptions).
  setInterval(() => { if (state.role && !document.hidden) refreshAll(); }, 3000);
}

wire();
if (state.token) applyRole();
