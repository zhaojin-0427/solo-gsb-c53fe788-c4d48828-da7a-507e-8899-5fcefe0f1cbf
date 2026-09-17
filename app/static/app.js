/* 选择性披露凭证验证台 — 原生 JS 前端（无框架、无构建） */
"use strict";

// ---------- 基础工具 ----------

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  const text = await resp.text();
  let data;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!resp.ok) {
    const detail = data && data.detail ? data.detail : `HTTP ${resp.status}`;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

async function apiIdempotent(path, presentation, idemKey) {
  const resp = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Idempotency-Key": idemKey },
    body: JSON.stringify(presentation),
  });
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.detail || `HTTP ${resp.status}`);
  return data;
}

function uuid() {
  return crypto.randomUUID ? crypto.randomUUID() : "idem-" + Math.random().toString(16).slice(2) + Date.now().toString(16);
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function pretty(obj) {
  return JSON.stringify(obj, null, 2);
}

// ---------- 与 Python 端逐字节一致的 canonical JSON + Merkle ----------

function canonical(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
}

const enc = new TextEncoder();

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

async function leafCommitment(field, value, type, salt) {
  const preimage = enc.encode(canonical({ field, salt, type, value }));
  return sha256(concatBytes(new Uint8Array([0x00]), preimage));
}

function hashNode(left, right) {
  return sha256(concatBytes(new Uint8Array([0x01]), left, right));
}

async function buildTree(leaves) {
  if (leaves.length === 0) return { root: new Uint8Array(32), levels: [] };
  const levels = [leaves.slice()];
  while (levels[levels.length - 1].length > 1) {
    const layer = levels[levels.length - 1];
    const nxt = [];
    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length) nxt.push(await hashNode(layer[i], layer[i + 1]));
      else nxt.push(layer[i]);
    }
    levels.push(nxt);
  }
  return { root: levels[levels.length - 1][0], levels };
}

function buildProof(levels, index) {
  const proof = [];
  let idx = index;
  for (let li = 0; li < levels.length - 1; li++) {
    const layer = levels[li];
    if (idx % 2 === 0) {
      if (idx + 1 < layer.length) proof.push({ side: "right", hash: toHex(layer[idx + 1]) });
    } else {
      proof.push({ side: "left", hash: toHex(layer[idx - 1]) });
    }
    idx = Math.floor(idx / 2);
  }
  return proof;
}

/* 持有者在浏览器本地生成 presentation（凭证 JSON 无需上传即可完成披露） */
async function buildPresentationLocally(envelope, discloseSet) {
  const leaves = envelope.leaves;
  const hashes = [];
  for (const lf of leaves) {
    hashes.push(await leafCommitment(lf.field, lf.value, lf.type, lf.salt));
  }
  const { levels } = await buildTree(hashes);

  // 自检：本地算出的根应与凭证中已签名的根一致
  const localRoot = levels.length ? toHex(levels[levels.length - 1][0]) : "0".repeat(64);
  if (localRoot !== envelope.header.merkle_root) {
    throw new Error("本地重算 Merkle 根与凭证签名根不一致，凭证可能已损坏");
  }

  const disclosed = [];
  for (const lf of leaves) {
    if (!discloseSet.has(lf.field)) continue;
    disclosed.push({
      field: lf.field,
      value: lf.value,
      salt: lf.salt,
      type: lf.type,
      proof: buildProof(levels, lf.index),
    });
  }
  return {
    header: envelope.header,
    signature: envelope.signature,
    schema_version: envelope.schema_version,
    disclosed,
  };
}

// ---------- Tab 切换 ----------

$$(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach((b) => b.classList.remove("active"));
    $$(".panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $("#tab-" + btn.dataset.tab).classList.add("active");
    if (btn.dataset.tab === "admin") loadAdmin();
    if (btn.dataset.tab === "issue") loadIssuePage();
    if (btn.dataset.tab === "wallet") loadWalletPage();
    if (btn.dataset.tab === "audits") loadChain();
  });
});

// ---------- ① 管理员 ----------

const FIELD_TYPES = ["string", "integer", "number", "boolean", "date"];

function fieldRow(name = "", type = "string", required = false) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><input class="f-name" value="${esc(name)}" placeholder="字段名"></td>
    <td><select class="f-type">${FIELD_TYPES.map((t) =>
      `<option value="${t}"${t === type ? " selected" : ""}>${t}</option>`).join("")}</select></td>
    <td style="text-align:center"><input type="checkbox" class="f-req" ${required ? "checked" : ""}></td>
    <td><button class="f-del danger">删除</button></td>`;
  tr.querySelector(".f-del").addEventListener("click", () => tr.remove());
  return tr;
}

async function loadAdmin() {
  await loadKeys();
  await loadTemplates();
  await loadRevocations();
}

async function loadKeys() {
  const data = await api("GET", "/api/keys");
  $("#active-key").textContent = data.active_kid ? `当前生效密钥：${data.active_kid}` : "无可用密钥";
  const tb = $("#keys-table tbody");
  tb.innerHTML = data.keys.map((k) =>
    `<tr><td><code>${esc(k.kid)}</code></td><td>${esc(k.created_at)}</td>
     <td>${k.active ? '<span class="badge ok">生效中</span>' : '<span class="badge warn">已轮换(历史)</span>'}</td></tr>`
  ).join("");
}

async function loadTemplates() {
  const data = await api("GET", "/api/templates");
  const box = $("#templates-list");
  if (!data.templates.length) { box.innerHTML = '<p class="muted">还没有模板</p>'; return; }
  box.innerHTML = data.templates.map((t) => `
    <div class="tpl-block">
      <strong>${esc(t.id)}</strong> — ${esc(t.name)}
      <span class="badge info">当前 v${t.current_version}</span>
      <div class="versions">版本: ${t.versions.map((v) =>
        `<span class="ver-chip ${v.version === t.current_version ? "current" : ""}">v${v.version} · ${esc(v.created_at)}</span>`
      ).join("")}</div>
      <div>${t.schema.map((f) =>
        `<span class="ver-chip">${esc(f.name)}: ${f.type}${f.required ? " *必填" : ""}</span>`
      ).join("")}</div>
      <div class="row">
        <button data-tpl="${esc(t.id)}" class="btn-newver">基于当前版本编辑并发布新版本</button>
      </div>
      <div class="newver-area" style="display:none">
        <table class="ver-fields"><thead><tr><th>字段名</th><th>类型</th><th>必填</th><th></th></tr></thead><tbody></tbody></table>
        <button class="btn-add-ver-field">+ 增加字段</button>
        <button class="btn-publish-ver primary">发布新版本</button>
      </div>
    </div>`).join("");

  box.querySelectorAll(".btn-newver").forEach((btn) => {
    btn.addEventListener("click", () => {
      const block = btn.closest(".tpl-block");
      const area = block.querySelector(".newver-area");
      const open = area.style.display !== "none";
      area.style.display = open ? "none" : "block";
      if (!open) {
        const tb = area.querySelector("tbody");
        tb.innerHTML = "";
        const tpl = data.templates.find((x) => x.id === btn.dataset.tpl);
        tpl.schema.forEach((f) => tb.appendChild(fieldRow(f.name, f.type, f.required)));
      }
    });
  });
  box.querySelectorAll(".tpl-block").forEach((block) => {
    const tplId = block.querySelector(".btn-newver").dataset.tpl;
    const area = block.querySelector(".newver-area");
    block.querySelector(".btn-add-ver-field").addEventListener("click", () =>
      area.querySelector("tbody").appendChild(fieldRow()));
    block.querySelector(".btn-publish-ver").addEventListener("click", async () => {
      const schema = collectSchema(area.querySelector("tbody"));
      try {
        const r = await api("POST", `/api/templates/${encodeURIComponent(tplId)}/versions`, { schema });
        alert(`已发布 ${tplId} v${r.version}`);
        await loadTemplates();
      } catch (e) { alert("发布失败：" + e.message); }
    });
  });
}

function collectSchema(tbody) {
  return $$(tbody.querySelectorAll("tr")).map((tr) => ({
    name: tr.querySelector(".f-name").value.trim(),
    type: tr.querySelector(".f-type").value,
    required: tr.querySelector(".f-req").checked,
  })).filter((f) => f.name);
}

async function loadRevocations() {
  const data = await api("GET", "/api/revocations");
  $("#revocations-table tbody").innerHTML = data.revocations.map((r) =>
    `<tr><td>${esc(r.template_id)}</td><td>v${r.version}</td><td><code>${esc(r.credential_id)}</code></td>
     <td>${esc(r.reason || "")}</td><td>${esc(r.created_at)}</td></tr>`).join("");
}

$("#btn-add-field").addEventListener("click", () =>
  $("#tpl-fields-edit tbody").appendChild(fieldRow()));
$("#tpl-fields-edit tbody").appendChild(fieldRow("full_name", "string", true));
$("#tpl-fields-edit tbody").appendChild(fieldRow("age", "integer", true));

$("#btn-create-tpl").addEventListener("click", async () => {
  const id = $("#tpl-id").value.trim();
  const name = $("#tpl-name").value.trim();
  if (!id || !name) return alert("请填写模板 ID 与名称");
  const schema = collectSchema($("#tpl-fields-edit tbody"));
  try {
    await api("POST", "/api/templates", { id, name, schema });
    $("#tpl-id").value = ""; $("#tpl-name").value = "";
    $("#tpl-fields-edit tbody").innerHTML = "";
    alert("模板创建成功（v1）");
    await loadTemplates();
  } catch (e) { alert("创建失败：" + e.message); }
});

$("#btn-rotate").addEventListener("click", async () => {
  if (!confirm("轮换后新凭证用新密钥签名；旧密钥保留，历史凭证仍可验证。确认？")) return;
  const r = await api("POST", "/api/keys/rotate");
  alert("新密钥已生效：" + r.kid);
  await loadKeys();
});

$("#btn-revoke").addEventListener("click", async () => {
  const credential_id = $("#revoke-cred-id").value.trim();
  const reason = $("#revoke-reason").value.trim();
  if (!credential_id) return alert("填写凭证 ID");
  try {
    await api("POST", "/api/revoke", { credential_id, reason });
    $("#revoke-cred-id").value = ""; $("#revoke-reason").value = "";
    alert("已加入该版本生效的撤销列表");
    await loadRevocations();
  } catch (e) { alert("撤销失败：" + e.message); }
});
$("#btn-refresh-revocations").addEventListener("click", loadRevocations);

// ---------- ② 签发端 ----------

async function loadIssuePage() {
  const data = await api("GET", "/api/templates");
  const sel = $("#issue-tpl");
  const prev = sel.value;
  sel.innerHTML = data.templates.map((t) =>
    `<option value="${esc(t.id)}">${esc(t.id)} — ${esc(t.name)} (v${t.current_version})</option>`).join("");
  if (prev) sel.value = prev;
  renderIssueForm();
  await loadCreds();
}

$("#issue-tpl").addEventListener("change", renderIssueForm);

async function renderIssueForm() {
  const tplId = $("#issue-tpl").value;
  if (!tplId) { $("#issue-form").innerHTML = '<p class="muted">请先创建模板</p>'; return; }
  const tpls = (await api("GET", "/api/templates")).templates;
  const tpl = tpls.find((t) => t.id === tplId);
  $("#issue-form").innerHTML = '<div class="card">' + tpl.schema.map((f) => `
    <div class="row">
      <label style="width:220px"><code>${esc(f.name)}</code>
        ${f.required ? '<span class="badge bad">必填</span>' : '<span class="muted">可选</span>'}
        <span class="muted">(${f.type})</span></label>
      <input class="claim-input" data-field="${esc(f.name)}" data-type="${f.type}"
             data-required="${f.required}" style="flex:1" placeholder="${f.type}">
    </div>`).join("") + "</div>";
}

function parseClaimValue(input) {
  const raw = input.value.trim();
  const type = input.dataset.type;
  if (raw === "") return { missing: true };
  if (type === "integer") {
    if (!/^-?\d+$/.test(raw)) throw new Error(`字段 ${input.dataset.field} 需要整数`);
    return { value: parseInt(raw, 10) };
  }
  if (type === "number") {
    if (!/^-?\d+(\.\d+)?$/.test(raw)) throw new Error(`字段 ${input.dataset.field} 需要数字`);
    return { value: parseFloat(raw) };
  }
  if (type === "boolean") {
    if (!["true", "false"].includes(raw)) throw new Error(`字段 ${input.dataset.field} 需要 true 或 false`);
    return { value: raw === "true" };
  }
  return { value: raw };
}

$("#btn-issue").addEventListener("click", async () => {
  const claims = {};
  try {
    $$(".claim-input").forEach((input) => {
      const r = parseClaimValue(input);
      if (r.missing) {
        if (input.dataset.required === "true") throw new Error(`必填字段 ${input.dataset.field} 未填`);
        return;
      }
      claims[input.dataset.field] = r.value;
    });
  } catch (e) { return alert(e.message); }
  try {
    const r = await api("POST", "/api/issue", {
      template_id: $("#issue-tpl").value,
      claims,
      valid_days: parseInt($("#issue-days").value || "365", 10),
    });
    window._lastCredential = r.credential;
    $("#issue-result").innerHTML = `
      <div class="card">
        <span class="badge ok">签发成功</span>
        凭证 ID：<code>${esc(r.credential.header.credential_id)}</code>
        <span class="muted">Merkle 根：<code>${esc(r.credential.header.merkle_root.slice(0, 20))}…</code></span>
        <div class="row">
          <button id="btn-send-wallet" class="primary">发送到持有者钱包 →</button>
          <button id="btn-download-cred">下载凭证信封 JSON</button>
        </div>
        <pre>${esc(pretty(r.credential))}</pre>
      </div>`;
    $("#btn-send-wallet").addEventListener("click", () => {
      $$(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === "wallet"));
      $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-wallet"));
      loadWalletPage(r.credential);
    });
    $("#btn-download-cred").addEventListener("click", () =>
      downloadJson("credential-" + r.credential.header.credential_id + ".json", r.credential));
    await loadCreds();
  } catch (e) { alert("签发失败：" + e.message); }
});

async function loadCreds() {
  const data = await api("GET", "/api/credentials");
  $("#creds-table tbody").innerHTML = data.credentials.map((c) => `
    <tr><td><code>${esc(c.id)}</code></td><td>${esc(c.template_id)} v${c.version}</td>
    <td><code>${esc(c.kid)}</code></td>
    <td>${c.revoked ? '<span class="badge bad">已撤销</span>' : '<span class="badge ok">有效</span>'}</td>
    <td>${esc(c.created_at)}</td>
    <td><button data-id="${esc(c.id)}" class="btn-cred-load">载入钱包</button></td></tr>`).join("");
  $$(".btn-cred-load").forEach((b) => b.addEventListener("click", async () => {
    const env = await api("GET", "/api/credentials/" + encodeURIComponent(b.dataset.id));
    $$(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === "wallet"));
    $$(".panel").forEach((x) => x.classList.toggle("active", x.id === "tab-wallet"));
    loadWalletPage(env);
  }));
}

function downloadJson(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---------- ③ 持有者钱包 ----------

let walletEnvelope = null;

async function loadWalletPage(preset) {
  if (preset) walletEnvelope = preset;
  const data = await api("GET", "/api/credentials");
  const sel = $("#wallet-cred");
  sel.innerHTML = data.credentials.map((c) =>
    `<option value="${esc(c.id)}">${esc(c.id)} (${esc(c.template_id)} v${c.version})</option>`).join("");
  if (walletEnvelope) {
    sel.value = walletEnvelope.header.credential_id;
    renderWalletFields();
  } else {
    $("#wallet-fields").innerHTML = '<p class="muted">从下拉框载入或导入凭证信封</p>';
    $("#wallet-result").innerHTML = "";
  }
}

$("#btn-load-cred").addEventListener("click", async () => {
  const id = $("#wallet-cred").value;
  if (!id) return;
  walletEnvelope = await api("GET", "/api/credentials/" + encodeURIComponent(id));
  renderWalletFields();
  $("#wallet-result").innerHTML = "";
});

$("#btn-import-cred").addEventListener("click", () => $("#wallet-import-file").click());
$("#wallet-import-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    walletEnvelope = JSON.parse(await file.text());
    if (!walletEnvelope.leaves || !walletEnvelope.header) throw new Error("不是凭证信封");
    renderWalletFields();
    $("#wallet-result").innerHTML = '<span class="badge ok">已导入离线凭证</span>';
  } catch (err) { alert("导入失败：" + err.message); }
});

function renderWalletFields() {
  $("#wallet-fields").innerHTML = '<div class="card">' + walletEnvelope.leaves.map((lf, i) => `
    <div class="field-check">
      <label><input type="checkbox" class="disclose-check" data-field="${esc(lf.field)}" ${i < 2 ? "checked" : ""}>
        <code>${esc(lf.field)}</code> <span class="muted">(${lf.type})</span>
        <span class="muted">值预览: <span class="disclosed-val">${esc(String(lf.value))}</span></span>
      </label>
    </div>`).join("") + `
    <p class="hint">勾选的字段会披露明文值+盐+Merkle 路径；其余字段仅以 0x00 域分隔的叶子承诺隐藏在根中。</p>
    </div>`;
}

$("#btn-build-presentation").addEventListener("click", async () => {
  if (!walletEnvelope) return alert("请先载入凭证");
  const disclose = new Set($$(".disclose-check:checked").map((c) => c.dataset.field));
  try {
    const presentation = await buildPresentationLocally(walletEnvelope, disclose);
    window._lastPresentation = presentation;
    $("#wallet-result").innerHTML = `
      <div class="card">
        <span class="badge ok">Presentation 已在本地生成</span>
        已披露 ${presentation.disclosed.length} 个字段，隐藏 ${walletEnvelope.leaves.length - presentation.disclosed.length} 个。
        <div class="row"><button id="btn-send-verify" class="primary">发送到验证端 →</button>
          <button id="btn-download-pres">下载 presentation</button></div>
        <pre>${esc(pretty(presentation))}</pre>
      </div>`;
    $("#btn-send-verify").addEventListener("click", () => {
      $$(".tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === "verify"));
      $$(".panel").forEach((x) => x.classList.toggle("active", x.id === "tab-verify"));
      $("#verify-input").value = pretty(presentation);
      $("#idem-key").value = uuid();
    });
    $("#btn-download-pres").addEventListener("click", () =>
      downloadJson("presentation-" + presentation.header.credential_id + ".json", presentation));
  } catch (e) { alert("生成失败：" + e.message); }
});

// ---------- ④ 验证端 ----------

$("#btn-gen-idem").addEventListener("click", () => $("#idem-key").value = uuid());
$("#idem-key").value = uuid();

function renderVerifyResult(r) {
  const s = r.result.summary || {};
  const badges = r.result.valid
    ? '<span class="badge ok">✔ 验证通过</span>'
    : '<span class="badge bad">✘ 验证失败</span>';
  const dup = r.duplicate ? '<span class="badge warn">重复提交（命中幂等，未新增审计）</span>' : '';
  const disclosedRows = (s.disclosed_fields || []).map((f) => {
    const pr = (s.proof_results || []).find((x) => x.field === f) || {};
    return `<tr><td><code>${esc(f)}</code></td>
      <td class="disclosed-val">${esc(JSON.stringify(s.disclosed_values ? s.disclosed_values[f] : undefined))}</td>
      <td>${pr.root_match ? '<span class="badge ok">承诺一致</span>' : '<span class="badge bad">不一致</span>'}</td>
      <td>${pr.type_ok ? '<span class="badge ok">类型正确</span>' : `<span class="badge bad">${esc(pr.type_detail || '')}</span>`}</td></tr>`;
  }).join("");

  $("#verify-result").innerHTML = `
    <div class="card">
      <div class="row">${badges} ${dup} <span class="muted">审计 #${r.id} · ${esc(r.completed_at || r.created_at)}</span></div>
      <dl class="kv">
        <dt>凭证 ID</dt><dd><code>${esc(s.credential_id || "-")}</code></dd>
        <dt>模板 / 版本</dt><dd>${esc(s.template_id || "-")} v${s.template_version ?? "-"}
          <span class="muted">（历史凭证按其签发版本的模板与撤销列表校验）</span></dd>
        <dt>签发密钥 KID</dt><dd><code>${esc(s.issuer_key_id || "-")}</code></dd>
        <dt>已披露字段</dt><dd>${(s.disclosed_fields || []).map((f) => `<span class="ver-chip">${esc(f)}</span>`).join("") || "（无）"}</dd>
        <dt>隐藏字段数</dt><dd>${s.hidden_field_count ?? "-"} / ${(s.disclosed_fields || []).length + (s.hidden_field_count ?? 0)}</dd>
        <dt>审计链 hash</dt><dd><code style="font-size:11px">${esc(r.chain_hash)}</code></dd>
      </dl>
      <h3>检查项</h3>
      ${(r.checks || r.result.checks || []).map((c) => {
        const icon = c.ok ? "✅" : (c.advisory ? "⚠️" : "❌");
        const tag = c.advisory ? ' <span class="badge warn">建议性，不影响有效性</span>' : "";
        return `
        <div class="check-row">${icon}
          <div><strong>${esc(c.name)}</strong>${tag} — <span class="detail">${esc(c.detail)}</span></div>
        </div>`;
      }).join("")}
      <h3>已披露字段与承诺校验</h3>
      <table><thead><tr><th>字段</th><th>明文值</th><th>Merkle 承诺</th><th>类型</th></tr></thead>
        <tbody>${disclosedRows || '<tr><td colspan="4" class="muted">无披露字段</td></tr>'}</tbody></table>
    </div>`;
}

async function submitVerify() {
  let presentation;
  try { presentation = JSON.parse($("#verify-input").value); }
  catch { return alert("presentation JSON 解析失败"); }
  const key = $("#idem-key").value.trim();
  if (!key) return alert("请填写幂等键");
  const r = await apiIdempotent("/api/verify", presentation, key);
  renderVerifyResult(r);
  return r;
}

$("#btn-verify").addEventListener("click", async () => {
  try { await submitVerify(); } catch (e) { alert("验证请求失败：" + e.message); }
});

$("#btn-replay").addEventListener("click", async () => {
  try {
    const r1 = await submitVerify();
    const r2 = await submitVerify();
    alert(`首次审计 #${r1.id}，重放返回 #${r2.id}（相同即幂等生效）`);
  } catch (e) { alert("重放失败：" + e.message); }
});

$("#same-key-concurrency").addEventListener("change", (e) => {
  if (!e.target.checked) return;
  e.target.checked = false;
  (async () => {
    let presentation;
    try { presentation = JSON.parse($("#verify-input").value); }
    catch { return alert("presentation JSON 解析失败"); }
    const key = $("#idem-key").value.trim() || uuid();
    $("#idem-key").value = key;
    $("#btn-verify").disabled = true;
    const results = await Promise.all(
      Array.from({ length: 5 }, () => apiIdempotent("/api/verify", presentation, key).catch((err) => ({ error: err.message })))
    );
    $("#btn-verify").disabled = false;
    const ids = results.map((r) => (r.error ? "ERR:" + r.error : "#" + r.id + (r.duplicate ? "(dup)" : "")));
    alert("5 个并发同键请求返回的审计记录：\n" + ids.join("\n") +
          "\n\n全部指向同一条审计即并发幂等生效。");
    const ok = results.find((r) => !r.error);
    if (ok) renderVerifyResult(ok);
  })();
});

// ---------- ⑤ 审计链 ----------

async function loadChain() {
  const data = await api("GET", "/api/audits/chain");
  $("#chain-status").innerHTML = data.chain_ok
    ? `<span class="badge ok">哈希链完整 · 共 ${data.length} 条</span>`
    : `<span class="badge bad">哈希链校验失败 · 共 ${data.length} 条（数据可能被篡改）</span>`;
  $("#chain-table tbody").innerHTML = data.entries.slice().reverse().map((e) => `
    <tr><td>${e.id}</td><td>${esc(e.created_at)}</td><td><code>${esc(e.idem_key.slice(0, 16))}…</code></td>
    <td>${e.credential_id ? `<code>${esc(e.credential_id.slice(0, 18))}…</code>` : "-"}</td>
    <td>${e.valid === true ? '<span class="badge ok">通过</span>' : e.valid === false ? '<span class="badge bad">失败</span>' : "-"}</td>
    <td>${e.duplicate ? '<span class="badge warn">重复</span>' : ""}</td>
    <td>${e.link_ok ? "✅" : "❌"}</td>
    <td><code style="font-size:11px">${esc(e.chain_hash.slice(0, 24))}…</code></td></tr>`).join("");
}

$("#btn-refresh-chain").addEventListener("click", () => loadChain().catch((e) => alert(e.message)));

// ---------- 启动 ----------

loadAdmin().catch((e) => console.error(e));
