/* 选择性披露凭证验证台 — 前端逻辑（原生 JS） */
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.className = "show" + (isError ? " error" : "");
  setTimeout(() => { el.className = ""; }, 3200);
}

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
  return data;
}

const short = (h) => (h ? h.slice(0, 12) + "…" : "-");
const uuid = () => crypto.randomUUID();

/* ================= 页签切换 ================= */
$$(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    $$(".tab").forEach((b) => b.classList.toggle("active", b === btn));
    $$(".panel").forEach((p) => p.classList.toggle("active", p.id === "tab-" + btn.dataset.tab));
    if (btn.dataset.tab === "verifier") refreshAudits();
    if (btn.dataset.tab === "issuer") refreshIssueForm();
  });
});

/* ================= 管理台：模板构建器 ================= */
const FIELD_TYPES = ["string", "integer", "number", "boolean", "date", "enum"];

function addFieldRow(f = {}) {
  const tbody = $("#tpl-fields tbody");
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td><input class="f-name" placeholder="字段名" value="${f.name || ""}"></td>
    <td><select class="f-type">${FIELD_TYPES.map(
      (t) => `<option ${t === f.type ? "selected" : ""}>${t}</option>`).join("")}</select></td>
    <td><input type="checkbox" class="f-required" ${f.required ? "checked" : ""}></td>
    <td><input class="f-values" placeholder="仅 enum 类型" value="${(f.values || []).join(",")}"></td>
    <td><button class="danger small f-del">删除</button></td>`;
  tr.querySelector(".f-del").addEventListener("click", () => tr.remove());
  tbody.appendChild(tr);
}

$("#btn-add-field").addEventListener("click", () => addFieldRow());

$("#btn-create-tpl").addEventListener("click", async () => {
  const name = $("#tpl-name").value.trim();
  if (!name) return toast("请填写模板名称", true);
  const fields = $$("#tpl-fields tbody tr").map((tr) => {
    const type = tr.querySelector(".f-type").value;
    const field = {
      name: tr.querySelector(".f-name").value.trim(),
      type,
      required: tr.querySelector(".f-required").checked,
    };
    if (type === "enum") {
      field.values = tr.querySelector(".f-values").value.split(",")
        .map((s) => s.trim()).filter(Boolean);
    }
    return field;
  });
  if (!fields.length) return toast("至少添加一个字段", true);
  try {
    const tpl = await api("/api/admin/templates", { method: "POST", body: { name, fields } });
    toast(`模板 ${tpl.name} v${tpl.version} 已创建`);
    $("#tpl-fields tbody").innerHTML = "";
    addFieldRow();
    await refreshAdmin();
  } catch (e) { toast(e.message, true); }
});

async function refreshTemplates() {
  const tpls = await api("/api/admin/templates");
  const tbody = $("#tpl-list tbody");
  tbody.innerHTML = "";
  for (const t of tpls) {
    const tr = document.createElement("tr");
    const fieldDesc = t.schema.fields
      .map((f) => `${f.name}:${f.type}${f.required ? "*" : ""}`).join(", ");
    tr.innerHTML = `
      <td>${t.name}</td><td>v${t.version}</td>
      <td class="mono">${fieldDesc}</td><td>${t.status}</td><td>${t.created_at}</td>
      <td></td>`;
    const btn = document.createElement("button");
    btn.className = "small " + (t.status === "active" ? "danger" : "secondary");
    btn.textContent = t.status === "active" ? "停用" : "启用";
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/admin/templates/${t.name}/${t.version}/status`, {
          method: "POST",
          body: { status: t.status === "active" ? "deprecated" : "active" },
        });
        await refreshAdmin();
      } catch (e) { toast(e.message, true); }
    });
    tr.lastElementChild.appendChild(btn);
    tbody.appendChild(tr);
  }
  // 同步签发端与撤销下拉框
  const opts = tpls.filter((t) => t.status === "active")
    .map((t) => `<option value="${t.name}|${t.version}">${t.name} v${t.version}</option>`).join("");
  $("#issue-tpl").innerHTML = opts;
  $("#rev-tpl").innerHTML = tpls
    .map((t) => `<option value="${t.name}|${t.version}">${t.name} v${t.version}</option>`).join("");
  return tpls;
}

/* ================= 管理台：密钥 ================= */
async function refreshKeys() {
  const keys = await api("/api/admin/keys");
  const tbody = $("#key-list tbody");
  tbody.innerHTML = "";
  for (const k of keys) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${k.kid}</td><td class="mono">${short(k.public_key)}</td>
      <td>${k.status}</td><td>${k.created_at}</td><td>${k.retired_at || "-"}</td>`;
    tbody.appendChild(tr);
  }
}

$("#btn-rotate").addEventListener("click", async () => {
  try {
    const k = await api("/api/admin/keys/rotate", { method: "POST", body: {} });
    toast(`已轮换密钥，新 KID: ${k.kid}`);
    await refreshKeys();
  } catch (e) { toast(e.message, true); }
});

/* ================= 管理台：撤销 ================= */
$("#btn-revoke").addEventListener("click", async () => {
  const sel = $("#rev-tpl").value;
  if (!sel) return toast("请先创建模板", true);
  const [template_name, version] = sel.split("|");
  const credential_id = $("#rev-cred").value.trim();
  if (!credential_id) return toast("请填写凭证 ID 或 *", true);
  try {
    await api("/api/admin/revocations", {
      method: "POST",
      body: { template_name, template_version: Number(version),
              credential_id, reason: $("#rev-reason").value },
    });
    toast("已加入撤销列表");
    $("#rev-cred").value = "";
    await refreshRevocations();
  } catch (e) { toast(e.message, true); }
});

async function refreshRevocations() {
  const list = await api("/api/admin/revocations");
  const tbody = $("#rev-list tbody");
  tbody.innerHTML = "";
  for (const r of list) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${r.template_name}</td><td>v${r.template_version}</td>
      <td class="mono">${r.credential_id}</td><td>${r.reason || "-"}</td><td>${r.revoked_at}</td>`;
    tbody.appendChild(tr);
  }
}

async function refreshAdmin() {
  await Promise.all([refreshTemplates(), refreshKeys(), refreshRevocations()]);
}

/* ================= 签发端 ================= */
let templatesCache = [];

function renderIssueFields(tpl) {
  const box = $("#issue-fields");
  box.innerHTML = "";
  if (!tpl) return;
  for (const f of tpl.schema.fields) {
    const div = document.createElement("div");
    div.className = "row";
    let input;
    if (f.type === "boolean") {
      input = `<select data-field="${f.name}"><option value="">（不填）</option>
        <option value="true">true</option><option value="false">false</option></select>`;
    } else if (f.type === "enum") {
      input = `<select data-field="${f.name}"><option value="">（不填）</option>${f.values
        .map((v) => `<option>${v}</option>`).join("")}</select>`;
    } else if (f.type === "integer" || f.type === "number") {
      input = `<input type="number" data-field="${f.name}" ${f.type === "number" ? 'step="any"' : ""}>`;
    } else if (f.type === "date") {
      input = `<input type="date" data-field="${f.name}">`;
    } else {
      input = `<input data-field="${f.name}">`;
    }
    div.innerHTML = `<label>${f.name}${f.required ? "（必填）" : ""} ${input}</label>`;
    box.appendChild(div);
  }
}

function currentIssueTemplate() {
  const sel = $("#issue-tpl").value;
  if (!sel) return null;
  const [name, version] = sel.split("|");
  return templatesCache.find((t) => t.name === name && String(t.version) === version);
}

function refreshIssueForm() {
  renderIssueFields(currentIssueTemplate());
}

$("#issue-tpl").addEventListener("change", refreshIssueForm);

$("#btn-issue").addEventListener("click", async () => {
  const tpl = currentIssueTemplate();
  if (!tpl) return toast("请先在管理台创建模板", true);
  const subject = $("#issue-subject").value.trim();
  if (!subject) return toast("请填写持有者 subject", true);
  const values = {};
  for (const el of $$("#issue-fields [data-field]")) {
    const f = tpl.schema.fields.find((x) => x.name === el.dataset.field);
    if (el.value === "") continue;
    if (f.type === "integer") values[f.name] = parseInt(el.value, 10);
    else if (f.type === "number") values[f.name] = parseFloat(el.value);
    else if (f.type === "boolean") values[f.name] = el.value === "true";
    else values[f.name] = el.value;
  }
  try {
    const cred = await api("/api/issuer/credentials", {
      method: "POST",
      body: { template_name: tpl.name, template_version: tpl.version,
              subject, values, valid_days: Number($("#issue-days").value || 365) },
    });
    $("#issue-result-card").hidden = false;
    $("#issue-result").textContent = JSON.stringify(cred, null, 2);
    $("#btn-to-holder").onclick = () => {
      $("#holder-cred-id").value = cred.credential_id;
      $(`.tab[data-tab="holder"]`).click();
      loadCredentialForHolder();
    };
    toast(`凭证已签发: ${cred.credential_id}`);
    await refreshCredentials();
  } catch (e) { toast(e.message, true); }
});

async function refreshCredentials() {
  const list = await api("/api/issuer/credentials");
  const tbody = $("#cred-list tbody");
  tbody.innerHTML = "";
  for (const c of list) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${c.credential_id}</td><td>${c.template_name}</td>
      <td>v${c.template_version}</td><td>${c.subject}</td><td>${c.created_at}</td>`;
    tbody.appendChild(tr);
  }
}

/* ================= 持有者 ================= */
let holderCredential = null;

async function loadCredentialForHolder() {
  const id = $("#holder-cred-id").value.trim();
  if (!id) return toast("请填写凭证 ID", true);
  try {
    holderCredential = await api(`/api/issuer/credentials/${encodeURIComponent(id)}`);
  } catch (e) {
    holderCredential = null;
    $("#btn-present").disabled = true;
    return toast(e.message, true);
  }
  const box = $("#holder-fields");
  box.innerHTML = "";
  for (const [name, value] of Object.entries(holderCredential.fields)) {
    const div = document.createElement("div");
    div.className = "field-row";
    div.innerHTML = `<label><input type="checkbox" data-disclose="${name}"> 披露</label>
      <span class="fname">${name}</span><span class="fvalue">${JSON.stringify(value)}</span>`;
    box.appendChild(div);
  }
  $("#btn-present").disabled = false;
  toast(`已加载凭证，共 ${Object.keys(holderCredential.fields).length} 个字段`);
}

$("#btn-load-cred").addEventListener("click", loadCredentialForHolder);

$("#btn-present").addEventListener("click", async () => {
  if (!holderCredential) return;
  const disclose = $$("#holder-fields [data-disclose]:checked")
    .map((el) => el.dataset.disclose);
  if (!disclose.length) return toast("至少勾选一个披露字段", true);
  try {
    const p = await api("/api/holder/presentations", {
      method: "POST",
      body: { credential_id: holderCredential.credential_id, disclose_fields: disclose },
    });
    $("#presentation-card").hidden = false;
    $("#presentation-output").textContent = JSON.stringify(p, null, 2);
    $("#btn-to-verifier").onclick = () => {
      $("#verify-input").value = JSON.stringify(p);
      $("#idem-key").value = uuid();
      $(`.tab[data-tab="verifier"]`).click();
    };
    $("#btn-download-presentation").onclick = () => {
      const blob = new Blob([JSON.stringify(p, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `presentation-${holderCredential.credential_id}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
    };
    toast(`已生成 presentation，披露 ${disclose.length} 个字段`);
  } catch (e) { toast(e.message, true); }
});

/* ================= 验证台 ================= */
const CHECK_LABELS = {
  key_registered: "签名密钥已登记（支持轮换后历史验证）",
  signature: "Ed25519 签名有效",
  template_version: "模板版本与哈希匹配",
  validity_period: "在有效期内",
  not_revoked: "未被撤销（按模板版本）",
  merkle_proofs: "Merkle 披露证明有效",
};

async function runVerify() {
  let presentation;
  try {
    presentation = JSON.parse($("#verify-input").value);
  } catch {
    return toast("Presentation JSON 解析失败", true);
  }
  const idempotency_key = $("#idem-key").value.trim();
  if (!idempotency_key) return toast("请填写幂等键", true);
  const data = await api("/api/verify", {
    method: "POST", body: { idempotency_key, presentation },
  });
  renderVerifyResult(data);
  return data;
}

function renderVerifyResult(data) {
  $("#verify-result-card").hidden = false;
  const ok = data.result === "valid";
  $("#verify-badge").innerHTML =
    `<span class="badge ${ok ? "valid" : "invalid"}">${ok ? "✓ 验证通过" : "✗ 验证失败"}</span>`;
  $("#verify-meta").innerHTML =
    `审计 #${data.audit.id} · ${data.deduplicated ? "<b>幂等去重命中（复用既有审计）</b>" : "新写入审计"}`
    + ` · hash <span class="mono">${short(data.audit.hash)}</span>`;

  const checksBody = $("#verify-checks tbody");
  checksBody.innerHTML = "";
  for (const [k, label] of Object.entries(CHECK_LABELS)) {
    const passed = data.checks[k];
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${label}</td>
      <td class="${passed ? "check-ok" : "check-bad"}">${passed ? "✓ 通过" : "✗ 未通过"}</td>`;
    checksBody.appendChild(tr);
  }

  const disBody = $("#verify-disclosed tbody");
  disBody.innerHTML = "";
  const entries = Object.entries(data.disclosed_fields || {});
  if (!entries.length) {
    disBody.innerHTML = `<tr><td colspan="2" style="color:var(--muted)">（无有效披露字段）</td></tr>`;
  }
  for (const [k, v] of entries) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="mono">${k}</td><td>${JSON.stringify(v)}</td>`;
    disBody.appendChild(tr);
  }

  $("#verify-failures").innerHTML = (data.failures || []).length
    ? `<ul class="failures">${data.failures.map((f) => `<li>${f}</li>`).join("")}</ul>` : "";
}

$("#btn-verify").addEventListener("click", async () => {
  try {
    const data = await runVerify();
    if (data) { toast(data.deduplicated ? "幂等命中：返回既有审计" : "验证完成"); await refreshAudits(); }
  } catch (e) { toast(e.message, true); }
});

$("#btn-verify-x5").addEventListener("click", async () => {
  let presentation;
  try {
    presentation = JSON.parse($("#verify-input").value);
  } catch { return toast("Presentation JSON 解析失败", true); }
  const idempotency_key = $("#idem-key").value.trim();
  if (!idempotency_key) return toast("请填写幂等键", true);
  try {
    const results = await Promise.all(Array.from({ length: 5 }, () =>
      api("/api/verify", { method: "POST", body: { idempotency_key, presentation } })));
    const ids = new Set(results.map((r) => r.audit.id));
    renderVerifyResult(results[0]);
    toast(ids.size === 1
      ? `并发 5 次提交 → 全部落到同一条审计 #${[...ids][0]}`
      : `出现异常：产生了 ${ids.size} 条审计`, ids.size !== 1);
    await refreshAudits();
  } catch (e) { toast(e.message, true); }
});

$("#btn-new-key").addEventListener("click", () => { $("#idem-key").value = uuid(); });

async function refreshAudits() {
  const list = await api("/api/audits");
  const tbody = $("#audit-list tbody");
  tbody.innerHTML = "";
  for (const a of list.slice().reverse()) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${a.id}</td><td>${a.created_at}</td>
      <td class="mono">${short(a.credential_id)}</td>
      <td class="${a.result === "valid" ? "check-ok" : "check-bad"}">${a.result}</td>
      <td class="mono">${short(a.idempotency_key)}</td>
      <td class="mono">${short(a.prev_hash)}</td><td class="mono">${short(a.hash)}</td>`;
    tbody.appendChild(tr);
  }
}

$("#btn-refresh-audits").addEventListener("click", refreshAudits);

$("#btn-verify-chain").addEventListener("click", async () => {
  try {
    const r = await api("/api/audits/verify-chain");
    $("#chain-result").textContent = r.valid
      ? `✓ 链完整，共 ${r.length} 条，head=${short(r.head)}`
      : `✗ 链断裂于 #${r.broken_at}：${r.detail}`;
    $("#chain-result").className = r.valid ? "check-ok" : "check-bad";
  } catch (e) { toast(e.message, true); }
});

/* ================= 初始化 ================= */
(async function init() {
  $("#idem-key").value = uuid();
  addFieldRow();
  try {
    templatesCache = await refreshTemplates();
    await Promise.all([refreshKeys(), refreshRevocations(), refreshCredentials()]);
    refreshIssueForm();
    await refreshAudits();
  } catch (e) { toast("初始化失败: " + e.message, true); }
})();
