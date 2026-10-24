/* TrustVault front end.
 *
 * Security notes for reviewers:
 *  - No innerHTML anywhere with data. Every string reaches the DOM through
 *    textContent (see h()). The CSP forbids inline script, so even a missed
 *    spot could not execute injected markup.
 *  - The UI hides buttons the user cannot use, but that is convenience only:
 *    every action is decided again by the server (app/authz.py).
 *  - The session cookie is HttpOnly; this script never sees it. It only holds
 *    the CSRF token, which it sends on state-changing requests.
 */
"use strict";

// ------------------------------------------------------------------ DOM helper
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k === "value") el.value = v;
    else if (k === "checked" || k === "disabled" || k === "selected" || k === "required") el[k] = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// replaceChildren that skips null/false, so conditional children never render as "null".
function put(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false));
}

const SVG_NS = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  for (const c of children.flat()) if (c) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}

function brandMark() {
  return s("svg", { viewBox: "0 0 32 32", class: "brand-mark", "aria-hidden": "true" },
    s("rect", { width: 32, height: 32, rx: 7, fill: "#2F4BA8" }),
    s("rect", { x: 9, y: 14, width: 14, height: 11, rx: 2, fill: "none", stroke: "#fff", "stroke-width": 2 }),
    s("path", { d: "M12 14v-3a4 4 0 0 1 8 0v3", fill: "none", stroke: "#fff", "stroke-width": 2 }),
    s("circle", { cx: 16, cy: 19.5, r: 1.6, fill: "#fff" }));
}

// ------------------------------------------------------------------ state & API
const state = { user: null, csrf: null, meta: null };

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, url, body) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (method !== "GET") opts.headers["X-CSRF-Token"] = state.csrf || "";
  if (body instanceof FormData) opts.body = body;
  else if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  let res;
  try { res = await fetch(url, opts); }
  catch { throw new ApiError(0, "Cannot reach TrustVault. Check your connection and try again."); }
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && !url.startsWith("/api/auth/login")) {
    state.user = null; state.csrf = null;
    renderSignIn("Your session ended. Sign in again to continue.");
    throw new ApiError(401, "Signed out");
  }
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || `Request failed (${res.status}).`);
  return data;
}

function toast(message, kind) {
  const t = h("div", { class: "toast" + (kind === "error" ? " error" : "") }, message);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), kind === "error" ? 6000 : 3500);
}

function fail(err) { if (err.status !== 401) toast(err.message, "error"); }

// ------------------------------------------------------------------ formatting
const fmtDate = (iso) => iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }) : "";
const fmtTime = (iso) => iso ? new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "";
function fmtSize(n) {
  if (n == null) return "";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
function ago(iso) {
  const sec = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (sec < 60) return "just now";
  if (sec < 3600) return `${Math.floor(sec / 60)} min ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} h ago`;
  return fmtDate(iso);
}
const ACCESS_LABEL = { owner: "Owner", edit: "Can edit", read: "Can view" };
function accessBadge(p) { return h("span", { class: `badge badge-${p || "muted"}` }, ACCESS_LABEL[p] || "No access"); }

const ACTION_TEXT = {
  "auth.login": "signed in", "auth.logout": "signed out", "auth.password_change": "changed their password",
  "document.upload": "uploaded", "document.view": "opened", "document.download": "downloaded",
  "document.update": "edited details of", "document.new_version": "uploaded a new version of",
  "document.delete": "moved to trash", "document.restore": "restored", "document.purge": "permanently deleted",
  "document.edit": "tried to edit", "document.share": "tried to manage sharing on", "document.access": "tried to reach",
  "permission.grant": "gave access to", "permission.change": "changed access for", "permission.revoke": "removed access for",
  "suggestion.shown": "was shown access suggestions for", "suggestion.dismissed": "dismissed a suggestion on",
  "admin.user_create": "created account", "admin.user_update": "updated account", "admin.sessions_revoked": "ended sessions of",
  "admin.audit_verified": "verified the audit chain", "security.csrf_rejected": "sent a forged request",
  "security.origin_rejected": "sent a cross-site request", "security.role_denied": "called a restricted endpoint",
};
// A refused event must never read like it happened: "downloaded" vs "tried to download".
const TRIED_TEXT = {
  view: "tried to open", download: "tried to download", edit: "tried to edit", share: "tried to manage sharing on",
  delete: "tried to delete", restore: "tried to restore", purge: "tried to permanently delete",
  upload: "tried to upload", access: "tried to reach", login: "failed to sign in", revoke: "tried to remove access on",
  password_change: "failed to change password",
};
function eventText(row) {
  if (row.outcome === "denied") {
    const t = TRIED_TEXT[row.action.split(".")[1]];
    if (t) return t;
  }
  if (row.outcome === "error" && row.action === "document.download") return "download failed integrity check for";
  return ACTION_TEXT[row.action] || row.action;
}
function describe(row) {
  const who = row.actor_username || "Someone";
  const target = row.target_username ? ` ${row.target_username}` : "";
  return `${who} ${eventText(row)}${target}`;
}

// Downloads go through fetch so a refusal (e.g. access removed a moment ago) shows a clear
// message instead of a broken browser download. One request either way; the server decides.
async function downloadFile(url, fallbackName) {
  let res;
  try { res = await fetch(url, { credentials: "same-origin" }); }
  catch { return toast("Cannot reach TrustVault. Check your connection and try again.", "error"); }
  if (res.status === 401) { state.user = null; return renderSignIn("Your session ended. Sign in again to continue."); }
  if (!res.ok) {
    let msg = "You don't have access to this file any more. The attempt was recorded.";
    if (res.status === 429) msg = "Too many downloads. Wait a minute and try again.";
    else if (res.status === 500) msg = "This file failed its integrity check and was not served.";
    return toast(msg, "error");
  }
  const cd = res.headers.get("Content-Disposition") || "";
  const m = /filename\*=UTF-8''([^;]+)/.exec(cd);
  const name = m ? decodeURIComponent(m[1]) : fallbackName || "download";
  const blob = await res.blob();
  const href = URL.createObjectURL(blob);
  const a = h("a", { href, download: name, hidden: true });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 10000);
}

// ------------------------------------------------------------------ routing
function go(hash) { if (location.hash !== hash) location.hash = hash; else route(); }
window.addEventListener("hashchange", () => route());

async function boot() {
  try {
    const me = await fetch("/api/auth/me", { credentials: "same-origin" });
    if (me.ok) {
      const u = await me.json();
      setUser(u);
      return route();
    }
  } catch { /* fall through to sign-in */ }
  renderSignIn();
}

function setUser(u) {
  state.user = u; state.csrf = u.csrf_token;
}

async function route() {
  if (!state.user) return renderSignIn();
  if (state.user.must_change_password) return renderShell(viewChangePassword, "password");
  if (!state.meta) { try { state.meta = await api("GET", "/api/meta"); } catch (e) { return fail(e); } }
  const parts = (location.hash.replace(/^#\/?/, "") || "documents").split("/");
  const admin = state.user.role === "admin";
  if (parts[0] === "documents" && parts[1]) return renderShell(() => viewDocument(parts[1]), "documents");
  if (parts[0] === "trash") return renderShell(viewTrash, "trash");
  if (parts[0] === "password") return renderShell(viewChangePassword, "password");
  if (parts[0] === "admin" && admin) {
    if (parts[1] === "activity") return renderShell(viewAudit, "admin-activity");
    if (parts[1] === "people") return renderShell(viewPeople, "admin-people");
    return renderShell(viewOverview, "admin");
  }
  return renderShell(viewDocuments, "documents");
}

function mount(node) {
  const app = document.getElementById("app");
  put(app, node);
}

// ------------------------------------------------------------------ sign in
function renderSignIn(message) {
  const err = h("p", { class: "form-error", role: "alert" }, message || "");
  const username = h("input", { name: "username", autocomplete: "username", required: true, autofocus: true, maxlength: 64 });
  const password = h("input", { name: "password", type: "password", autocomplete: "current-password", required: true, maxlength: 256 });
  const submit = h("button", { class: "btn-primary", type: "submit" }, "Sign in");
  const form = h("form", { class: "form-grid", onsubmit: async (e) => {
    e.preventDefault();
    submit.disabled = true; err.textContent = "";
    try {
      const u = await api("POST", "/api/auth/login", { username: username.value, password: password.value });
      setUser(u);
      password.value = "";
      route();
    } catch (ex) { err.textContent = ex.message; password.value = ""; password.focus(); }
    finally { submit.disabled = false; }
  } },
    h("label", { class: "field" }, "Username", username),
    h("label", { class: "field" }, "Password", password),
    err, submit);

  const sample = [
    ["09:14:02", "allowed", "victor downloaded Offer letter v1"],
    ["09:14:37", "denied", "victor was refused: Salary bands 2026"],
    ["09:15:10", "allowed", "olivia removed access for victor"],
    ["09:15:12", "denied", "victor was refused: Offer letter"],
  ];
  mount(h("div", { class: "signin" },
    h("section", { class: "signin-story" },
      h("div", { class: "brand" }, brandMark(), "TrustVault"),
      h("div", null,
        h("h1", null, "Every opening is on the record."),
        h("p", { class: "lede" }, "Confidential documents reach only the people they were given to. Every view, download, refusal and change of access is written to a chained ledger that cannot be quietly edited.")),
      h("div", { class: "ledger-sample", "aria-hidden": "true" },
        sample.map(([t, o, w]) => h("div", null, h("span", null, t), h("span", { class: o === "allowed" ? "ok" : "no" }, o), h("span", null, w))))),
    h("section", { class: "signin-form" },
      h("div", { class: "signin-card" },
        h("div", null, h("h2", null, "Sign in"), h("p", { class: "sub" }, "Accounts are created by your administrator.")),
        form))));
}

// ------------------------------------------------------------------ shell
function renderShell(view, active) {
  const u = state.user;
  const link = (hash, label, key) => h("a", { href: hash, "aria-current": active === key ? "page" : null }, label);
  const nav = [link("#/documents", "Documents", "documents")];
  if (u.role === "owner") nav.push(link("#/trash", "Trash", "trash"));
  if (u.role === "admin") {
    nav.push(h("div", { class: "group" }, "Administration"),
      link("#/admin", "Overview", "admin"),
      link("#/admin/activity", "Activity log", "admin-activity"),
      link("#/admin/people", "People", "admin-people"));
  }
  const main = h("main", { id: "main" }, h("div", { class: "loading" }, "Loading…"));
  mount(h("div", { class: "shell" },
    h("aside", { class: "rail" },
      h("div", { class: "brand" }, brandMark(), "TrustVault"),
      h("nav", { "aria-label": "Main" }, nav),
      h("div", { class: "me" },
        h("div", null, h("div", { class: "name" }, u.display_name), h("div", { class: "role" }, `@${u.username} · ${roleName(u.role)}`)),
        h("a", { href: "#/password", class: "btn btn-quiet btn-small", style: null }, "Change password"),
        h("button", { onclick: signOut }, "Sign out"))),
    main));
  Promise.resolve(view(main)).catch(fail);
}

function roleName(r) { return { admin: "Administrator", owner: "Document owner", viewer: "Viewer" }[r] || r; }

async function signOut() {
  try { await api("POST", "/api/auth/logout"); } catch { /* ignore */ }
  state.user = null; state.csrf = null; state.meta = null;
  location.hash = "";
  renderSignIn();
}

function pageHead(title, sub, ...actions) {
  return h("div", { class: "page-head" },
    h("div", null, h("h1", null, title), sub ? h("p", { class: "sub" }, sub) : null),
    actions.length ? h("div", null, actions) : null);
}

// ------------------------------------------------------------------ documents list
const listState = { q: "", owner: "", category: "", from: "", to: "", scope: "all", page: 1 };

async function viewDocuments(main) {
  const canUpload = state.user.role === "owner";
  const tableHost = h("div");
  const debounced = debounce(() => { listState.page = 1; load(); }, 250);
  const input = (key, attrs) => {
    const el = h("input", Object.assign({ value: listState[key], oninput: (e) => { listState[key] = e.target.value; debounced(); } }, attrs));
    return el;
  };
  const cat = h("select", { onchange: (e) => { listState.category = e.target.value; listState.page = 1; load(); } },
    h("option", { value: "" }, "All categories"),
    state.meta.categories.map((c) => h("option", { value: c, selected: listState.category === c }, c)));
  const scopeBtn = (value, label) => h("button", { type: "button", "aria-pressed": String(listState.scope === value),
    onclick: () => { listState.scope = value; listState.page = 1; put(main); viewDocuments(main); } }, label);

  put(main, 
    pageHead("Documents", state.user.role === "viewer"
      ? "Documents people have shared with you. You can only see what you were given."
      : "Your documents and the ones shared with you.",
      canUpload ? h("button", { class: "btn-primary", onclick: () => uploadDialog() }, "Upload document") : null),
    h("div", { class: "sheet" },
      h("div", { class: "sheet-head" },
        h("div", { class: "scope", role: "group", "aria-label": "Show" },
          scopeBtn("all", "All"), scopeBtn("mine", "Owned by me"), scopeBtn("shared", "Shared with me")),
        h("div", { class: "sub", id: "count" })),
      h("div", { class: "filters" },
        h("label", null, "Name", input("q", { type: "search", placeholder: "Title, description or file name", maxlength: 100 })),
        h("label", null, "Owner", input("owner", { type: "search", placeholder: "Name or username", maxlength: 64 })),
        h("label", null, "Category", cat),
        h("label", null, "Uploaded from", input("from", { type: "date" })),
        h("label", null, "Uploaded to", input("to", { type: "date" }))),
      tableHost));

  async function load() {
    const p = new URLSearchParams({ scope: listState.scope, page: listState.page, page_size: 25 });
    for (const k of ["q", "owner", "category", "from", "to"]) if (listState[k]) p.set(k, listState[k]);
    let data;
    try { data = await api("GET", "/api/documents?" + p); } catch (e) { return fail(e); }
    const count = document.getElementById("count");
    if (count) count.textContent = `${data.total} document${data.total === 1 ? "" : "s"}`;
    if (!data.items.length) {
      const filtered = ["q", "owner", "category", "from", "to"].some((k) => listState[k]);
      put(tableHost, h("div", { class: "empty" },
        h("strong", null, filtered ? "Nothing matches these filters" : "No documents yet"),
        h("span", null, filtered ? "Clear a filter to widen the search."
          : canUpload ? "Upload a document, then choose exactly who can open it." : "When someone shares a document with you, it appears here."),
        !filtered && canUpload ? h("button", { class: "btn-primary", onclick: () => uploadDialog() }, "Upload document") : null));
      return;
    }
    const rows = data.items.map((d) => h("tr", { class: "link", onclick: (e) => { if (e.target.tagName !== "A") go(`#/documents/${d.id}`); } },
      h("td", null,
        h("a", { class: "title", href: `#/documents/${d.id}` }, d.title),
        h("div", { class: "meta" }, d.current_version ? `${d.current_version.filename} · v${d.current_version.version_no}` : "")),
      h("td", { class: "hide-sm" }, d.category),
      h("td", null, d.owner.display_name, h("div", { class: "meta" }, `@${d.owner.username}`)),
      h("td", null, accessBadge(d.my_permission)),
      h("td", { class: "num hide-sm" }, fmtDate(d.updated_at)),
      h("td", { class: "num hide-sm" }, fmtSize(d.current_version && d.current_version.size_bytes))));
    const pages = Math.max(1, Math.ceil(data.total / data.page_size));
    put(tableHost, 
      h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "Document"), h("th", { class: "hide-sm" }, "Category"), h("th", null, "Owner"),
          h("th", null, "Your access"), h("th", { class: "hide-sm" }, "Updated"), h("th", { class: "hide-sm" }, "Size"))),
        h("tbody", null, rows))),
      pages > 1 ? h("div", { class: "pager" },
        h("span", null, `Page ${data.page} of ${pages}`),
        h("span", null,
          h("button", { class: "btn-small", disabled: data.page <= 1, onclick: () => { listState.page--; load(); } }, "Previous"), " ",
          h("button", { class: "btn-small", disabled: data.page >= pages, onclick: () => { listState.page++; load(); } }, "Next"))) : null);
  }
  load();
}

function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

// ------------------------------------------------------------------ dialogs
function dialog(title, body, actions) {
  const d = h("dialog", { "aria-labelledby": "dlg-title" },
    h("div", { class: "dhead" }, h("h2", { id: "dlg-title" }, title)),
    h("div", { class: "dbody" }, body),
    h("div", { class: "dfoot" }, actions));
  d.addEventListener("close", () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}

function confirmDialog(title, text, confirmLabel, danger) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); d.close(); } };
    const d = dialog(title, h("p", null, text), [
      h("button", { onclick: () => finish(false) }, "Cancel"),
      h("button", { class: danger ? "btn-danger" : "btn-primary", onclick: () => finish(true) }, confirmLabel)]);
    d.addEventListener("close", () => finish(false));
  });
}

function fileField(onPick) {
  const allowed = state.meta.allowed_extensions.map((e) => "." + e).join(",");
  const label = h("span", null, "Choose a file");
  const wrap = h("label", { class: "drop" });
  const input = h("input", { type: "file", accept: allowed, required: true, onchange: () => {
    const f = input.files[0];
    if (!f) return;
    label.textContent = `${f.name} · ${fmtSize(f.size)}`;
    wrap.classList.add("has-file");
    if (f.size > state.meta.max_upload_bytes) toast(`That file is over ${fmtSize(state.meta.max_upload_bytes)}.`, "error");
    if (onPick) onPick(f);
  } });
  wrap.append(label, input,
    h("span", { class: "hint" }, `PDF, Word, Excel, PowerPoint, text, CSV, Markdown, PNG or JPEG · up to ${fmtSize(state.meta.max_upload_bytes)}`));
  return { el: wrap, input };
}

function uploadDialog() {
  const err = h("p", { class: "form-error", role: "alert" });
  const title = h("input", { name: "title", required: true, maxlength: 200 });
  const category = h("select", { name: "category" }, state.meta.categories.map((c) => h("option", { value: c }, c)));
  const description = h("textarea", { name: "description", maxlength: 2000 });
  const file = fileField((f) => { if (!title.value) title.value = f.name.replace(/\.[^.]+$/, ""); });
  const submit = h("button", { class: "btn-primary", type: "submit", form: "upload-form" }, "Upload");
  const form = h("form", { id: "upload-form", class: "form-grid", onsubmit: async (e) => {
    e.preventDefault();
    if (!file.input.files[0]) { err.textContent = "Choose a file to upload."; return; }
    const fd = new FormData();
    fd.append("title", title.value); fd.append("category", category.value);
    fd.append("description", description.value); fd.append("file", file.input.files[0]);
    submit.disabled = true; err.textContent = "";
    try {
      const doc = await api("POST", "/api/documents", fd);
      d.close(); toast("Uploaded. Only you can open it until you share it.");
      go(`#/documents/${doc.id}`);
    } catch (ex) { err.textContent = ex.message; }
    finally { submit.disabled = false; }
  } },
    file.el,
    h("label", { class: "field" }, "Title", title),
    h("label", { class: "field" }, "Category", category),
    h("label", { class: "field" }, h("span", null, "Description ", h("span", { class: "hint" }, "(optional)")), description),
    h("p", { class: "notice notice-info" }, "New documents are private. Nobody else can open this until you add them."),
    err);
  const d = dialog("Upload document", form, [h("button", { type: "button", onclick: () => d.close() }, "Cancel"), submit]);
}

// ------------------------------------------------------------------ document detail
async function viewDocument(id, main) {
  main = main || document.getElementById("main");
  let doc;
  try { doc = await api("GET", `/api/documents/${encodeURIComponent(id)}`); }
  catch (e) {
    if (e.status === 404 || e.status === 403) {
      put(main, h("a", { class: "back", href: "#/documents" }, "‹ All documents"),
        h("div", { class: "sheet empty" }, h("strong", null, "This document isn't available to you"),
          h("span", null, "It doesn't exist, or nobody has shared it with you. If you need it, ask its owner."),
          h("span", { class: "hint" }, "This attempt has been recorded.")));
      return;
    }
    throw e;
  }
  const owner = doc.my_permission === "owner";
  const canEdit = owner || doc.my_permission === "edit";
  const v = doc.current_version;
  const refresh = () => viewDocument(id, main);

  const actions = [];
  if (!doc.in_trash) {
    actions.push(h("button", { class: "btn-primary", onclick: () => downloadFile(`/api/documents/${doc.id}/download`, v && v.filename) }, "Download"));
    if (canEdit) actions.push(h("button", { onclick: () => editDialog(doc, refresh) }, "Edit details"),
      h("button", { onclick: () => versionDialog(doc, refresh) }, "Upload new version"));
    if (owner) actions.push(h("button", { class: "btn-danger", onclick: async () => {
      if (!(await confirmDialog("Move to trash?", `"${doc.title}" will stop being available to everyone it is shared with. You can restore it from Trash for ${30} days.`, "Move to trash", true))) return;
      try { await api("DELETE", `/api/documents/${doc.id}`); toast("Moved to trash. Shared access is suspended."); go("#/documents"); } catch (e) { fail(e); }
    } }, "Move to trash"));
  } else if (owner) {
    actions.push(h("button", { class: "btn-primary", onclick: async () => {
      try { await api("POST", `/api/documents/${doc.id}/restore`); toast("Restored. Earlier sharing applies again."); refresh(); } catch (e) { fail(e); }
    } }, "Restore"));
  }

  const left = h("div", { class: "stack" },
    doc.in_trash ? h("p", { class: "notice notice-warn" }, `In trash since ${fmtTime(doc.deleted_at)}. Nobody it was shared with can open it.`) : null,
    h("section", { class: "sheet sheet-pad" },
      h("h2", { style: null }, "Details"),
      h("dl", { class: "kv", style: null },
        h("dt", null, "Description"), h("dd", null, doc.description || "No description."),
        h("dt", null, "Current file"), h("dd", null, v ? `${v.filename} (${fmtSize(v.size_bytes)})` : "—"),
        h("dt", null, "Uploaded"), h("dd", null, fmtTime(doc.created_at)),
        h("dt", null, "Last change"), h("dd", null, fmtTime(doc.updated_at)),
        h("dt", null, "SHA-256"), h("dd", { class: "hash" }, (doc.versions[0] || {}).sha256 || ""))),
    h("section", { class: "sheet" },
      h("div", { class: "sheet-head" }, h("div", null, h("h2", null, "Versions"),
        h("div", { class: "sub" }, "Every upload is kept. Download any earlier version."))),
      h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "Version"), h("th", null, "File"), h("th", { class: "hide-sm" }, "By"), h("th", { class: "hide-sm" }, "When"), h("th", null, ""))),
        h("tbody", null, doc.versions.map((ver) => h("tr", null,
          h("td", { class: "num" }, `v${ver.version_no}`),
          h("td", null, ver.filename || ver.original_filename, h("div", { class: "meta" }, fmtSize(ver.size_bytes))),
          h("td", { class: "hide-sm" }, ver.uploaded_by),
          h("td", { class: "num hide-sm" }, fmtTime(ver.created_at)),
          h("td", null, doc.in_trash ? null : h("button", { class: "btn-small", onclick: () => downloadFile(`/api/documents/${doc.id}/download?version=${encodeURIComponent(ver.id)}`, ver.original_filename) }, "Download")))))))));

  const right = h("div", { class: "stack" });
  if (owner && !doc.in_trash) {
    right.append(await sharingPanel(doc));
  } else if (!owner) {
    right.append(h("section", { class: "sheet sheet-pad" },
      h("h2", null, "Your access"),
      h("p", { style: null }, accessBadge(doc.my_permission)),
      h("p", { class: "meta" }, doc.my_permission === "edit"
        ? "You can download, edit details and upload new versions. Only the owner can share or delete it."
        : "You can open and download this document. Only the owner can change it or share it."),
      h("p", { class: "meta" }, "Your downloads are recorded.")));
  }
  if (owner && !doc.in_trash) right.append(await activityPanel(doc));

  put(main, 
    h("a", { class: "back", href: "#/documents" }, "‹ All documents"),
    h("header", { class: "doc-head" },
      h("h1", null, doc.title),
      h("div", { class: "facts" },
        h("span", null, doc.category),
        h("span", null, `Owned by ${doc.owner.display_name}`),
        v ? h("span", null, `Version ${v.version_no}`) : null,
        accessBadge(doc.my_permission)),
      h("div", { class: "actions" }, actions)),
    h("div", { class: "doc-grid" }, left, right));
}

function editDialog(doc, done) {
  const err = h("p", { class: "form-error", role: "alert" });
  const title = h("input", { value: doc.title, required: true, maxlength: 200 });
  const category = h("select", null, state.meta.categories.map((c) => h("option", { value: c, selected: c === doc.category }, c)));
  const description = h("textarea", { maxlength: 2000 }, doc.description);
  const save = h("button", { class: "btn-primary", onclick: async () => {
    save.disabled = true;
    try {
      await api("PATCH", `/api/documents/${doc.id}`, { title: title.value, category: category.value, description: description.value });
      d.close(); toast("Details saved."); done();
    } catch (e) { err.textContent = e.message; } finally { save.disabled = false; }
  } }, "Save details");
  const d = dialog("Edit details", h("div", { class: "form-grid" },
    h("label", { class: "field" }, "Title", title), h("label", { class: "field" }, "Category", category),
    h("label", { class: "field" }, "Description", description), err),
  [h("button", { onclick: () => d.close() }, "Cancel"), save]);
}

function versionDialog(doc, done) {
  const err = h("p", { class: "form-error", role: "alert" });
  const file = fileField();
  const up = h("button", { class: "btn-primary", onclick: async () => {
    if (!file.input.files[0]) { err.textContent = "Choose a file to upload."; return; }
    const fd = new FormData(); fd.append("file", file.input.files[0]);
    up.disabled = true;
    try { await api("POST", `/api/documents/${doc.id}/versions`, fd); d.close(); toast("New version uploaded."); done(); }
    catch (e) { err.textContent = e.message; } finally { up.disabled = false; }
  } }, "Upload version");
  const d = dialog("Upload a new version", h("div", { class: "form-grid" },
    file.el, h("p", { class: "meta" }, "Earlier versions stay available in the version list."), err),
  [h("button", { onclick: () => d.close() }, "Cancel"), up]);
}

// ------------------------------------------------------------------ sharing panel (owner)
async function sharingPanel(doc) {
  const panel = h("section", { class: "sheet" });
  async function render() {
    let grants, sugg;
    try {
      [grants, sugg] = await Promise.all([
        api("GET", `/api/documents/${doc.id}/grants`),
        api("GET", `/api/documents/${doc.id}/suggestions`)]);
    } catch (e) { return fail(e); }

    const list = grants.items.length
      ? h("ul", { class: "people" }, grants.items.map((g) => {
          const sel = h("select", { "aria-label": `Access for ${g.user.display_name}`, onchange: async () => {
            try { await api("POST", `/api/documents/${doc.id}/grants`, { username: g.user.username, permission: sel.value, expires_at: g.expires_at || null }); toast(`${g.user.display_name} ${sel.value === "edit" ? "can now edit" : "can now only view"}.`); render(); }
            catch (e) { fail(e); render(); }
          } }, h("option", { value: "read", selected: g.permission === "read" }, "Can view"), h("option", { value: "edit", selected: g.permission === "edit" }, "Can edit"));
          return h("li", null,
            h("div", null,
              h("div", { class: "who" }, g.user.display_name, " ", h("span", { class: "meta" }, `@${g.user.username}`)),
              h("div", { class: "when" }, g.expired ? h("span", { class: "badge badge-denied" }, "Expired") :
                g.expires_at ? `Until ${fmtDate(new Date(new Date(g.expires_at).getTime() - 1).toISOString())}` : `Since ${fmtDate(g.created_at)}`)),
            h("div", { class: "controls" }, sel,
              h("button", { class: "btn-quiet btn-small", "aria-label": `Remove ${g.user.display_name}`, onclick: async () => {
                if (!(await confirmDialog(`Remove ${g.user.display_name}?`, "Their access ends immediately, including in any browser where they are signed in right now.", "Remove access", true))) return;
                try { await api("DELETE", `/api/documents/${doc.id}/grants/${g.id}`); toast(`${g.user.display_name} can no longer open this.`); render(); } catch (e) { fail(e); }
              } }, "Remove")));
        }))
      : h("p", { class: "sheet-pad meta" }, "Only you can open this document.");

    const suggestBox = sugg.items.length ? h("div", { class: "suggest" },
      h("div", { class: "suggest-head" }, h("strong", null, "Suggested people"), " · based on who you already share similar documents with"),
      sugg.items.map((sg) => h("div", { class: "suggest-item" },
        h("div", null, h("div", { class: "who" }, sg.user.display_name, " ", h("span", { class: "meta" }, ACCESS_LABEL[sg.permission].toLowerCase())),
          h("div", { class: "why" }, sg.reason)),
        h("div", { class: "controls" },
          h("button", { class: "btn-small btn-primary", onclick: async () => {
            const ok = await confirmDialog(`Give ${sg.user.display_name} access?`,
              `${sg.user.display_name} will be able to ${sg.permission === "edit" ? "open, download and edit" : "open and download"} "${doc.title}". The suggestion and your decision are both recorded.`, "Give access");
            if (!ok) return;
            try { await api("POST", `/api/documents/${doc.id}/grants`, { username: sg.user.username, permission: sg.permission, suggestion_id: sg.id }); toast(`${sg.user.display_name} can now open this.`); render(); } catch (e) { fail(e); }
          } }, "Add"),
          h("button", { class: "btn-small btn-quiet", onclick: async () => {
            try { await api("POST", `/api/documents/${doc.id}/suggestions/${sg.id}/dismiss`); render(); } catch (e) { fail(e); }
          } }, "Dismiss")))),
      h("div", { class: "why" }, "Suggestions never change access. Nothing happens until you press Add.")) : null;

    // add person
    const err = h("p", { class: "form-error", role: "alert" });
    const who = h("input", { placeholder: "Name or username", autocomplete: "off", "aria-label": "Person to add", maxlength: 64 });
    const perm = h("select", { "aria-label": "Access level" }, h("option", { value: "read" }, "Can view"), h("option", { value: "edit" }, "Can edit"));
    const until = h("input", { type: "date", "aria-label": "Access ends", min: new Date(Date.now() + 86400000).toISOString().slice(0, 10) });
    const picks = h("ul", { hidden: true, role: "listbox" });
    let chosen = null;
    who.addEventListener("input", debounce(async () => {
      chosen = null;
      const q = who.value.trim();
      if (q.length < 2) { picks.hidden = true; return; }
      try {
        const r = await api("GET", "/api/users/lookup?q=" + encodeURIComponent(q));
        put(picks, ...r.items.map((u) => h("li", null, h("button", { type: "button", onclick: () => {
          chosen = u.username; who.value = u.display_name; picks.hidden = true; } },
          u.display_name, h("span", { class: "u" }, `@${u.username}`)))));
        picks.hidden = !r.items.length;
      } catch (e) { fail(e); }
    }, 200));
    const add = h("button", { class: "btn-primary", type: "submit" }, "Give access");
    const form = h("form", { class: "add-person", onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      const username = chosen || who.value.trim().replace(/^@/, "");
      if (!username) { err.textContent = "Choose a person."; return; }
      add.disabled = true;
      try {
        await api("POST", `/api/documents/${doc.id}/grants`, { username, permission: perm.value, expires_at: until.value || null });
        toast("Access given."); render();
      } catch (ex) { err.textContent = ex.message; } finally { add.disabled = false; }
    } },
      h("div", { class: "lookup" }, who, picks), perm,
      h("div", { class: "row2" }, h("label", { class: "field" }, h("span", null, "Access ends ", h("span", { class: "hint" }, "(optional)")), until), add),
      err);

    put(panel, 
      h("div", { class: "sheet-head" }, h("div", null, h("h2", null, "Who can open this"),
        h("div", { class: "sub" }, "Named people only. Removing someone takes effect on their next click."))),
      list, suggestBox, form);
  }
  await render();
  return panel;
}

async function activityPanel(doc) {
  let data;
  try { data = await api("GET", `/api/documents/${doc.id}/activity`); } catch (e) { fail(e); return h("div"); }
  return h("section", { class: "sheet" },
    h("div", { class: "sheet-head" }, h("div", null, h("h2", null, "Record for this document"),
      h("div", { class: "sub" }, "Every view, download, refusal and change of access."))),
    data.items.length ? h("ol", { class: "timeline" }, data.items.slice(0, 40).map((r) => h("li", null,
      h("span", { class: `dot ${r.outcome}` }),
      h("div", null, h("div", { class: "what" }, describe(r), r.outcome !== "allowed" ? [" ", h("span", { class: `badge badge-${r.outcome}` }, r.outcome === "denied" ? "refused" : r.outcome)] : null),
        h("div", { class: "when" }, fmtTime(r.ts)))))) : h("p", { class: "sheet-pad meta" }, "Nothing recorded yet."));
}

// ------------------------------------------------------------------ trash
async function viewTrash(main) {
  const data = await api("GET", "/api/documents/trash");
  const purgeDate = (iso) => fmtDate(new Date(new Date(iso).getTime() + data.retention_days * 86400000).toISOString());
  put(main, 
    pageHead("Trash", `Documents here can't be opened by anyone you shared them with. They are destroyed for good after ${data.retention_days} days.`),
    h("div", { class: "sheet" }, data.items.length ? h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Document"), h("th", { class: "hide-sm" }, "Deleted"), h("th", { class: "hide-sm" }, "Destroyed on"), h("th", null, ""))),
      h("tbody", null, data.items.map((d) => h("tr", null,
        h("td", null, h("a", { class: "title", href: `#/documents/${d.id}` }, d.title), h("div", { class: "meta" }, d.category)),
        h("td", { class: "num hide-sm" }, fmtTime(d.deleted_at)),
        h("td", { class: "num hide-sm" }, purgeDate(d.deleted_at)),
        h("td", { style: null }, h("button", { class: "btn-small", onclick: async () => {
          try { await api("POST", `/api/documents/${d.id}/restore`); toast("Restored."); viewTrash(main); } catch (e) { fail(e); } } }, "Restore"), " ",
          h("button", { class: "btn-small btn-danger", onclick: async () => {
            if (!(await confirmDialog("Delete forever?", `Every version of "${d.title}" will be destroyed now. The audit record of it stays.`, "Delete forever", true))) return;
            try { await api("POST", `/api/documents/${d.id}/purge`); toast("Destroyed."); viewTrash(main); } catch (e) { fail(e); } } }, "Delete forever")))))))
      : h("div", { class: "empty" }, h("strong", null, "Trash is empty"), h("span", null, "Deleted documents wait here before they are destroyed."))));
}

// ------------------------------------------------------------------ change password
function viewChangePassword(main) {
  const forced = state.user.must_change_password;
  const err = h("p", { class: "form-error", role: "alert" });
  const cur = h("input", { type: "password", autocomplete: "current-password", required: true });
  const next = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: 12 });
  const again = h("input", { type: "password", autocomplete: "new-password", required: true });
  const btn = h("button", { class: "btn-primary", type: "submit" }, "Change password");
  put(main, 
    pageHead(forced ? "Choose your password" : "Change password",
      forced ? "Your administrator gave you a temporary password. Choose your own before you continue." : "Changing your password signs you out everywhere else."),
    h("div", { class: "sheet sheet-pad", style: null },
      h("form", { class: "form-grid", onsubmit: async (e) => {
        e.preventDefault(); err.textContent = "";
        if (next.value !== again.value) { err.textContent = "The new passwords don't match."; return; }
        btn.disabled = true;
        try {
          const u = await api("POST", "/api/auth/change-password", { current_password: cur.value, new_password: next.value });
          setUser(u); toast("Password changed. Other sessions were signed out."); go("#/documents");
        } catch (ex) { err.textContent = ex.message; } finally { btn.disabled = false; }
      } },
        h("label", { class: "field" }, forced ? "Temporary password" : "Current password", cur),
        h("label", { class: "field" }, h("span", null, "New password ", h("span", { class: "hint" }, "at least 12 characters")), next),
        h("label", { class: "field" }, "Repeat new password", again), err, h("div", null, btn))));
}

// ------------------------------------------------------------------ admin: overview
const LOCK = () => s("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "aria-hidden": "true" },
  s("rect", { x: 5, y: 11, width: 14, height: 10, rx: 2 }), s("path", { d: "M8 11V7a4 4 0 0 1 8 0v4" }));
const BROKEN = () => s("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2, "aria-hidden": "true" },
  s("path", { d: "M12 3 2 21h20L12 3z" }), s("path", { d: "M12 10v5M12 18v.5" }));

async function viewOverview(main) {
  const [sum, recent] = await Promise.all([api("GET", "/api/admin/summary"), api("GET", "/api/admin/audit?page_size=6")]);
  const st = sum.stats;
  const strip = h("div", { class: "sheet ledger-strip" },
    [["Active people", st.users], ["Live documents", st.documents], ["Downloads, 24 h", st.downloads_24h],
     ["Refusals, 24 h", st.refusals_24h, st.refusals_24h > 0], ["Access changes, 24 h", st.permission_changes_24h]]
      .map(([k, v, alert]) => h("div", null, h("div", { class: "v" + (alert ? " alert" : "") }, v), h("div", { class: "k" }, k))));

  // hourly chart
  const W = 600, H = 150, pad = 18, bw = (W - pad) / 24;
  const max = Math.max(4, ...sum.hourly.map((x) => x.allowed + x.denied));
  const bars = sum.hourly.flatMap((x, i) => {
    const ha = (x.allowed / max) * (H - pad - 4), hd = (x.denied / max) * (H - pad - 4);
    const xpos = pad + i * bw + 2;
    return [
      s("rect", { x: xpos, y: H - pad - ha, width: bw - 4, height: Math.max(0, ha), fill: "#2E7D5B", rx: 1 },
        s("title", null, `${fmtTime(x.hour)}: ${x.allowed} allowed`)),
      s("rect", { x: xpos, y: H - pad - ha - hd, width: bw - 4, height: Math.max(0, hd), fill: "#B3261E", rx: 1 },
        s("title", null, `${fmtTime(x.hour)}: ${x.denied} refused`)),
    ];
  });
  const chart = s("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Allowed and refused events per hour, last 24 hours" },
    s("line", { x1: pad, y1: H - pad, x2: W, y2: H - pad, stroke: "#D5DBE3" }),
    s("text", { x: pad, y: H - 3, "font-size": 10, fill: "#5B6578" }, "24 h ago"),
    s("text", { x: W - 2, y: H - 3, "font-size": 10, fill: "#5B6578", "text-anchor": "end" }, "now"),
    bars);

  const sealHost = h("section", { class: "sheet" });
  renderSeal(sealHost, null);

  put(main, 
    pageHead("Overview", "What happened in the last 24 hours, and anything worth a closer look."),
    strip,
    h("div", { class: "admin-grid" },
      h("div", { class: "stack" },
        h("section", { class: "sheet" },
          h("div", { class: "sheet-head" }, h("div", null, h("h2", null, "Worth a look"),
            h("div", { class: "sub" }, "Patterns that usually mean probing, guessing or data leaving."))),
          sum.alerts.length ? h("ul", { class: "alerts" }, sum.alerts.map((a) => h("li", { class: a.severity },
            h("div", { class: "t" }, a.title), h("div", { class: "d" }, a.detail),
            a.actor ? h("div", null, h("a", { href: "#/admin/activity", onclick: () => { auditState.actor = a.actor; auditState.outcome = ""; } }, `See ${a.actor}'s activity`)) : null)))
            : h("div", { class: "empty" }, h("strong", null, "Nothing unusual"), h("span", null, "No repeated refusals, bulk downloads or password guessing."))),
        h("section", { class: "sheet" },
          h("div", { class: "sheet-head" }, h("h2", null, "Activity, last 24 hours")),
          h("div", { class: "chart" }, chart, h("div", { class: "legend" }, h("span", null, "Allowed"), h("span", { class: "denied" }, "Refused"))))),
      h("div", { class: "stack" },
        sealHost,
        h("section", { class: "sheet" },
          h("div", { class: "sheet-head" }, h("h2", null, "Latest events"), h("a", { href: "#/admin/activity", class: "btn btn-small" }, "Full log")),
          h("ol", { class: "timeline" }, recent.items.map((r) => h("li", null, h("span", { class: `dot ${r.outcome}` }),
            h("div", null, h("div", { class: "what" }, describe(r), r.document_title ? [" ", h("em", null, r.document_title)] : null),
              h("div", { class: "when" }, ago(r.ts))))))))));
}

function renderSeal(host, result) {
  const verify = h("button", { class: "btn-small", onclick: async () => {
    verify.disabled = true;
    try { renderSeal(host, await api("GET", "/api/admin/audit/verify")); } catch (e) { fail(e); verify.disabled = false; }
  } }, result ? "Verify again" : "Verify now");
  let ring, stateText, detail;
  if (!result) { ring = h("div", { class: "seal-ring unknown" }, LOCK()); stateText = "Audit chain not checked yet"; detail = "Recompute every entry's keyed hash and compare it with the stored chain."; }
  else if (result.intact) { ring = h("div", { class: "seal-ring" }, LOCK()); stateText = "Audit chain intact"; detail = `${result.checked} entries verified ${fmtTime(new Date().toISOString())}. Record the head hash somewhere outside TrustVault to detect truncation later.`; }
  else { ring = h("div", { class: "seal-ring broken" }, BROKEN()); stateText = `Chain broken at entry ${result.broken_at_id}`; detail = `${result.problem}. Entries after this point cannot be trusted as evidence.`; }
  const chain = result ? h("div", { class: "chain" + (result.intact ? "" : " bad") },
    [result.intact ? Math.max(1, result.head_id - 2) : Math.max(1, result.broken_at_id - 2)].flatMap((startId) => {
      const last = result.intact ? result.head_id : result.broken_at_id;
      const out = [];
      for (let i = startId; i <= last; i++) {
        if (out.length) out.push(h("span", { class: "join" }));
        out.push(h("div", { class: "link" }, h("div", { class: "n" }, `#${i}`),
          h("div", { class: "h" }, i === last && result.intact ? result.head_hash : i === last ? "mismatch" : "…linked")));
      }
      return out;
    })) : null;
  put(host, 
    h("div", { class: "seal" }, ring, h("div", null, h("div", { class: "state" }, stateText), h("div", { class: "detail" }, detail),
      h("div", { style: null }, verify))),
    chain,
    result && result.intact ? h("div", { class: "sheet-pad", style: null }, h("div", { class: "meta" }, "Head hash"), h("div", { class: "hash" }, result.head_hash)) : null);
}

// ------------------------------------------------------------------ admin: activity log
const auditState = { actor: "", action: "", outcome: "", document: "", from: "", to: "", page: 1 };

async function viewAudit(main) {
  const host = h("div");
  const deb = debounce(() => { auditState.page = 1; load(); }, 250);
  const inp = (k, a) => h("input", Object.assign({ value: auditState[k], oninput: (e) => { auditState[k] = e.target.value; deb(); } }, a));
  const action = h("select", { onchange: (e) => { auditState.action = e.target.value; auditState.page = 1; load(); } },
    [["", "All events"], ["document.", "Documents"], ["document.download", "Downloads"], ["permission.", "Permission changes"],
     ["auth.", "Sign-ins"], ["admin.", "Administration"], ["security.", "Forged requests"], ["suggestion.", "Suggestions"]]
      .map(([v, l]) => h("option", { value: v, selected: auditState.action === v }, l)));
  const outcome = h("select", { onchange: (e) => { auditState.outcome = e.target.value; auditState.page = 1; load(); } },
    [["", "Any outcome"], ["allowed", "Allowed"], ["denied", "Refused"], ["error", "Error"]]
      .map(([v, l]) => h("option", { value: v, selected: auditState.outcome === v }, l)));

  put(main, 
    pageHead("Activity log", "Every entry is chained to the one before it with a keyed hash. The database refuses edits and deletions."),
    h("div", { class: "sheet" },
      h("div", { class: "filters audit-filters" },
        h("label", null, "Document", inp("document", { type: "search", placeholder: "Title or id" })),
        h("label", null, "Person", inp("actor", { type: "search", placeholder: "Username" })),
        h("label", null, "Event", action), h("label", null, "Outcome", outcome),
        h("label", null, "From", inp("from", { type: "date" })), h("label", null, "To", inp("to", { type: "date" }))),
      host));

  async function load() {
    const p = new URLSearchParams({ page: auditState.page, page_size: 50 });
    for (const k of ["actor", "action", "outcome", "document", "from", "to"]) if (auditState[k]) p.set(k, auditState[k]);
    let data;
    try { data = await api("GET", "/api/admin/audit?" + p); } catch (e) { return fail(e); }
    if (!data.items.length) { put(host, h("div", { class: "empty" }, h("strong", null, "No events match"), h("span", null, "Widen the filters."))); return; }
    const tbody = h("tbody");
    for (const r of data.items) {
      const detail = h("tr", { class: "audit-detail", hidden: true },
        h("td", { colspan: 6 }, h("pre", null,
          `entry #${r.id}   ${r.ts}\nip ${r.ip || "-"}   ${r.user_agent || ""}\ndocument ${r.document_id || "-"}\ndetails ${JSON.stringify(JSON.parse(r.details || "{}"), null, 2)}\nprev  ${r.prev_hash}\nhash  ${r.hash}`)));
      tbody.append(
        h("tr", { class: "link", tabindex: 0, onclick: () => { detail.hidden = !detail.hidden; },
          onkeydown: (e) => { if (e.key === "Enter") detail.hidden = !detail.hidden; } },
          h("td", { class: "num" }, fmtTime(r.ts)),
          h("td", null, r.actor_username || h("span", { class: "meta" }, "anonymous")),
          h("td", null, eventText(r), h("div", { class: "meta" }, r.action)),
          h("td", null, r.document_title || (r.target_username ? `@${r.target_username}` : "—"),
            r.document_title && r.target_username ? h("div", { class: "meta" }, `→ @${r.target_username}`) : null),
          h("td", null, h("span", { class: `badge badge-${r.outcome}` }, r.outcome === "denied" ? "refused" : r.outcome)),
          h("td", { class: "num hide-sm meta" }, `#${r.id}`)),
        detail);
    }
    const pages = Math.max(1, Math.ceil(data.total / data.page_size));
    put(host, 
      h("div", { class: "table-wrap" }, h("table", null,
        h("thead", null, h("tr", null, h("th", null, "When"), h("th", null, "Who"), h("th", null, "Event"), h("th", null, "Document / person"), h("th", null, "Outcome"), h("th", { class: "hide-sm" }, "Entry"))),
        tbody)),
      h("div", { class: "pager" }, h("span", null, `${data.total} entries · page ${data.page} of ${pages} · select a row for its hash and details`),
        h("span", null,
          h("button", { class: "btn-small", disabled: data.page <= 1, onclick: () => { auditState.page--; load(); } }, "Newer"), " ",
          h("button", { class: "btn-small", disabled: data.page >= pages, onclick: () => { auditState.page++; load(); } }, "Older"))));
  }
  load();
}

// ------------------------------------------------------------------ admin: people
async function viewPeople(main) {
  const data = await api("GET", "/api/admin/users");
  const reload = () => viewPeople(main);
  const rows = data.items.map((u) => {
    const self = u.id === state.user.id;
    const role = h("select", { disabled: self, "aria-label": `Role for ${u.display_name}`, onchange: async () => {
      try { await api("PATCH", `/api/admin/users/${u.id}`, { role: role.value }); toast(`${u.display_name} is now ${roleName(role.value).toLowerCase()}. Their sessions were ended.`); reload(); }
      catch (e) { fail(e); reload(); }
    } }, ["admin", "owner", "viewer"].map((r) => h("option", { value: r, selected: u.role === r }, roleName(r))));
    return h("tr", null,
      h("td", null, h("strong", null, u.display_name), h("div", { class: "meta" }, `@${u.username}`)),
      h("td", null, role),
      h("td", null, u.active ? (u.must_change_password ? h("span", { class: "badge badge-muted" }, "Awaiting first sign-in") : h("span", { class: "badge badge-allowed" }, "Active"))
        : h("span", { class: "badge badge-denied" }, "Disabled")),
      h("td", { class: "num hide-sm" }, u.documents),
      h("td", { class: "num hide-sm" }, u.sessions),
      h("td", null, self ? h("span", { class: "meta" }, "You") : [
        h("button", { class: "btn-small" + (u.active ? " btn-danger" : ""), onclick: async () => {
          if (u.active && !(await confirmDialog(`Disable ${u.display_name}?`, "They are signed out everywhere immediately and cannot sign in. Their documents stay, and access they were given stops working.", "Disable account", true))) return;
          try { await api("PATCH", `/api/admin/users/${u.id}`, { active: !u.active }); toast(u.active ? "Account disabled. Sessions ended." : "Account enabled."); reload(); } catch (e) { fail(e); }
        } }, u.active ? "Disable" : "Enable"), " ",
        u.sessions ? h("button", { class: "btn-small", onclick: async () => {
          try { const r = await api("POST", `/api/admin/users/${u.id}/revoke-sessions`); toast(`${r.sessions_ended} session(s) ended.`); reload(); } catch (e) { fail(e); }
        } }, "Sign out everywhere") : null]));
  });
  put(main, 
    pageHead("People", "Administrators manage accounts. They cannot open documents unless an owner shares them.",
      h("button", { class: "btn-primary", onclick: () => newUserDialog(reload) }, "Add person")),
    h("div", { class: "sheet" }, h("div", { class: "table-wrap" }, h("table", null,
      h("thead", null, h("tr", null, h("th", null, "Person"), h("th", null, "Role"), h("th", null, "Status"), h("th", { class: "hide-sm" }, "Documents"), h("th", { class: "hide-sm" }, "Sessions"), h("th", null, ""))),
      h("tbody", null, rows)))),
    h("p", { class: "meta", style: null }, "Owners upload documents and decide who can open each one. Viewers can only open what is shared with them."));
}

function newUserDialog(done) {
  const err = h("p", { class: "form-error", role: "alert" });
  const username = h("input", { required: true, maxlength: 32, placeholder: "e.g. jlee", autocomplete: "off" });
  const name = h("input", { required: true, maxlength: 80, placeholder: "e.g. Jordan Lee" });
  const role = h("select", null, h("option", { value: "viewer" }, "Viewer"), h("option", { value: "owner" }, "Document owner"), h("option", { value: "admin" }, "Administrator"));
  const body = h("div", { class: "form-grid" },
    h("label", { class: "field" }, "Username", username), h("label", { class: "field" }, "Full name", name),
    h("label", { class: "field" }, "Role", role), err);
  const create = h("button", { class: "btn-primary", onclick: async () => {
    create.disabled = true; err.textContent = "";
    try {
      const r = await api("POST", "/api/admin/users", { username: username.value, display_name: name.value, role: role.value });
      put(body, 
        h("p", null, `${r.user.display_name} can sign in with this temporary password. It is shown once; they must change it at first sign-in.`),
        h("div", { class: "secret-once" }, r.temporary_password),
        h("p", { class: "meta" }, "Give it to them in person or over a channel you trust."));
      create.remove(); cancel.textContent = "Done"; done();
    } catch (e) { err.textContent = e.message; create.disabled = false; }
  } }, "Create account");
  const cancel = h("button", { onclick: () => d.close() }, "Cancel");
  const d = dialog("Add person", body, [cancel, create]);
}

boot();
