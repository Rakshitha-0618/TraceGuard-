/* ============================================================
   TraceGuard — single-page client
   Sections: config → state → helpers → views → actions → boot
   ============================================================ */

/* --------------------------- 1. Config --------------------------- */

const API_BASE =
  (typeof import.meta !== "undefined" && import.meta.env?.VITE_API_URL) ||
 "mongodb+srv://traceguard:traceguard@12@cluster0.vcdyoec.mongodb.net/traceguard";


const TOKEN_KEY = "token";
const DEMO_PASSWORD = "TraceGuard@123";
const ALLOW_SIGNUP = true; // set false if accounts are admin-created only

const CASE_STATUSES = ["open", "under_investigation", "closed", "archived"];
const CASE_CATEGORIES = ["Payment Fraud", "Phishing", "Identity Theft", "Account Hacking", "Cyber Harassment", "Other"];
const CASE_SEVERITIES = ["Low", "Medium", "High", "Critical"];

/* --------------------------- 2. State ---------------------------- */

const state = {
  token: localStorage.getItem(TOKEN_KEY) || "",
  me: null,
  cases: [],
  investigators: [],
  stats: { total: 0, pending: 0, active: 0, resolved: 0 },
};

/* -------------------------- 3. Helpers --------------------------- */

const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (ch) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
  ));

const options = (values, selected) =>
  values.map((v) => `<option ${v === selected ? "selected" : ""}>${esc(v)}</option>`).join("");

const toArray = (value, key) =>
  Array.isArray(value) ? value : Array.isArray(value?.[key]) ? value[key] : [];

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function api(path, { method = "GET", body, ...rest } = {}) {
  const isForm = body instanceof FormData;
  const headers = {
    ...(isForm || body === undefined ? {} : { "Content-Type": "application/json" }),
    ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
  };
  const payload =
    body === undefined || isForm || typeof body === "string" ? body : JSON.stringify(body);

  let res;
  try {
    res = await fetch(API_BASE + path, { method, headers, body: payload, ...rest });
  } catch {
    // Network-level failure: server down, wrong port, CORS, DNS…
    throw new ApiError("Cannot reach the server. Is the backend running?", 0);
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(data.message || data.error || `Request failed (${res.status})`, res.status);
  }
  return data;
}

function setSession(token, user) {
  state.token = token;
  state.me = user;
  localStorage.setItem(TOKEN_KEY, token);
}

function clearSession() {
  state.token = "";
  state.me = null;
  localStorage.removeItem(TOKEN_KEY);
}

function mount(html) {
  $("#app").innerHTML = html;
}

function showError(message) {
  const box = $("#err");
  if (box) box.textContent = message;
}

function deriveStats(cases) {
  const count = (status) => cases.filter((c) => c.status === status).length;
  return {
    total: cases.length,
    pending: count("Pending"),
    active: count("Under Investigation"),
    resolved: count("Resolved") + count("Closed"),
  };
}

/* --------------------------- 4. Views ---------------------------- */

function renderLogin(message = "") {
  mount(`
    <main class="login panel">
      <div class="brand">TRACEGUARD</div>
      <p class="muted">Cyber Incident &amp; Digital Evidence Management</p>
      <h2>Secure sign in</h2>
      <form id="login" data-form="login">
        <label>Email<input name="email" type="email" required autocomplete="username"
          value="admin@traceguard.local"></label>
        <label>Password<input name="password" type="password" required
          autocomplete="current-password" value="${DEMO_PASSWORD}"></label>
        <p id="err" class="error">${esc(message)}</p>
        <button type="submit">Sign in</button>
      </form>
      <small>
        Demo password for all roles: ${DEMO_PASSWORD}
        ${ALLOW_SIGNUP ? ' · <a href="#" data-action="go-signup">Create an account</a>' : ""}
      </small>
    </main>
  `);
}

function renderSignup() {
  mount(`
    <main class="login panel">
      <div class="brand">TRACEGUARD</div>
      <p class="muted">Cyber Incident &amp; Digital Evidence Management</p>
      <h2>Create your account</h2>
      <form id="signup" data-form="signup">
        <label>Full name<input name="name" required autocomplete="name"></label>
        <label>Email<input name="email" type="email" required autocomplete="username"></label>
        <label>Password<input name="password" type="password" minlength="8" required
          autocomplete="new-password"></label>
        <label>Confirm password<input name="confirm" type="password" minlength="8" required
          autocomplete="new-password"></label>
        <p id="err" class="error"></p>
        <button type="submit">Create account</button>
      </form>
      <small>Already registered? <a href="#" data-action="go-login">Sign in</a></small>
    </main>
  `);
}

function renderFatal(message) {
  mount(`
    <main class="login panel">
      <div class="brand">TRACEGUARD</div>
      <h2>Something went wrong</h2>
      <p class="error">${esc(message)}</p>
      <p class="muted">API: <code>${esc(API_BASE)}</code></p>
      <button data-action="retry">Try again</button>
      <button class="secondary" data-action="logout">Sign out</button>
    </main>
  `);
}

function renderDashboard() {
  const { me, cases, stats, investigators } = state;
  const isAdmin        = me.role === "admin";
  const isInvestigator = me.role === "investigator";
  const isReporter     = me.role === "reporter";

  const heading = isAdmin ? "Administration Console"
    : isInvestigator ? "Investigation Workspace"
    : "Reporter Portal";

  const blurb = isAdmin ? "Review all complaints and assign investigators."
    : isInvestigator ? "Only cases assigned to your account are shown."
    : "Submit complaints and track your own reports.";

  const statCards = [
    ["Total", stats.total ?? 0],
    ["Pending", stats.pending ?? 0],
    ["Under investigation", stats.active ?? 0],
    ["Resolved", stats.resolved ?? 0],
  ].map(([label, value]) => `
    <article class="panel"><small>${esc(label)}</small><strong>${esc(value)}</strong></article>
  `).join("");

  mount(`
    <main class="wrap">
      <header>
        <div>
          <div class="brand">TRACEGUARD</div>
          <small>CYBER INCIDENT &amp; DIGITAL EVIDENCE PORTAL</small>
        </div>
        <div class="user">
          <span class="pill">${esc(me.role.toUpperCase())}</span>
          ${esc(me.name)}
          <button class="secondary" data-action="logout">Logout</button>
        </div>
      </header>

      <h1>${heading}</h1>
      <p class="muted">${blurb}</p>

      <section class="stats">${statCards}</section>

      ${isReporter ? newCaseForm() : ""}

      <section class="panel">
        <div class="sectionhead">
          <h2>${isAdmin ? "All complaints" : isInvestigator ? "Cases assigned to me" : "My complaints"}</h2>
          <span class="pill">${cases.length} cases</span>
        </div>
        <div>${cases.map((c) => caseCard(c, { isAdmin, isInvestigator })).join("") || '<p class="muted">No cases found.</p>'}</div>
      </section>
    </main>
  `);
}

function newCaseForm() {
  return `
    <section class="panel">
      <h2>Submit cyber incident</h2>
      <form data-form="newcase" class="formgrid">
        <label>Title<input name="title" required></label>
        <label>Category<select name="category">${options(CASE_CATEGORIES, "Payment Fraud")}</select></label>
        <label>Severity<select name="severity">${options(CASE_SEVERITIES, "Medium")}</select></label>
        <label class="wide">Description<textarea name="description" required></textarea></label>
        <button type="submit">Submit complaint</button>
      </form>
    </section>`;
}

function caseCard(c, { isAdmin, isInvestigator }) {
  const id = c._id;
  const canTriage = isAdmin || isInvestigator;
  const notes = c.notes || [];
  const evidence = c.evidence || [];

  const assignControls = isAdmin ? `
    <div class="actions">
      <select data-role="assign-select" data-id="${id}">
        <option value="">Select investigator</option>
        ${state.investigators.map((u) => `
          <option value="${esc(u.id)}" ${c.assignedTo?._id === u.id ? "selected" : ""}>
            ${esc(u.name)} — ${esc(u.email)}
          </option>`).join("")}
      </select>
      <button data-action="assign" data-id="${id}">Assign / reassign</button>
    </div>` : "";

  const triageControls = canTriage ? `
    <div class="actions">
      <select data-role="status-select" data-id="${id}">
        ${CASE_STATUSES.map((s) => `<option ${s === c.status ? "selected" : ""}>${esc(s)}</option>`).join("")}
      </select>
      <button data-action="status" data-id="${id}">Update status</button>
    </div>
    <label>Internal investigation note
      <textarea data-role="note-text" data-id="${id}" placeholder="Add an internal note"></textarea>
    </label>
    <button class="secondary" data-action="note" data-id="${id}">Add note</button>
    ${notes.map((n) => `<p class="note">${esc(n.text)}</p>`).join("")}` : "";

  return `
    <article class="case">
      <div class="sectionhead">
        <h3>${esc(c.title)}</h3>
        <span class="pill">${esc(c.status)}</span>
      </div>
      <p>${esc(c.description)}</p>
      <small>
        ${esc(c.category)} · ${esc(c.severity)} ·
        Reporter: ${esc(c.reporter?.name)} ·
        Investigator: ${esc(c.assignedTo?.name || "Not assigned")}
      </small>
      ${assignControls}
      ${triageControls}
      <form class="actions" data-form="evidence" data-id="${id}">
        <input type="file" name="file" required>
        <button class="secondary" type="submit">Upload evidence</button>
      </form>
      ${evidence.map((e) => `<small class="hash">${esc(e.originalName)} · SHA-256 ${esc(e.sha256)}</small>`).join("<br>")}
    </article>`;
}

/* -------------------------- 5. Actions --------------------------- */

async function submitLogin(form) {
  const { email, password } = Object.fromEntries(new FormData(form));
  const data = await api("/auth/login", { method: "POST", body: { email, password } });
  setSession(data.token, data.user);
  await loadDashboard();
}

async function submitSignup(form) {
  const { name, email, password, confirm } = Object.fromEntries(new FormData(form));
  if (password !== confirm) throw new Error("Passwords do not match");

  const data = await api("/auth/register", { method: "POST", body: { name, email, password } });
  if (data.token) {
    setSession(data.token, data.user);
    return loadDashboard();
  }
  renderLogin("Account created — please sign in.");
}

async function submitNewCase(form) {
  await api("/cases", { method: "POST", body: Object.fromEntries(new FormData(form)) });
  await loadDashboard();
}

async function assignCase(caseId) {
  const select = $(`[data-role="assign-select"][data-id="${caseId}"]`);
  if (!select?.value) return alert("Select an investigator first.");
  await api(`/cases/${caseId}/assign`, { method: "PATCH", body: { investigatorId: select.value } });
  await loadDashboard();
}

async function updateStatus(caseId) {
  const select = $(`[data-role="status-select"][data-id="${caseId}"]`);
  if (!select?.value) return;
  await api(`/cases/${caseId}/status`, { method: "PATCH", body: { status: select.value } });
  await loadDashboard();
}

async function addNote(caseId) {
  const field = $(`[data-role="note-text"][data-id="${caseId}"]`);
  const text = field?.value.trim();
  if (!text) return alert("Write a note first.");
  await api(`/cases/${caseId}/notes`, { method: "POST", body: { text } });
  await loadDashboard();
}

async function submitEvidence(caseId, form) {
  const data = await api(`/cases/${caseId}/evidence`, { method: "POST", body: new FormData(form) });
  const hash = data?.sha256 || data?.evidence?.sha256;
  alert(hash ? `Evidence uploaded.\nSHA-256: ${hash}` : "Evidence uploaded.");
  await loadDashboard();
}

function logout() {
  clearSession();
  renderLogin();
}

async function loadDashboard() {
  try {
    if (!state.me) state.me = (await api("/auth/me")).user;

    const [casesRes, statsRes, invRes] = await Promise.allSettled([
      api("/cases"),
      api("/dashboard/stats"),
      state.me.role === "admin" ? api("/users/investigators") : Promise.resolve([]),
    ]);

    if (casesRes.status === "rejected") throw casesRes.reason;

    state.cases = toArray(casesRes.value, "cases");
    state.stats = statsRes.status === "fulfilled" ? statsRes.value : deriveStats(state.cases);
    state.investigators = invRes.status === "fulfilled" ? toArray(invRes.value, "users") : [];

    renderDashboard();
  } catch (err) {
    if (err.status === 401) {
      clearSession();
      return renderLogin("Session expired — please sign in.");
    }
    console.error("Dashboard load failed:", err);
    renderFatal(err.message);
  }
}

/* ------------------------ 6. Event wiring ------------------------ */

async function onAppClick(event) {
  const trigger = event.target instanceof Element ? event.target.closest("[data-action]") : null;
  if (!trigger) return;

  const { action, id } = trigger.dataset;
  const handlers = {
    logout,
    retry: () => loadDashboard(),
    "go-signup": () => renderSignup(),
    "go-login": () => renderLogin(),
    assign: () => assignCase(id),
    status: () => updateStatus(id),
    note: () => addNote(id),
  };

  const handler = handlers[action];
  if (!handler) return;

  event.preventDefault();
  try {
    await handler();
  } catch (err) {
    alert(err.message);
  }
}

async function onAppSubmit(event) {
  const form = event.target instanceof Element ? event.target.closest("[data-form]") : null;
  if (!form) return;

  event.preventDefault();
  const { form: kind, id } = form.dataset;

  try {
    if (kind === "login") await submitLogin(form);
    else if (kind === "signup") await submitSignup(form);
    else if (kind === "newcase") await submitNewCase(form);
    else if (kind === "evidence") await submitEvidence(id, form);
  } catch (err) {
    if (kind === "login" || kind === "signup") showError(err.message);
    else alert(err.message);
  }
}

/* ---------------------------- 7. Boot ---------------------------- */

function boot() {
  const root = $("#app");
  root.addEventListener("click", onAppClick);
  root.addEventListener("submit", onAppSubmit);

  if (state.token) loadDashboard();
  else renderLogin();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
