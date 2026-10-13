(() => {
  "use strict";

  const TOKEN_KEY = "threatlens.session";
  const loginPanel = document.querySelector("#login-panel");
  const appPanel = document.querySelector("#app-panel");
  const loginForm = document.querySelector("#login-form");
  const loginError = document.querySelector("#login-error");
  const statusMessage = document.querySelector("#status-message");
  const userLabel = document.querySelector("#user-label");
  const refreshButton = document.querySelector("#refresh-button");
  const logoutButton = document.querySelector("#logout-button");

  function token() {
    return sessionStorage.getItem(TOKEN_KEY);
  }

  function setMessage(target, message, isError = false) {
    target.textContent = message || "";
    target.classList.toggle("error-text", isError);
    target.hidden = !message;
  }

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (options.body) headers.set("Content-Type", "application/json");
    if (token()) headers.set("Authorization", `Bearer ${token()}`);
    const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
    if (response.status === 401 && path !== "/api/v1/auth/login") {
      sessionStorage.removeItem(TOKEN_KEY);
      showLogin();
      throw new Error("Your session expired. Please sign in again.");
    }
    if (!response.ok) {
      let detail = `Request failed (${response.status})`;
      try {
        const body = await response.json();
        if (typeof body.detail === "string") detail = body.detail;
      } catch (_) {
        // Keep the bounded generic error when the server response is not JSON.
      }
      throw new Error(detail);
    }
    if (response.status === 204) return null;
    return response.json();
  }

  function showLogin() {
    loginPanel.hidden = false;
    appPanel.hidden = true;
    userLabel.textContent = "";
  }

  function showApp() {
    loginPanel.hidden = true;
    appPanel.hidden = false;
  }

  function setText(id, value) {
    document.getElementById(id).textContent = String(value ?? "—");
  }

  function clearChildren(element) {
    while (element.firstChild) element.removeChild(element.firstChild);
  }

  function renderTable(bodyId, rows, columns, emptyText) {
    const body = document.getElementById(bodyId);
    clearChildren(body);
    if (!rows.length) {
      const row = document.createElement("tr");
      const cell = document.createElement("td");
      cell.colSpan = columns.length;
      cell.className = "empty-cell";
      cell.textContent = emptyText;
      row.appendChild(cell);
      body.appendChild(row);
      return;
    }
    for (const item of rows) {
      const row = document.createElement("tr");
      for (const column of columns) {
        const cell = document.createElement("td");
        const value = column.value(item);
        cell.textContent = value === null || value === undefined || value === "" ? "—" : String(value);
        if (column.className) cell.className = column.className(item);
        row.appendChild(cell);
      }
      body.appendChild(row);
    }
  }

  function renderBreakdown(containerId, values, palette) {
    const container = document.getElementById(containerId);
    clearChildren(container);
    const entries = Object.entries(values || {}).sort((a, b) => a[0].localeCompare(b[0]));
    if (!entries.length) {
      const empty = document.createElement("p");
      empty.className = "muted empty-breakdown";
      empty.textContent = "No recorded activity";
      container.appendChild(empty);
      return;
    }
    const total = entries.reduce((sum, entry) => sum + Number(entry[1] || 0), 0);
    for (const [label, rawValue] of entries) {
      const value = Number(rawValue || 0);
      const item = document.createElement("div");
      item.className = "breakdown-item";
      const top = document.createElement("div");
      top.className = "breakdown-top";
      const name = document.createElement("span");
      name.textContent = label.replaceAll("_", " ");
      const count = document.createElement("strong");
      count.textContent = String(value);
      top.append(name, count);
      const track = document.createElement("div");
      track.className = "bar-track";
      const bar = document.createElement("div");
      const percentage = total ? Math.round(Math.max(0, Math.min(100, value / total * 100)) / 5) * 5 : 0;
      bar.className = `bar-fill width-${percentage} ${palette[label] || "bar-neutral"}`;
      track.appendChild(bar);
      item.append(top, track);
      container.appendChild(item);
    }
  }

  function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
  }

  async function loadDashboard() {
    setMessage(statusMessage, "Loading live data…");
    refreshButton.disabled = true;
    try {
      const [summary, assets, findings, scans, principal] = await Promise.all([
        request("/api/v1/dashboard/summary"),
        request("/api/v1/assets?limit=8&offset=0"),
        request("/api/v1/findings?limit=8&offset=0"),
        request("/api/v1/scans?limit=8&offset=0"),
        request("/api/v1/me")
      ]);
      setText("campaign-count", summary.campaigns);
      setText("asset-count", summary.assets);
      setText("service-count", summary.services);
      setText("finding-count", summary.findings);
      setText("asset-total", `${assets.total} total assets`);
      setText("finding-total", `${findings.total} total findings`);
      setText("scan-total", `${scans.total} recorded executions`);
      setText("user-label", `${principal.username} · ${principal.role}`);
      renderBreakdown("severity-breakdown", summary.findings_by_severity, {
        CRITICAL: "bar-critical", HIGH: "bar-high", MEDIUM: "bar-medium",
        LOW: "bar-low", INFO: "bar-info", INFORMATIONAL: "bar-info"
      });
      renderBreakdown("scan-breakdown", summary.scans_by_state, {
        COMPLETED: "bar-success", RUNNING: "bar-running", QUEUED: "bar-neutral",
        FAILED: "bar-critical", CANCELLED: "bar-medium", PARTIAL: "bar-high"
      });
      renderTable("assets-body", assets.items, [
        { value: item => item.value },
        { value: item => item.asset_type },
        { value: item => item.services.length },
        { value: item => formatDate(item.last_seen_at) }
      ], "No assets have been discovered yet.");
      renderTable("findings-body", findings.items, [
        { value: item => item.title },
        { value: item => item.severity, className: item => `severity-cell severity-${String(item.severity).toLowerCase()}` },
        { value: item => item.state },
        { value: item => item.asset_canonical_id }
      ], "No findings have been recorded yet.");
      renderTable("scans-body", scans.items, [
        { value: item => item.provider_name },
        { value: item => item.state, className: item => `state-cell state-${String(item.state).toLowerCase()}` },
        { value: item => item.campaign_name },
        { value: item => formatDate(item.queued_at) }
      ], "No scan executions have been queued yet.");
      setMessage(statusMessage, `Data refreshed at ${new Date().toLocaleTimeString()}.`);
    } catch (error) {
      setMessage(statusMessage, error.message || "Unable to load dashboard data.", true);
    } finally {
      refreshButton.disabled = false;
    }
  }

  loginForm.addEventListener("submit", async event => {
    event.preventDefault();
    const submit = loginForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    setMessage(loginError, "");
    try {
      const username = document.getElementById("username").value.trim();
      const password = document.getElementById("password").value;
      const result = await request("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password })
      });
      sessionStorage.setItem(TOKEN_KEY, result.access_token);
      document.getElementById("password").value = "";
      showApp();
      await loadDashboard();
    } catch (error) {
      setMessage(loginError, error.message || "Sign-in failed.", true);
    } finally {
      submit.disabled = false;
    }
  });

  refreshButton.addEventListener("click", loadDashboard);
  logoutButton.addEventListener("click", async () => {
    try {
      await request("/api/v1/auth/logout", { method: "POST" });
    } catch (_) {
      // Always clear the browser-held session token on logout.
    }
    sessionStorage.removeItem(TOKEN_KEY);
    showLogin();
  });

  for (const link of document.querySelectorAll("[data-section-link]")) {
    link.addEventListener("click", () => {
      document.querySelectorAll("[data-section-link]").forEach(item => item.classList.remove("active"));
      link.classList.add("active");
    });
  }

  if (token()) {
    showApp();
    loadDashboard();
  } else {
    showLogin();
  }
})();
