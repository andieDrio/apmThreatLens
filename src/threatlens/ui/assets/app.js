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
  const reportCampaignSelect = document.querySelector("#report-campaign-select");
  const downloadReportButton = document.querySelector("#download-campaign-report");
  const reportStatus = document.querySelector("#report-status");
  const scopeCreateForm = document.querySelector("#scope-create-form");
  const scopeTargetInput = document.querySelector("#scope-targets");
  const scopeTargetLabel = document.querySelector("#scope-target-label");
  const scopeTargetHelp = document.querySelector("#scope-target-help");
  const startTargetScanButton = document.querySelector("#start-target-scan");
  const scanProfileType = document.querySelector("#scan-profile-type");
  const scanProfileSummary = document.querySelector("#scan-profile-summary");
  const scanProfileChecks = document.querySelector("#scan-profile-checks");
  const scanProfileSafety = document.querySelector("#scan-profile-safety");
  const scanRunForm = document.querySelector("#scan-run-form");
  const scanCampaignSelect = document.querySelector("#scan-campaign-select");
  const scanProviderSelect = document.querySelector("#scan-provider-select");
  const runScanButton = document.querySelector("#run-scan-button");
  const providerDescription = document.querySelector("#provider-description");
  const vaptNavGroup = document.querySelector("#vapt-nav-group");
  const vaptNavToggle = document.querySelector("#vapt-nav-toggle");
  let registeredProviders = [];
  let campaignTargets = new Map();
  let campaignItems = [];
  let activeScanCapability = "NETWORK";
  let canAssess = false;

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
    document.body.classList.remove("app-active");
    loginPanel.hidden = false;
    appPanel.hidden = true;
    userLabel.textContent = "";
  }

  function showApp() {
    document.body.classList.add("app-active");
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
      const [summary, assets, findings, scans, principal, campaigns, evidence, relations, providers] = await Promise.all([
        request("/api/v1/dashboard/summary"),
        request("/api/v1/assets?limit=8&offset=0"),
        request("/api/v1/findings?limit=8&offset=0"),
        request("/api/v1/scans?limit=8&offset=0"),
        request("/api/v1/me"),
        request("/api/v1/campaigns?limit=100&offset=0"),
        request("/api/v1/evidence?limit=8&offset=0"),
        request("/api/v1/attack-path/relations?limit=8&offset=0"),
        request("/api/v1/providers")
      ]);
      registeredProviders = providers;
      campaignItems = campaigns.items;
      campaignTargets = new Map(campaigns.items.map(item => [item.id, item.include]));
      canAssess = principal.role !== "VIEWER";
      setText("campaign-count", summary.campaigns);
      setText("asset-count", summary.assets);
      setText("service-count", summary.services);
      setText("finding-count", summary.findings);
      setText("asset-total", `${assets.total} total assets`);
      setText("finding-total", `${findings.total} total findings`);
      setText("scan-total", `${scans.total} recorded executions`);
      setText("user-label", `${principal.username} · ${principal.role}`);
      scopeCreateForm.hidden = principal.role !== "ADMIN";
      scanRunForm.hidden = principal.role === "ADMIN";
      startTargetScanButton.disabled = !canAssess;
      scanRunForm.querySelectorAll("select, button").forEach(control => {
        control.disabled = principal.role === "VIEWER";
      });
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
      setText("campaign-total", `${campaigns.total} persisted campaigns`);
      clearChildren(reportCampaignSelect);
      const placeholder = document.createElement("option");
      placeholder.value = "";
      placeholder.textContent = "Select a campaign";
      reportCampaignSelect.appendChild(placeholder);
      for (const campaign of campaigns.items) {
        const option = document.createElement("option");
        option.value = campaign.id;
        option.textContent = `${campaign.name} · ${campaign.include[0] || "no target"}`;
        reportCampaignSelect.appendChild(option);
      }
      updateScanCampaignOptions();
      updateRunButton();
      downloadReportButton.disabled = true;
      renderTable("campaigns-body", campaigns.items.slice(0, 8), [
        { value: item => item.name },
        { value: item => item.state, className: item => `state-cell state-${String(item.state).toLowerCase()}` },
        { value: item => item.authorized ? "Yes" : "No" },
        { value: item => formatDate(item.created_at) }
      ], "No campaigns have been recorded yet.");
      setText("evidence-total", `${evidence.total} persisted evidence records`);
      renderTable("evidence-body", evidence.items, [
        { value: item => item.kind },
        { value: item => item.source },
        { value: item => formatDate(item.captured_at) },
        { value: item => item.sha256 }
      ], "No evidence records have been captured yet.");
      setText("attack-path-total", `${relations.total} explicit relationships`);
      renderTable("attack-paths-body", relations.items, [
        { value: item => item.source_asset_id },
        { value: item => item.relationship_type },
        { value: item => item.target_asset_id },
        { value: item => item.evidence_ids.length },
        { value: item => item.validated ? "Validated" : "Unvalidated",
          className: item => `state-cell state-${item.validated ? "completed" : "queued"}` }
      ], "No attack-path relationships have been recorded.");
      try {
        const audit = await request("/api/v1/audit-events?limit=8&offset=0");
        setText("audit-total", `${audit.total} audit events · latest records`);
        renderTable("audit-body", audit.items, [
          { value: item => formatDate(item.created_at) },
          { value: item => item.action },
          { value: item => `${item.resource_type}${item.resource_id ? ` · ${item.resource_id}` : ""}` },
          { value: item => item.outcome, className: item => `state-cell state-${String(item.outcome).toLowerCase()}` }
        ], "No security audit events have been recorded.");
      } catch (auditError) {
        setText("audit-total", "Administrator access required");
        renderTable("audit-body", [], [
          { value: item => item.created_at },
          { value: item => item.action },
          { value: item => item.resource_type },
          { value: item => item.outcome }
        ], "Audit events are available to administrator accounts only.");
      }
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
  reportCampaignSelect.addEventListener("change", () => {
    downloadReportButton.disabled = !reportCampaignSelect.value;
  });
  downloadReportButton.addEventListener("click", async () => {
    const campaignId = reportCampaignSelect.value;
    if (!campaignId) return;
    downloadReportButton.disabled = true;
    setMessage(reportStatus, "Preparing campaign report…");
    try {
      const report = await request(`/api/v1/campaigns/${encodeURIComponent(campaignId)}/report`);
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      const slug = String(report.campaign.name).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 64);
      link.href = objectUrl;
      link.download = `threatlens-${slug || "campaign"}-report.json`;
      link.hidden = true;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
      setMessage(reportStatus, "Campaign report downloaded.");
    } catch (error) {
      setMessage(reportStatus, error.message || "Unable to download campaign report.", true);
    } finally {
      downloadReportButton.disabled = !reportCampaignSelect.value;
    }
  });
  function updateRunButton() {
    runScanButton.disabled = !canAssess || !scanCampaignSelect.value || !scanProviderSelect.value;
  }

  function updateProviderOptions() {
    const previousProvider = scanProviderSelect.value;
    const targets = campaignTargets.get(scanCampaignSelect.value) || [];
    const isWebScope = targets.length > 0 && targets.every(value => /^https?:\/\//i.test(value));
    const scopeMatchesPage = targets.length > 0 && (activeScanCapability === "WEB") === isWebScope;
    const eligible = scopeMatchesPage
      ? registeredProviders.filter(item => item.capabilities.includes(activeScanCapability))
      : [];
    clearChildren(scanProviderSelect);
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = !targets.length
      ? "Select a scope first"
      : !scopeMatchesPage
        ? `Select a scope for ${activeScanCapability === "WEB" ? "a website" : "a network host"}`
      : eligible.length
        ? "Select an assessment module"
        : "No compatible modules available";
    scanProviderSelect.appendChild(placeholder);
    for (const provider of eligible) {
      const option = document.createElement("option");
      option.value = provider.name;
      option.textContent = `${provider.name} · ${provider.capabilities.join(", ")}`;
      scanProviderSelect.appendChild(option);
    }
    scanProviderSelect.value = eligible.some(item => item.name === previousProvider)
      ? previousProvider
      : "";
    updateProviderDescription();
  }

  function updateScanCampaignOptions() {
    const previousCampaign = scanCampaignSelect.value;
    const eligibleCampaigns = campaignItems.filter(campaign => {
      if (!campaign.authorized) return false;
      const targets = campaignTargets.get(campaign.id) || [];
      const isWebScope = targets.length > 0 && targets.every(value => /^https?:\/\//i.test(value));
      return (activeScanCapability === "WEB") === isWebScope;
    });
    clearChildren(scanCampaignSelect);
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = eligibleCampaigns.length
      ? "Select an authorized scope"
      : `No authorized ${activeScanCapability === "WEB" ? "website" : "network"} scopes yet`;
    scanCampaignSelect.appendChild(placeholder);
    for (const campaign of eligibleCampaigns) {
      const option = document.createElement("option");
      option.value = campaign.id;
      option.textContent = `${campaign.name} · ${campaign.include[0] || "no target"}`;
      scanCampaignSelect.appendChild(option);
    }
    scanCampaignSelect.value = eligibleCampaigns.some(item => item.id === previousCampaign)
      ? previousCampaign
      : "";
    updateProviderOptions();
  }

  function ipv4Number(value) {
    const octets = value.split(".");
    if (octets.length !== 4 || octets.some(part => !/^\d{1,3}$/.test(part))) {
      throw new Error("Enter a valid IPv4 address or IPv4 range.");
    }
    const numbers = octets.map(Number);
    if (numbers.some(part => part > 255)) throw new Error("IPv4 octets must be 0–255.");
    return numbers.reduce((total, part) => total * 256 + part, 0);
  }

  function ipv4String(value) {
    return [
      Math.floor(value / 16777216) % 256,
      Math.floor(value / 65536) % 256,
      Math.floor(value / 256) % 256,
      value % 256
    ].join(".");
  }

  function expandNetworkHosts(value) {
    const target = value.trim();
    if (!target) throw new Error("Enter an IP address or IP range.");
    if (target.includes("/")) {
      const [address, prefixText, ...extra] = target.split("/");
      const addressNumber = ipv4Number(address);
      const prefix = Number(prefixText);
      if (extra.length || !/^\d{1,2}$/.test(prefixText) || prefix > 32) {
        throw new Error("IPv4 CIDR must use a prefix from /0 to /32.");
      }
      const size = 2 ** (32 - prefix);
      let first = Math.floor(addressNumber / size) * size;
      let last = first + size - 1;
      if (prefix <= 30) { first += 1; last -= 1; }
      if (last - first + 1 > 32) throw new Error("This scan is limited to 32 IP addresses.");
      return Array.from({ length: last - first + 1 }, (_, index) => ipv4String(first + index));
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}-/.test(target)) {
      const [firstText, lastText, ...extra] = target.split("-");
      if (!lastText || extra.length) throw new Error("Enter an IPv4 range as startIP-endIP.");
      const first = ipv4Number(firstText);
      const last = ipv4Number(lastText);
      if (last < first) throw new Error("IP range end must be at or after its start.");
      if (last - first + 1 > 32) throw new Error("This scan is limited to 32 IP addresses.");
      return Array.from({ length: last - first + 1 }, (_, index) => ipv4String(first + index));
    }
    return [target];
  }

  function buildScanTargets() {
    const target = scopeTargetInput.value.trim();
    if (activeScanCapability === "WEB") {
      let parsed;
      try {
        parsed = new URL(target);
      } catch (_) {
        throw new Error("Enter a complete website URL beginning with https:// or http://.");
      }
      if (!new Set(["http:", "https:"]).has(parsed.protocol) || !parsed.hostname) {
        throw new Error("Website scans accept HTTP or HTTPS URLs only.");
      }
      if (parsed.username || parsed.password || parsed.hash) {
        throw new Error("Remove URL credentials and fragments before scanning.");
      }
      return [target];
    }
    return expandNetworkHosts(target);
  }

  function updateScanFormMode() {
    const isWeb = activeScanCapability === "WEB";
    const scanName = isWeb ? "Web Scan" : "Network Scan";
    startTargetScanButton.textContent = `Start ${scanName}`;
    scopeTargetLabel.textContent = isWeb ? "Website URL" : "IP address or IP range";
    scopeTargetInput.placeholder = isWeb
      ? "https://your-site.example/"
      : "192.168.1.20 or 192.168.1.0/28";
    scopeTargetInput.type = isWeb ? "url" : "text";
    scopeTargetHelp.textContent = isWeb
      ? "Enter one absolute HTTP(S) URL that you own or are authorized to assess."
      : "Enter one IP address, hostname, or IPv4 range up to 32 hosts.";
    scanProfileType.textContent = isWeb ? "Web" : "Network";
    scanProfileSummary.textContent = isWeb
      ? "A bounded, read-only HTTP check for the approved website."
      : "A bounded TCP reachability check for the approved network target.";
    scanProfileChecks.replaceChildren(...(isWeb
      ? ["HTTP(S) HEAD request to the target URL", "Response status and security headers recorded as evidence"]
      : ["TCP connection checks on ports 80 and 443", "Open port observations saved as scan evidence"]
    ).map(text => {
      const item = document.createElement("li");
      item.textContent = text;
      return item;
    }));
    scanProfileSafety.textContent = isWeb
      ? "Requires explicit authorization. Redirects are not followed, and private or reserved destinations are blocked by default."
      : "Requires explicit authorization. Checks stay within the saved target scope and use a bounded port profile.";
  }

  function updateProviderDescription() {
    const provider = registeredProviders.find(item => item.name === scanProviderSelect.value);
    if (!provider) {
      providerDescription.textContent = "Only modules registered by the server can run.";
    } else if (provider.capabilities.includes("NETWORK")) {
      providerDescription.textContent = "Bounded TCP connection checks on the server's approved port profile. No exploit payloads or destructive checks.";
    } else if (provider.capabilities.includes("WEB")) {
      providerDescription.textContent = "Bounded HTTP(S) HEAD requests. Redirects are not followed; private and reserved destinations are blocked by default.";
    } else {
      providerDescription.textContent = `Capabilities: ${provider.capabilities.join(", ")}.`;
    }
    updateRunButton();
  }

  function providerForCurrentScan() {
    const capability = activeScanCapability;
    const preferredName = capability === "WEB"
      ? "builtin-web-assessment"
      : "builtin-network-discovery";
    return registeredProviders.find(item => item.name === preferredName && item.safe_by_default)
      || registeredProviders.find(item => item.safe_by_default && item.capabilities.includes(capability));
  }

  scopeCreateForm.addEventListener("submit", async event => {
    event.preventDefault();
    const submit = scopeCreateForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    const scopeStatus = document.querySelector("#scope-status");
    let savedCampaign = null;
    setMessage(scopeStatus, "Preparing your authorized scan…");
    try {
      const include = buildScanTargets();
      if (!include.length) throw new Error("Add at least one target.");
      const provider = providerForCurrentScan();
      if (!provider) throw new Error("No approved scan module is available for this scan type.");
      const targetLabel = scopeTargetInput.value.trim().slice(0, 96);
      const scanName = activeScanCapability === "WEB" ? "Web Scan" : "Network Scan";
      savedCampaign = await request("/api/v1/campaigns", {
        method: "POST",
        body: JSON.stringify({
          name: `${scanName} · ${targetLabel}`,
          include,
          exclude: [],
          authorized: true
        })
      });
      setMessage(scopeStatus, "Target saved. Running the approved checks…");
      const result = await request(
        `/api/v1/campaigns/${encodeURIComponent(savedCampaign.id)}/scans/run`,
        {
          method: "POST",
          headers: { "Idempotency-Key": `ui-run-${crypto.randomUUID().replaceAll("-", "")}` },
          body: JSON.stringify({ provider_name: provider.name })
        }
      );
      scopeCreateForm.reset();
      setMessage(scopeStatus, `${scanName} ${result.state.toLowerCase()}. Execution: ${result.execution_id}`);
      await loadDashboard();
    } catch (error) {
      const message = savedCampaign
        ? `Target saved, but the scan could not start: ${error.message || "unknown error"}`
        : error.message || "Unable to start the scan.";
      setMessage(scopeStatus, message, true);
    } finally {
      submit.disabled = !canAssess;
    }
  });

  scanCampaignSelect.addEventListener("change", updateProviderOptions);
  scanProviderSelect.addEventListener("change", updateProviderDescription);
  scanRunForm.addEventListener("submit", async event => {
    event.preventDefault();
    const campaignId = scanCampaignSelect.value;
    const providerName = scanProviderSelect.value;
    if (!campaignId || !providerName) return;
    runScanButton.disabled = true;
    setMessage(document.querySelector("#scan-status"), "Running bounded assessment…");
    try {
      const result = await request(
        `/api/v1/campaigns/${encodeURIComponent(campaignId)}/scans/run`,
        {
          method: "POST",
          headers: { "Idempotency-Key": `ui-run-${crypto.randomUUID().replaceAll("-", "")}` },
          body: JSON.stringify({ provider_name: providerName })
        }
      );
      setMessage(document.querySelector("#scan-status"), `Assessment ${result.state.toLowerCase()}. Execution: ${result.execution_id}`);
      await loadDashboard();
    } catch (error) {
      setMessage(document.querySelector("#scan-status"), error.message || "Assessment could not run.", true);
    } finally {
      updateRunButton();
    }
  });
  logoutButton.addEventListener("click", async () => {
    try {
      await request("/api/v1/auth/logout", { method: "POST" });
    } catch (_) {
      // Always clear the browser-held session token on logout.
    }
    sessionStorage.removeItem(TOKEN_KEY);
    showLogin();
  });

  const sectionLinks = [...document.querySelectorAll("[data-section-link]")];
  const viewLinks = [...document.querySelectorAll("[data-section-link], [data-view-link]")];
  const workspaceViews = [...document.querySelectorAll("[data-workspace-view]")];
  const pageDetails = {
    overview: ["Dashboard", "See scan activity and review security findings."],
    tools: ["VAPT tools", "Run a bounded check against a system you are authorized to test."],
    "network-scan": ["Network Scan", "Check selected network ports on an authorized host."],
    "web-scan": ["Web Scan", "Run bounded, read-only checks on an authorized website."],
    campaigns: ["Authorized scopes", "Campaigns define the targets and exclusions approved for assessment."],
    assets: ["Asset inventory", "Hosts, domains, and services observed within authorized scope."],
    findings: ["Findings", "Recorded security issues with severity and affected asset context."],
    cve: ["CVE", "CVE feed integration is planned; API keys will stay on the server."],
    ioc: ["IOC Collections", "Import and review your indicator collections."],
    scans: ["Scan runs", "Persisted assessment executions and their current lifecycle state."],
    evidence: ["Evidence", "Supporting observations and integrity hashes for recorded results."],
    "attack-paths": ["Attack paths", "Evidence-linked relationships between assets; review validation state."],
    "audit-log": ["Audit Logs", "Administrator-only record of security-sensitive actions in this workspace."]
  };

  function activateView(view) {
    const selected = Object.hasOwn(pageDetails, view) ? view : "overview";
    const renderedView = selected === "network-scan" || selected === "web-scan" ? "tools" : selected;
    for (const panel of workspaceViews) panel.hidden = panel.dataset.workspaceView !== renderedView;
    if (selected === "network-scan" || selected === "web-scan") {
      activeScanCapability = selected === "web-scan" ? "WEB" : "NETWORK";
      setVaptMenuOpen(true);
      updateScanFormMode();
      updateScanCampaignOptions();
    } else {
      setVaptMenuOpen(false);
    }
    for (const link of sectionLinks) {
      const active = link.getAttribute("href") === `#${selected}`;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    const [title, subtitle] = pageDetails[selected];
    document.getElementById("page-title").textContent = title;
    document.getElementById("page-subtitle").textContent = subtitle;
    document.getElementById("page-eyebrow").textContent = `ThreatLens · ${title}`;
    document.getElementById("workspace-content").scrollTop = 0;
  }

  for (const link of viewLinks) {
    link.addEventListener("click", event => {
      const view = link.getAttribute("href")?.slice(1);
      if (!Object.hasOwn(pageDetails, view)) return;
      event.preventDefault();
      if (window.location.hash !== `#${view}`) window.history.pushState(null, "", `#${view}`);
      activateView(view);
    });
  }
  window.addEventListener("hashchange", () => activateView(window.location.hash.slice(1)));
  window.addEventListener("popstate", () => activateView(window.location.hash.slice(1)));
  activateView(window.location.hash.slice(1));

  function setVaptMenuOpen(open) {
    vaptNavGroup.classList.toggle("is-open", open);
    vaptNavToggle.setAttribute("aria-expanded", String(open));
  }
  vaptNavToggle.addEventListener("click", () => {
    setVaptMenuOpen(vaptNavToggle.getAttribute("aria-expanded") !== "true");
  });
  vaptNavGroup.addEventListener("mouseenter", () => setVaptMenuOpen(true));
  vaptNavGroup.addEventListener("mouseleave", () => {
    const onScanPage = ["#network-scan", "#web-scan"].includes(window.location.hash);
    if (!onScanPage) setVaptMenuOpen(false);
  });
  vaptNavGroup.addEventListener("focusin", () => setVaptMenuOpen(true));
  vaptNavGroup.addEventListener("focusout", event => {
    if (!vaptNavGroup.contains(event.relatedTarget)) {
      const onScanPage = ["#network-scan", "#web-scan"].includes(window.location.hash);
      if (!onScanPage) setVaptMenuOpen(false);
    }
  });

  if (token()) {
    showApp();
    loadDashboard();
  } else {
    showLogin();
  }
})();
