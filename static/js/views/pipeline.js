export const meta = { id: "pipeline", label: "Pipeline" };

export async function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <h1>Pipeline</h1>
      <div class="sub">continuous discovery → PHP fingerprint → vulnerability scan</div>
    </div>

    <div class="panel" id="pipeConfig">
      <h2>Configuration</h2>
      <div class="field-row">
        <dt-input id="pipeKw" label="Keywords (space-separated)" placeholder="shop store ecommerce wordpress"></dt-input>
      </div>
      <div style="margin-top:18px;">
        <dt-chip-group id="pipeTlds" label="TLDs"
          options="com,net,org,io,co,dev,app,ai,xyz,biz,info"
          selected="com,net,org,io,co"></dt-chip-group>
      </div>
      <div class="opts-row">
        <dt-toggle id="pipeSmart" label="⚡ smart mode" checked></dt-toggle>
        <dt-toggle id="pipeContinuous" label="continuous mode" checked></dt-toggle>
        <dt-toggle id="pipeHyphens" label="hyphens"></dt-toggle>
        <dt-toggle id="pipeInsecure" label="skip TLS" checked></dt-toggle>
        <dt-toggle id="pipeRedirects" label="follow redirects" checked></dt-toggle>
        <label class="numfield">SAPI
          <select class="dt-select" id="pipeSapi">
            <option value="auto" selected>auto</option>
            <option value="mod_php">mod_php</option>
            <option value="fpm">fpm</option>
          </select>
        </label>
        <label class="numfield">batch <input type="text" id="pipeBatch" value="50"></label>
        <label class="numfield">concurrency <input type="text" id="pipeConcurrency" value="50"></label>
        <label class="numfield">scan timeout <input type="text" id="pipeTimeout" value="60"></label>
        <label class="numfield">max len <input type="text" id="pipeMaxLen" value="15"></label>
      </div>
      <div class="smart-hint" id="smartHint">
        <span class="smart-icon">⚡</span>
        <span>Smart mode searches <strong>Certificate Transparency logs</strong> for real domains first, then expands keywords with PHP/CMS terms. 10–50× higher PHP hit rate.</span>
      </div>
      <div class="actions">
        <button class="primary" id="pipeStart">▶ Start Pipeline</button>
        <button class="primary pipe-stop-btn" id="pipeStop" style="display:none;">■ Stop Pipeline</button>
        <span class="pipeline-phase" id="pipePhase" style="display:none;">
          <span class="dot-pulse"></span>
          <span id="pipePhaseText">starting</span>
        </span>
        <span class="pipeline-source-tag" id="sourceTag" style="display:none;"></span>
        <span class="hint" id="pipeStatus"></span>
      </div>
    </div>

    <div class="pipeline-stats-bar" id="statsBar" style="display:none;">
      <div class="pipeline-stat">
        <span class="pipeline-stat-value" id="statChecked">0</span>
        <span class="pipeline-stat-label">checked</span>
      </div>
      <div class="pipeline-stat">
        <span class="pipeline-stat-value php" id="statPhp">0</span>
        <span class="pipeline-stat-label">PHP found</span>
      </div>
      <div class="pipeline-stat">
        <span class="pipeline-stat-value" id="statScanned">0</span>
        <span class="pipeline-stat-label">scanned</span>
      </div>
      <div class="pipeline-stat">
        <span class="pipeline-stat-value vuln" id="statVuln">0</span>
        <span class="pipeline-stat-label">vulnerable</span>
      </div>
      <div class="pipeline-stat">
        <span class="pipeline-stat-value clean" id="statClean">0</span>
        <span class="pipeline-stat-label">clean</span>
      </div>
      <div class="pipeline-stat">
        <span class="pipeline-stat-value" id="statHitRate">—</span>
        <span class="pipeline-stat-label">hit rate</span>
      </div>
      <div class="pipeline-stat">
        <span class="pipeline-stat-value" id="statElapsed">0:00</span>
        <span class="pipeline-stat-label">elapsed</span>
      </div>
    </div>

    <div class="pipeline-split" id="splitView" style="display:none;">
      <div class="pipeline-pane">
        <div class="pipeline-pane-head">
          <div class="pipeline-pane-title"><span class="pipeline-pane-icon">🔍</span> Discovery</div>
          <span class="pipeline-pane-count" id="discoveryCount">0</span>
        </div>
        <div class="pipeline-feed" id="discoveryFeed">
          <div class="pipeline-empty"><div class="modal-spinner"></div>Waiting for domains…</div>
        </div>
      </div>
      <div class="pipeline-pane">
        <div class="pipeline-pane-head">
          <div class="pipeline-pane-title"><span class="pipeline-pane-icon">🎯</span> Vulnerability Scanner</div>
          <span class="pipeline-pane-count" id="scannerCount">0</span>
        </div>
        <div class="pipeline-feed" id="scannerFeed">
          <div class="pipeline-empty">PHP sites will be scanned automatically</div>
        </div>
      </div>
    </div>

    <div class="panel vuln-saved-panel" id="vulnSavedPanel">
      <div class="vuln-saved-head">
        <div class="vuln-saved-title">
          <span>🚨</span>
          <span>Saved Vulnerable Sites</span>
          <span class="pipeline-pane-count vuln-count-badge" id="vulnSavedCount">0</span>
        </div>
        <div class="vuln-saved-actions">
          <button class="evidence-btn" id="vulnCopyBtn" title="Copy all vulnerable targets">Copy All</button>
          <button class="evidence-btn vuln-clear-btn" id="vulnClearBtn" title="Clear saved vulnerable sites">Clear</button>
        </div>
      </div>
      <div class="vuln-saved-list" id="vulnSavedList">
        <div class="pipeline-empty" style="padding:24px;">No vulnerable sites saved yet.</div>
      </div>
    </div>
  `;

  /* ---- DOM refs ---- */
  const $ = (id) => container.querySelector(`#${id}`);
  const el = {
    config: $("pipeConfig"), kw: $("pipeKw"), tlds: $("pipeTlds"),
    startBtn: $("pipeStart"), stopBtn: $("pipeStop"),
    phase: $("pipePhase"), phaseText: $("pipePhaseText"),
    status: $("pipeStatus"), sourceTag: $("sourceTag"),
    smartToggle: $("pipeSmart"), smartHint: $("smartHint"),
    statsBar: $("statsBar"), splitView: $("splitView"),
    statChecked: $("statChecked"), statPhp: $("statPhp"),
    statScanned: $("statScanned"), statVuln: $("statVuln"),
    statClean: $("statClean"), statElapsed: $("statElapsed"),
    statHitRate: $("statHitRate"),
    discoveryFeed: $("discoveryFeed"), scannerFeed: $("scannerFeed"),
    discoveryCount: $("discoveryCount"), scannerCount: $("scannerCount"),
    vulnSavedList: $("vulnSavedList"), vulnSavedCount: $("vulnSavedCount"),
    vulnCopyBtn: $("vulnCopyBtn"), vulnClearBtn: $("vulnClearBtn"),
  };

  let controller = null;
  let elapsedTimer = null;
  let startTime = 0;
  let discRowCount = 0;
  const scanRows = new Map();
  const MAX_DISC_ROWS = 150;

  /* ---- smart mode hint toggle ---- */
  function updateSmartHint() {
    el.smartHint.style.display = el.smartToggle?.checked ? "flex" : "none";
  }
  if (el.smartToggle) el.smartToggle.addEventListener("change", updateSmartHint);
  updateSmartHint();

  /* ---- helpers ---- */
  const fmtElapsed = (s) => {
    const sec = Math.floor(s), m = Math.floor(sec / 60);
    if (m >= 60) { const h = Math.floor(m / 60); return `${h}:${String(m % 60).padStart(2, "0")}:${String(sec % 60).padStart(2, "0")}`; }
    return `${m}:${String(sec % 60).padStart(2, "0")}`;
  };
  const domainOf = (url) => { try { return new URL(url).hostname; } catch { return url.replace(/^https?:\/\//, "").split("/")[0]; } };
  const clamp = (v, lo, hi, fb) => { const n = parseInt(v, 10); return Number.isNaN(n) ? fb : Math.max(lo, Math.min(hi, n)); };

  /* ---- source tag ---- */
  const SOURCE_LABELS = {
    ct: "🔗 CT Logs",
    generate: "🔄 Generated",
    wordlist: "📋 Wordlist",
  };
  function showSource(src) {
    if (!src) { el.sourceTag.style.display = "none"; return; }
    el.sourceTag.textContent = SOURCE_LABELS[src] || src;
    el.sourceTag.className = `pipeline-source-tag source-${src}`;
    el.sourceTag.style.display = "inline-flex";
  }

  /* ---- stats ---- */
  function updateStats(s) {
    el.statChecked.textContent = (s.domains_checked || 0).toLocaleString();
    el.statPhp.textContent = (s.php_found || 0).toLocaleString();
    el.statScanned.textContent = (s.scanned || 0).toLocaleString();
    el.statVuln.textContent = (s.vulnerable || 0).toLocaleString();
    el.statClean.textContent = (s.scan_clean || 0).toLocaleString();
    el.discoveryCount.textContent = (s.domains_checked || 0).toLocaleString();
    el.scannerCount.textContent = (s.scanned || 0).toLocaleString();
    // Hit rate
    const checked = s.domains_checked || 0;
    const phpFound = s.php_found || 0;
    if (checked > 0) {
      const pct = ((phpFound / checked) * 100).toFixed(1);
      el.statHitRate.textContent = `${pct}%`;
    } else {
      el.statHitRate.textContent = "—";
    }
    if (s.phase && s.running) {
      el.phaseText.textContent = s.source ? `${s.phase} (${s.source})` : s.phase;
      el.phase.style.display = "inline-flex";
    }
    if (s.source) showSource(s.source);
  }

  function showRunning(stats) {
    el.statsBar.style.display = "flex";
    el.splitView.style.display = "flex";
    el.startBtn.style.display = "none";
    el.stopBtn.style.display = "inline-flex";
    el.status.textContent = "";
    container.querySelectorAll("#pipeConfig input, #pipeConfig select, #pipeConfig dt-toggle, #pipeConfig dt-chip-group, #pipeConfig dt-input")
      .forEach((x) => { x.style.pointerEvents = "none"; x.style.opacity = "0.5"; });
    updateStats(stats);
    startTimer(stats.elapsed || 0);
  }

  function showStopped() {
    el.startBtn.style.display = "inline-flex";
    el.startBtn.disabled = false;
    el.stopBtn.style.display = "none";
    el.phase.style.display = "none";
    el.sourceTag.style.display = "none";
    if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; }
    container.querySelectorAll("#pipeConfig input, #pipeConfig select, #pipeConfig dt-toggle, #pipeConfig dt-chip-group, #pipeConfig dt-input")
      .forEach((x) => { x.style.pointerEvents = ""; x.style.opacity = ""; });
  }

  function startTimer(initialSecs) {
    startTime = Date.now() - initialSecs * 1000;
    if (elapsedTimer) clearInterval(elapsedTimer);
    elapsedTimer = setInterval(() => {
      el.statElapsed.textContent = fmtElapsed((Date.now() - startTime) / 1000);
    }, 1000);
  }

  /* ---- discovery feed (left pane) ---- */
  function addDiscRow(ev) {
    const isPhp = ev.type === "php_found";
    const isCt = ev.source === "ct";
    const row = document.createElement("div");
    row.className = `pipeline-row${isPhp ? " php-found" : ""}${isCt ? " ct-source" : ""}`;

    const dom = document.createElement("span");
    dom.className = "domain";
    dom.textContent = ev.domain;

    const sig = document.createElement("span");
    sig.className = "signal";
    if (isPhp) sig.textContent = "🐘 " + (ev.php_signals || []).join(", ");
    else if (ev.available === true) sig.textContent = "available (no DNS)";
    else if (ev.error) sig.textContent = ev.error;
    else sig.textContent = "registered · no PHP";

    row.append(dom, sig);
    if (isPhp) {
      const b = document.createElement("span");
      b.className = "pipe-badge php";
      b.textContent = "PHP";
      row.appendChild(b);
    }
    if (isCt) {
      const c = document.createElement("span");
      c.className = "pipe-badge ct";
      c.textContent = "CT";
      row.appendChild(c);
    }

    el.discoveryFeed.appendChild(row);
    discRowCount++;

    // Trim non-PHP rows
    while (discRowCount > MAX_DISC_ROWS) {
      const first = el.discoveryFeed.querySelector(".pipeline-row:not(.php-found)");
      if (first) { first.remove(); discRowCount--; } else break;
    }
    el.discoveryFeed.scrollTop = el.discoveryFeed.scrollHeight;

    // Remove empty placeholder
    const empty = el.discoveryFeed.querySelector(".pipeline-empty");
    if (empty) empty.remove();
  }

  /* ---- scanner feed (right pane) ---- */
  function upsertScanRow(domain, status, detail) {
    let row = scanRows.get(domain);
    if (!row) {
      row = document.createElement("div");
      row.className = "pipeline-row queued";

      const dom = document.createElement("span");
      dom.className = "domain";
      dom.textContent = domain;

      const sig = document.createElement("span");
      sig.className = "signal";
      sig.textContent = "queued…";

      const b = document.createElement("span");
      b.className = "pipe-badge queued";
      b.textContent = "QUEUED";

      row.append(dom, sig, b);
      if (status === "vulnerable") el.scannerFeed.prepend(row);
      else el.scannerFeed.appendChild(row);
      scanRows.set(domain, row);

      const empty = el.scannerFeed.querySelector(".pipeline-empty");
      if (empty) empty.remove();
    }

    const signalEl = row.querySelector(".signal");
    const badge = row.querySelector(".pipe-badge");
    const cfg = {
      queued:     { cls: "queued",     sig: detail || "queued…",    badge: "QUEUED",   bcls: "queued" },
      scanning:   { cls: "scanning",   sig: "scanning…",           badge: "SCAN",     bcls: "scanning" },
      vulnerable: { cls: "vulnerable", sig: detail || "VULNERABLE", badge: "VULN",     bcls: "vuln" },
      clean:      { cls: "clean",      sig: detail || "clean",     badge: "CLEAN",    bcls: "clean" },
      error:      { cls: "error",      sig: detail || "error",     badge: "ERR",      bcls: "error" },
    }[status] || { cls: "error", sig: detail || "unknown", badge: "?", bcls: "error" };

    row.className = `pipeline-row ${cfg.cls}`;
    if (signalEl) signalEl.textContent = cfg.sig;
    if (badge) { badge.textContent = cfg.badge; badge.className = `pipe-badge ${cfg.bcls}`; }

    if (status === "vulnerable" && row.parentElement) row.parentElement.prepend(row);
  }

  /* ---- saved vulnerable sites panel ---- */
  const savedVulns = new Map();

  function fmtTime(iso) {
    if (!iso) return "";
    try { return new Date(iso).toLocaleString(); } catch { return iso; }
  }

  function renderSavedVulns() {
    el.vulnSavedCount.textContent = String(savedVulns.size);
    if (!savedVulns.size) {
      el.vulnSavedList.innerHTML = `<div class="pipeline-empty" style="padding:24px;">No vulnerable sites saved yet.</div>`;
      return;
    }
    el.vulnSavedList.innerHTML = "";
    for (const site of savedVulns.values()) {
      const row = document.createElement("div");
      row.className = "pipeline-row vulnerable vuln-saved-row";

      const dom = document.createElement("span");
      dom.className = "domain";
      dom.textContent = site.target || site.domain;
      dom.title = site.target || site.domain;

      const sig = document.createElement("span");
      sig.className = "signal";
      const parts = [site.vuln_type || "php2shell"];
      if (site.php_version) parts.push(site.php_version);
      if (site.reason) parts.push(site.reason);
      sig.textContent = parts.join(" · ");
      sig.title = sig.textContent;

      const ts = document.createElement("span");
      ts.className = "vuln-saved-time";
      ts.textContent = fmtTime(site.found_at);

      row.append(dom, sig, ts);

      if (site.source) {
        const src = document.createElement("span");
        src.className = `pipe-badge ${site.source === "ct" ? "ct" : "queued"}`;
        src.textContent = site.source.toUpperCase();
        row.appendChild(src);
      }

      const b = document.createElement("span");
      b.className = "pipe-badge vuln";
      b.textContent = "VULN";
      row.appendChild(b);

      el.vulnSavedList.appendChild(row);
    }
  }

  function upsertSavedVuln(site) {
    if (!site || !(site.domain || site.target)) return;
    const key = domainOf(site.domain || site.target);
    // Re-insert at front so newest appears first
    const ordered = new Map([[key, site]]);
    for (const [k, v] of savedVulns.entries()) {
      if (k !== key) ordered.set(k, v);
    }
    savedVulns.clear();
    for (const [k, v] of ordered.entries()) savedVulns.set(k, v);
    renderSavedVulns();
  }

  async function loadSavedVulns() {
    try {
      const res = await fetch("/api/pipeline/vulnerable");
      if (!res.ok) return;
      const data = await res.json();
      savedVulns.clear();
      for (const s of (data.sites || [])) {
        const key = domainOf(s.domain || s.target || "");
        if (key && !savedVulns.has(key)) savedVulns.set(key, s);
      }
      renderSavedVulns();
    } catch {}
  }

  el.vulnCopyBtn.onclick = async () => {
    const list = Array.from(savedVulns.values()).map((s) => s.target || s.domain).join("\n");
    if (!list) return;
    try {
      await navigator.clipboard.writeText(list);
      const orig = el.vulnCopyBtn.textContent;
      el.vulnCopyBtn.textContent = "Copied!";
      setTimeout(() => { el.vulnCopyBtn.textContent = orig; }, 1500);
    } catch {}
  };

  el.vulnClearBtn.onclick = async () => {
    try {
      await fetch("/api/pipeline/vulnerable", { method: "DELETE" });
      savedVulns.clear();
      renderSavedVulns();
    } catch {}
  };

  /* ---- stream handler ---- */
  function handleEv(ev) {
    if (ev.stats) updateStats(ev.stats);

    switch (ev.type) {
      case "snapshot":
        if (ev.running) showRunning(ev);
        (ev.php_targets || []).forEach((t) => addDiscRow({ type: "php_found", domain: t.domain, php_signals: t.signals, source: t.source }));
        (ev.scan_results || []).forEach((r) => {
          const d = domainOf(r.target || "");
          const st = r.vulnerable === true ? "vulnerable" : r.vulnerable === false ? "clean" : "error";
          upsertScanRow(d, st, r.vuln_type || r.reason || "");
        });
        break;
      case "started":    showRunning(ev.stats); break;
      case "checked":    addDiscRow(ev); break;
      case "php_found":
        addDiscRow(ev);
        upsertScanRow(ev.domain, "queued", (ev.php_signals || []).join(", "));
        break;
      case "source_change":
        showSource(ev.source);
        break;
      case "scan_start":
        (ev.targets || []).forEach((t) => upsertScanRow(domainOf(t), "scanning", ""));
        break;
      case "live_result":
      case "result":
        if (ev._src === "scanner" && ev.target) {
          const d = domainOf(ev.target);
          const st = ev.vulnerable === true ? "vulnerable" : ev.vulnerable === false ? "clean" : "error";
          upsertScanRow(d, st, ev.vuln_type || ev.reason || ev.error || "");
          if (ev.vulnerable === true && ev.saved_vuln) {
            upsertSavedVuln(ev.saved_vuln);
          }
        }
        break;
      case "scan_error":
        (ev.targets || []).forEach((t) => upsertScanRow(domainOf(t), "error", ev.error || "scan error"));
        break;
      case "discovery_done":
        el.status.textContent = "Discovery complete — draining scanner queue…";
        break;
      case "complete":
        showStopped();
        el.status.textContent = "✓ Pipeline complete.";
        break;
      case "stopped":
        showStopped();
        el.status.textContent = "■ Pipeline stopped.";
        break;
      case "error":
        showStopped();
        el.status.textContent = "Error: " + (ev.error || "unknown");
        break;
    }
  }

  async function connectStream() {
    controller = new AbortController();
    try {
      const res = await fetch("/api/pipeline/stream", { signal: controller.signal });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop();
        for (const line of lines) {
          if (!line.trim()) continue;
          try { handleEv(JSON.parse(line)); } catch {}
        }
      }
      buf += decoder.decode();
      if (buf.trim()) try { handleEv(JSON.parse(buf)); } catch {}
    } catch (e) {
      if (e.name !== "AbortError") el.status.textContent = "Stream disconnected.";
    }
  }

  /* ---- buttons ---- */
  el.startBtn.onclick = async () => {
    const keywords = (el.kw.value || "").split(/\s+/).filter(Boolean);
    if (!keywords.length) { el.status.textContent = "Enter at least one keyword."; return; }
    const tlds = el.tlds.value;
    if (!tlds.length) { el.status.textContent = "Select at least one TLD."; return; }

    const body = {
      keywords, tlds,
      max_length: clamp($("pipeMaxLen")?.value, 3, 63, 15),
      hyphens: Boolean($("pipeHyphens")?.checked),
      continuous: Boolean($("pipeContinuous")?.checked),
      smart_mode: Boolean($("pipeSmart")?.checked),
      batch_size: clamp($("pipeBatch")?.value, 10, 500, 50),
      concurrency: clamp($("pipeConcurrency")?.value, 1, 200, 50),
      scanner_timeout: clamp($("pipeTimeout")?.value, 1, 300, 60),
      insecure: Boolean($("pipeInsecure")?.checked),
      follow_redirects: Boolean($("pipeRedirects")?.checked),
      sapi: $("pipeSapi")?.value || "auto",
    };

    el.status.textContent = "Starting…";
    el.startBtn.disabled = true;
    el.discoveryFeed.innerHTML = "";
    el.scannerFeed.innerHTML = "";
    discRowCount = 0;
    scanRows.clear();

    try {
      const res = await fetch("/api/pipeline/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.detail || `HTTP ${res.status}`);
      }
      connectStream();
    } catch (e) {
      el.status.textContent = "Failed: " + e.message;
      el.startBtn.disabled = false;
    }
  };

  el.stopBtn.onclick = async () => {
    el.stopBtn.disabled = true;
    el.status.textContent = "Stopping…";
    try { await fetch("/api/pipeline/stop", { method: "POST" }); } catch {}
    if (controller) controller.abort();
    el.stopBtn.disabled = false;
  };

  /* ---- init: load saved vulnerable sites & reconnect if running ---- */
  loadSavedVulns();
  try {
    const res = await fetch("/api/pipeline/status");
    if (res.ok) {
      const data = await res.json();
      if (data.running) {
        showRunning(data);
        (data.php_targets || []).forEach((t) => addDiscRow({ type: "php_found", domain: t.domain, php_signals: t.signals, source: t.source }));
        (data.scan_results || []).forEach((r) => {
          const d = domainOf(r.target || "");
          const st = r.vulnerable === true ? "vulnerable" : r.vulnerable === false ? "clean" : "error";
          upsertScanRow(d, st, r.vuln_type || r.reason || "");
        });
        connectStream();
      }
    }
  } catch {}
}
