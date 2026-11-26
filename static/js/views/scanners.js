export const meta = { id: "scanners", label: "Scanners" };

export async function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <h1>Scanners</h1>
      <div class="sub">auto-discovered modules under core/scanners/</div>
    </div>

    <div class="panel">
      <h2>Available Scanners</h2>
      <div class="tool-grid" id="toolGrid">
        <div class="hint">Loading scanners...</div>
      </div>
    </div>

    <div class="panel" id="runnerPanel" style="display:none; margin-top:16px;">
      <h2 id="selectedTitle">Run Scanner</h2>
      <div class="field-row" style="margin-top:8px;">
        <div>
          <label style="display:block; font-size:12px; color:var(--ink-dim); margin-bottom:6px;">
            Targets (one URL or host per line)
          </label>
          <textarea class="dt-textarea" id="targets" placeholder="https://example.com&#10;http://testphp.vulnweb.com"></textarea>
        </div>
      </div>

      <div class="field-row" id="pathRow" style="margin-top:14px; display:none;">
        <dt-input id="customPath" label="Custom path(s), space or comma separated (optional)" placeholder="/index.php /admin.php"></dt-input>
      </div>

      <div class="opts-row" id="optsRow"></div>

      <div class="actions">
        <button class="primary" id="runScanner">Run Scanner</button>
        <span class="hint" id="scanStatus"></span>
      </div>
    </div>
  `;

  const grid = container.querySelector("#toolGrid");
  const runnerPanel = container.querySelector("#runnerPanel");
  const selectedTitle = container.querySelector("#selectedTitle");
  const pathRow = container.querySelector("#pathRow");
  const optsRow = container.querySelector("#optsRow");
  const runBtn = container.querySelector("#runScanner");
  const scanStatus = container.querySelector("#scanStatus");
  const modal = document.getElementById("resultsModal");

  let scanners = [];
  let selected = null;

  function selectScanner(sc) {
    selected = sc;
    Array.from(grid.children).forEach((card) => {
      card.classList.toggle("selected", card.dataset.id === sc.id);
    });
    runnerPanel.style.display = "block";
    selectedTitle.textContent = `${sc.name} (${sc.category})`;
    scanStatus.textContent = "";

    const opts = sc.options || {};
    pathRow.style.display = opts.path ? "flex" : "none";

    const parts = [];
    if (opts.insecure) parts.push(`<dt-toggle id="optInsecure" label="ignore TLS errors (-k)"></dt-toggle>`);
    if (opts.follow_redirects) parts.push(`<dt-toggle id="optRedirects" label="follow redirects"></dt-toggle>`);
    if (opts.sapi) {
      parts.push(`
        <label class="numfield">SAPI
          <select class="dt-select" id="optSapi">
            <option value="auto" selected>auto</option>
            <option value="mod_php">mod_php</option>
            <option value="fpm">fpm</option>
          </select>
        </label>
      `);
    }
    if (opts.threads) parts.push(`<label class="numfield">threads <input type="text" id="optThreads" value="10"></label>`);
    if (opts.timeout) parts.push(`<label class="numfield">timeout (s) <input type="text" id="optTimeout" value="60"></label>`);
    optsRow.innerHTML = parts.join("");
  }

  try {
    const res = await fetch("/api/scanners");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    scanners = data.scanners || [];
  } catch (e) {
    grid.innerHTML = `<div class="hint">Failed to load scanners: ${e.message}</div>`;
    return;
  }

  if (!scanners.length) {
    grid.innerHTML = `<div class="hint">No scanners found in core/scanners/.</div>`;
    return;
  }

  grid.innerHTML = "";
  scanners.forEach((sc, idx) => {
    const card = document.createElement("div");
    card.className = "tool-card ready";
    card.dataset.id = sc.id;

    const h3 = document.createElement("h3");
    const titleSpan = document.createElement("span");
    titleSpan.textContent = sc.name;
    const catBadge = document.createElement("span");
    catBadge.className = "badge free";
    catBadge.textContent = sc.category;
    h3.append(titleSpan, catBadge);

    const p = document.createElement("p");
    const maxLen = 160;
    p.textContent = sc.description.length > maxLen
      ? sc.description.slice(0, maxLen) + "…"
      : sc.description;
    if (sc.description.length > maxLen) p.title = sc.description;

    const btn = document.createElement("button");
    btn.textContent = "Select";
    btn.onclick = (e) => {
      e.stopPropagation();
      selectScanner(sc);
    };
    card.onclick = () => selectScanner(sc);

    card.append(h3, p, btn);
    grid.appendChild(card);
    if (idx === 0) selectScanner(sc);
  });

  const clamp = (val, min, max, fallback) => {
    const n = parseInt(val, 10);
    if (Number.isNaN(n)) return fallback;
    return Math.max(min, Math.min(max, n));
  };

  runBtn.onclick = async () => {
    if (!selected) return;
    const targetsRaw = container.querySelector("#targets").value;
    const targets = targetsRaw
      .split(/[\r\n]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    if (!targets.length) {
      scanStatus.textContent = "Enter at least one target URL or host.";
      return;
    }

    const pathsRaw = container.querySelector("#customPath")?.value || "";
    const paths = pathsRaw.split(/[\s,]+/).filter(Boolean);

    const body = {
      scanner_id: selected.id,
      targets,
      threads: clamp(container.querySelector("#optThreads")?.value, 1, 100, 10),
      timeout: clamp(container.querySelector("#optTimeout")?.value, 1, 300, 60),
      insecure: Boolean(container.querySelector("#optInsecure")?.checked),
      follow_redirects: Boolean(container.querySelector("#optRedirects")?.checked),
      sapi: container.querySelector("#optSapi")?.value || "auto",
      paths,
    };

    const controller = new AbortController();
    runBtn.disabled = true;
    scanStatus.textContent = "";
    modal.open(() => controller.abort());
    modal.setStatus(`Running ${selected.name} on ${targets.length} target(s)...`);

    let resultCount = 0;
    let vulnCount = 0;
    let cleanCount = 0;
    let errorCount = 0;
    let logLineCount = 0;

    try {
      const res = await fetch("/api/scanners/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        let detail = `HTTP ${res.status}`;
        try {
          const errData = await res.json();
          detail = errData.detail || detail;
        } catch { }
        throw new Error(detail);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      const handleEvent = (line) => {
        if (!line.trim()) return;
        let ev;
        try {
          ev = JSON.parse(line);
        } catch {
          return;
        }

        if (ev.type === "log") {
          logLineCount++;
          modal.addLog(ev.line);
          // Parse progress from tqdm-style output or bracket patterns
          const pctMatch = ev.line.match(/(\d+)%\|/);
          const bracketMatch = ev.line.match(/(\d+)\/(\d+)/);
          if (pctMatch) {
            const pct = parseInt(pctMatch[1]);
            if (bracketMatch) {
              modal.setProgress(parseInt(bracketMatch[1]), parseInt(bracketMatch[2]));
            } else {
              modal.setProgress(pct, 100);
            }
          }
          // Update the bottom status with the last meaningful log line
          const stripped = ev.line.replace(/\x1b\[[0-9;]*m/g, "").trim();
          if (stripped && !stripped.startsWith("=")) {
            modal.setStatus(stripped);
          }
        } else if (ev.type === "result") {
          resultCount++;
          let badge;
          if (ev.vulnerable === true) {
            vulnCount++;
            badge = { label: "vulnerable", cls: "taken" };
          } else if (ev.vulnerable === false) {
            cleanCount++;
            badge = { label: "clean", cls: "free" };
          } else {
            errorCount++;
            badge = { label: "unknown", cls: "soon" };
          }
          const details = [];
          if (ev.reason) details.push(ev.reason);
          if (ev.error) details.push(ev.error);
          if (ev.verdict) details.push(`verdict: ${ev.verdict}`);
          if (ev.powered_by) details.push(ev.powered_by);
          modal.addRow(ev.target, null, details, ev.error, badge);
          modal.setStatus(`${resultCount} result(s) — ${vulnCount} vuln / ${cleanCount} clean / ${errorCount} unknown`);
        } else if (ev.type === "error") {
          errorCount++;
          modal.addRow(ev.message || "Error", null, [ev.message], ev.message, { label: "error", cls: "taken" });
        } else if (ev.type === "done") {
          const summary = [
            `Scan complete (exit ${ev.exit_code})`,
            `${resultCount} target(s) scanned`,
            vulnCount > 0 ? `${vulnCount} VULNERABLE` : null,
            cleanCount > 0 ? `${cleanCount} clean` : null,
            errorCount > 0 ? `${errorCount} error/unknown` : null,
          ].filter(Boolean).join(" · ");
          modal.finish(summary);
        }
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split("\n");
        buf = lines.pop();
        for (const line of lines) handleEvent(line);
      }
      buf += decoder.decode();
      if (buf.trim()) handleEvent(buf);

      // If we never got a "done" event, generate a finish summary
      if (resultCount === 0 && logLineCount > 0) {
        modal.finish(`Scan complete — ${logLineCount} log line(s), no structured results (check log).`);
      }
    } catch (e) {
      if (e.name !== "AbortError") {
        modal.finish("Error: " + e.message);
      }
    } finally {
      runBtn.disabled = false;
    }
  };
}
