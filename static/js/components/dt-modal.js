class DtModal extends HTMLElement {
  connectedCallback() {
    const title = this.getAttribute("title") || "Results";
    this.innerHTML = `
      <dialog class="dt-modal">
        <div class="modal-head">
          <div class="modal-head-left">
            <h3>${title}</h3>
            <span class="modal-counter" id="dtModalCount"></span>
          </div>
          <div class="modal-head-right">
            <div class="modal-stats" id="dtModalStats"></div>
            <button class="modal-close" aria-label="Close">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M12 4L4 12M4 4l8 8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
            </button>
          </div>
        </div>

        <div class="modal-progress-wrap" id="dtModalProgressWrap" style="display:none">
          <div class="modal-progress-bar"><div class="modal-progress-fill" id="dtModalProgressFill"></div></div>
          <span class="modal-progress-label" id="dtModalProgressLabel"></span>
        </div>

        <div class="modal-log-wrap" id="dtModalLogWrap" style="display:none">
          <div class="modal-log-toggle" id="dtModalLogToggle">
            <svg class="log-chevron" width="12" height="12" viewBox="0 0 12 12"><path d="M4 2l4 4-4 4" stroke="currentColor" stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>
            <span>Live Log</span>
            <span class="modal-log-count" id="dtModalLogCount">0 lines</span>
          </div>
          <div class="modal-log" id="dtModalLog" style="display:none"></div>
        </div>

        <div class="modal-tools">
          <div class="modal-search-wrap">
            <svg class="modal-search-icon" width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="6" cy="6" r="4.5" stroke="currentColor" stroke-width="1.3"/><path d="M9.5 9.5L13 13" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
            <input type="text" id="dtModalFilter" placeholder="Filter results...">
          </div>
          <div class="modal-tools-actions">
            <button id="dtModalExport" title="Export CSV">
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 1v8M4 6l3 3 3-3M2 11h10" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>
              CSV
            </button>
            <button id="dtModalCopyAll" title="Copy all results">
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><rect x="4" y="4" width="8" height="8" rx="1.5" stroke="currentColor" stroke-width="1.2"/><path d="M10 4V2.5A1.5 1.5 0 008.5 1h-6A1.5 1.5 0 001 2.5v6A1.5 1.5 0 002.5 10H4" stroke="currentColor" stroke-width="1.2"/></svg>
              Copy
            </button>
          </div>
        </div>

        <div class="modal-body" id="dtModalBody">
          <div class="modal-empty" id="dtModalEmpty">
            <div class="modal-spinner"></div>
            <span>Initializing...</span>
          </div>
          <table style="display:none" id="dtModalTable">
            <thead><tr><th style="width:42%">Target</th><th style="width:16%">Status</th><th>Details</th></tr></thead>
            <tbody id="dtModalTbody"></tbody>
          </table>
        </div>

        <div class="modal-foot" id="dtModalFoot">
          <div class="modal-foot-left" id="dtModalFootLeft"></div>
          <div class="modal-foot-right" id="dtModalFootRight">
            <span class="modal-elapsed" id="dtModalElapsed"></span>
          </div>
        </div>
      </dialog>`;

    this._dialog = this.querySelector("dialog");
    this._tbody = this.querySelector("#dtModalTbody");
    this._table = this.querySelector("#dtModalTable");
    this._empty = this.querySelector("#dtModalEmpty");
    this._count = this.querySelector("#dtModalCount");
    this._foot = this.querySelector("#dtModalFootLeft");
    this._stats = this.querySelector("#dtModalStats");
    this._progressWrap = this.querySelector("#dtModalProgressWrap");
    this._progressFill = this.querySelector("#dtModalProgressFill");
    this._progressLabel = this.querySelector("#dtModalProgressLabel");
    this._logWrap = this.querySelector("#dtModalLogWrap");
    this._logToggle = this.querySelector("#dtModalLogToggle");
    this._logPanel = this.querySelector("#dtModalLog");
    this._logCount = this.querySelector("#dtModalLogCount");
    this._elapsed = this.querySelector("#dtModalElapsed");
    this._filterInput = this.querySelector("#dtModalFilter");

    this.querySelector(".modal-close").onclick = () => this._dialog.close();
    this._dialog.addEventListener("close", () => {
      this._stopTimer();
      if (this._onClose) {
        const cb = this._onClose;
        this._onClose = null;
        cb();
      }
    });
    this._filterInput.oninput = (e) => this._filter(e.target.value);
    this.querySelector("#dtModalExport").onclick = () => this._exportCsv();
    this.querySelector("#dtModalCopyAll").onclick = (e) => this._copyAll(e.currentTarget);
    this._logToggle.onclick = () => {
      const open = this._logPanel.style.display === "none";
      this._logPanel.style.display = open ? "block" : "none";
      this._logToggle.classList.toggle("open", open);
      if (open) this._logPanel.scrollTop = this._logPanel.scrollHeight;
    };

    this._rows = [];
    this._logs = [];
    this._onClose = null;
    this._timer = null;
    this._startTime = null;
    this._statCounts = { vulnerable: 0, clean: 0, error: 0, available: 0, taken: 0, generated: 0 };
  }

  open(onClose = null) {
    this._rows = [];
    this._logs = [];
    this._onClose = onClose;
    this._tbody.innerHTML = "";
    this._filterInput.value = "";
    this._table.style.display = "none";
    this._empty.style.display = "flex";
    this._empty.innerHTML = `<div class="modal-spinner"></div><span>Initializing...</span>`;
    this._count.textContent = "";
    this._foot.textContent = "";
    this._stats.innerHTML = "";
    this._progressWrap.style.display = "none";
    this._progressFill.style.width = "0%";
    this._progressLabel.textContent = "";
    this._logWrap.style.display = "none";
    this._logPanel.style.display = "none";
    this._logPanel.innerHTML = "";
    this._logCount.textContent = "0 lines";
    this._logToggle.classList.remove("open");
    this._elapsed.textContent = "";
    this._statCounts = { vulnerable: 0, clean: 0, error: 0, available: 0, taken: 0, generated: 0 };
    this._startTime = Date.now();
    this._startTimer();
    this._dialog.showModal();
  }

  setStatus(text) {
    this._foot.textContent = text;
  }

  setProgress(current, total) {
    this._progressWrap.style.display = "flex";
    const pct = total > 0 ? Math.round((current / total) * 100) : 0;
    this._progressFill.style.width = pct + "%";
    this._progressLabel.textContent = `${current}/${total} (${pct}%)`;
  }

  addLog(line) {
    this._logWrap.style.display = "block";
    this._logs.push(line);
    const el = document.createElement("div");
    el.className = "log-line";
    el.textContent = line;
    this._logPanel.appendChild(el);
    this._logCount.textContent = `${this._logs.length} lines`;
    if (this._logPanel.style.display !== "none") {
      this._logPanel.scrollTop = this._logPanel.scrollHeight;
    }
    // Keep log panel memory bounded
    if (this._logPanel.children.length > 500) {
      this._logPanel.removeChild(this._logPanel.firstChild);
    }
  }

  async _copyText(text, btn) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
      const prev = btn.textContent;
      btn.textContent = "copied!";
      setTimeout(() => { btn.textContent = prev; }, 1200);
    } catch {
      // Ignore clipboard errors
    }
  }

  addRow(domain, available, signals, error, badgeOverride = null) {
    this._empty.style.display = "none";
    this._table.style.display = "table";
    const tr = document.createElement("tr");
    tr.className = "modal-result-row";
    tr.dataset.domain = domain;

    // Target cell
    const d = document.createElement("td");
    const cell = document.createElement("div");
    cell.className = "domain-cell";
    const nameSpan = document.createElement("span");
    nameSpan.className = "domain-name";
    nameSpan.textContent = domain;
    const copyBtn = document.createElement("button");
    copyBtn.className = "copy-btn";
    copyBtn.textContent = "copy";
    copyBtn.onclick = () => this._copyText(domain, copyBtn);
    cell.append(nameSpan, copyBtn);
    d.appendChild(cell);

    // Status cell
    const s = document.createElement("td");
    let statusLabel = "";
    const badge = document.createElement("span");
    if (badgeOverride) {
      statusLabel = badgeOverride.label;
      badge.className = `badge ${badgeOverride.cls || "soon"}`;
      badge.textContent = statusLabel;
    } else if (error) {
      statusLabel = "error";
      badge.className = "badge taken";
      badge.textContent = "error";
    } else if (available === true) {
      statusLabel = "available";
      badge.className = "badge free";
      badge.textContent = "available";
    } else if (available === false) {
      statusLabel = "taken";
      badge.className = "badge taken";
      badge.textContent = "taken";
    } else {
      statusLabel = "generated";
      badge.className = "badge soon";
      badge.textContent = "generated";
    }
    s.appendChild(badge);

    // Track stats
    const statKey = statusLabel.toLowerCase();
    if (statKey in this._statCounts) {
      this._statCounts[statKey]++;
    }

    // Details cell
    const sig = document.createElement("td");
    sig.className = "sig";
    const sigText = signals && signals.length ? (typeof signals === "string" ? signals : signals.join(", ")) : (error || "");
    sig.textContent = sigText;
    tr.append(d, s, sig);
    this._tbody.appendChild(tr);
    this._rows.push({ domain, status: statusLabel, signals: sigText });
    this._count.textContent = `${this._rows.length} result(s)`;
    this._updateStats();

    // Auto-scroll to new result
    const body = this.querySelector("#dtModalBody");
    if (body) {
      const isNearBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 80;
      if (isNearBottom) body.scrollTop = body.scrollHeight;
    }
  }

  finish(summary) {
    this._stopTimer();
    this.setStatus(summary);
    this._progressWrap.style.display = "none";
    if (this._rows.length === 0) {
      this._empty.style.display = "flex";
      this._empty.innerHTML = `
        <svg width="40" height="40" viewBox="0 0 40 40" fill="none"><circle cx="20" cy="20" r="18" stroke="var(--ink-faint)" stroke-width="1.5"/><path d="M14 26c1.5-3 4-4.5 6-4.5s4.5 1.5 6 4.5" stroke="var(--ink-faint)" stroke-width="1.5" stroke-linecap="round"/><circle cx="15" cy="16" r="1.5" fill="var(--ink-faint)"/><circle cx="25" cy="16" r="1.5" fill="var(--ink-faint)"/></svg>
        <span>No matches found. Try different settings.</span>`;
    }
  }

  _updateStats() {
    const c = this._statCounts;
    const parts = [];
    if (c.vulnerable > 0) parts.push(`<span class="stat-pill vuln">${c.vulnerable} vuln</span>`);
    if (c.clean > 0) parts.push(`<span class="stat-pill clean">${c.clean} clean</span>`);
    if (c.available > 0) parts.push(`<span class="stat-pill avail">${c.available} avail</span>`);
    if (c.taken > 0) parts.push(`<span class="stat-pill taken">${c.taken} taken</span>`);
    if (c.error > 0) parts.push(`<span class="stat-pill err">${c.error} err</span>`);
    this._stats.innerHTML = parts.join("");
  }

  _startTimer() {
    this._stopTimer();
    this._timer = setInterval(() => {
      if (!this._startTime) return;
      const sec = Math.floor((Date.now() - this._startTime) / 1000);
      const m = Math.floor(sec / 60);
      const s = sec % 60;
      this._elapsed.textContent = m > 0 ? `${m}m ${s}s` : `${s}s`;
    }, 1000);
  }

  _stopTimer() {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  _filter(q) {
    q = q.toLowerCase();
    Array.from(this._tbody.children).forEach((tr) => {
      const match = tr.dataset.domain.toLowerCase().includes(q) ||
                    tr.textContent.toLowerCase().includes(q);
      tr.style.display = match ? "" : "none";
    });
  }

  _exportCsv() {
    const esc = (v) => `"${String(v).replace(/"/g, '""')}"`;
    const lines = ["domain,status,details"].concat(
      this._rows.map((r) => [esc(r.domain), esc(r.status), esc(r.signals)].join(","))
    );
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `results-${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async _copyAll(btn) {
    const text = this._rows.map((r) => `${r.domain}\t${r.status}\t${r.signals}`).join("\n");
    await this._copyText(text, btn);
  }
}
customElements.define("dt-modal", DtModal);
