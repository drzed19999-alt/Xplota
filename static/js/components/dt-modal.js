class DtModal extends HTMLElement {
  connectedCallback() {
    const title = this.getAttribute("title") || "Results";
    this.innerHTML = `
      <dialog class="dt-modal">
        <div class="modal-head">
          <div><h3>${title}</h3><span class="count" id="dtModalCount"></span></div>
          <button class="modal-close" aria-label="Close">&times;</button>
        </div>
        <div class="modal-tools">
          <input type="text" id="dtModalFilter" placeholder="Filter results...">
          <button id="dtModalExport">Export CSV</button>
        </div>
        <div class="modal-body">
          <div class="modal-empty" id="dtModalEmpty">Nothing yet.</div>
          <table style="display:none" id="dtModalTable">
            <thead><tr><th style="width:42%">Domain</th><th style="width:18%">Status</th><th>Signals</th></tr></thead>
            <tbody id="dtModalTbody"></tbody>
          </table>
        </div>
        <div class="modal-foot" id="dtModalFoot"></div>
      </dialog>`;
    this._dialog = this.querySelector("dialog");
    this._tbody = this.querySelector("#dtModalTbody");
    this._table = this.querySelector("#dtModalTable");
    this._empty = this.querySelector("#dtModalEmpty");
    this._count = this.querySelector("#dtModalCount");
    this._foot = this.querySelector("#dtModalFoot");
    this._filterInput = this.querySelector("#dtModalFilter");
    this.querySelector(".modal-close").onclick = () => this._dialog.close();
    this._dialog.addEventListener("close", () => {
      if (this._onClose) {
        const cb = this._onClose;
        this._onClose = null;
        cb();
      }
    });
    this._filterInput.oninput = (e) => this._filter(e.target.value);
    this.querySelector("#dtModalExport").onclick = () => this._exportCsv();
    this._rows = [];
    this._onClose = null;
  }
  open(onClose = null) {
    this._rows = [];
    this._onClose = onClose;
    this._tbody.innerHTML = "";
    this._filterInput.value = "";
    this._table.style.display = "none";
    this._empty.style.display = "block";
    this._empty.textContent = "Searching...";
    this._count.textContent = "";
    this._foot.textContent = "";
    this._dialog.showModal();
  }
  setStatus(text) {
    this._foot.textContent = text;
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
      btn.textContent = "copied";
      setTimeout(() => { btn.textContent = prev; }, 1000);
    } catch {
      // Ignore clipboard permission errors
    }
  }
  addRow(domain, available, signals, error) {
    this._empty.style.display = "none";
    this._table.style.display = "table";
    const tr = document.createElement("tr");
    tr.dataset.domain = domain;
    const d = document.createElement("td");
    const cell = document.createElement("div");
    cell.className = "domain-cell";
    const nameSpan = document.createElement("span");
    nameSpan.textContent = domain;
    const copyBtn = document.createElement("button");
    copyBtn.className = "copy-btn";
    copyBtn.textContent = "copy";
    copyBtn.onclick = () => this._copyText(domain, copyBtn);
    cell.append(nameSpan, copyBtn);
    d.appendChild(cell);

    const s = document.createElement("td");
    let statusLabel = "";
    if (error) {
      statusLabel = "error";
      s.innerHTML = `<span class="badge taken">error</span>`;
    } else if (available === true) {
      statusLabel = "available";
      s.innerHTML = `<span class="badge free">available</span>`;
    } else if (available === false) {
      statusLabel = "taken";
      s.innerHTML = `<span class="badge taken">taken</span>`;
    } else {
      statusLabel = "generated";
      s.innerHTML = `<span class="sig">—</span>`;
    }

    const sig = document.createElement("td");
    sig.className = "sig";
    const sigText = signals && signals.length ? signals.join(", ") : (error || "");
    sig.textContent = sigText;
    tr.append(d, s, sig);
    this._tbody.appendChild(tr);
    this._rows.push({ domain, status: statusLabel, signals: sigText });
    this._count.textContent = `${this._rows.length} result(s)`;
  }
  finish(summary) {
    this.setStatus(summary);
    if (this._rows.length === 0) {
      this._empty.style.display = "block";
      this._empty.textContent = "No matches. Try different keywords or TLDs.";
    }
  }
  _filter(q) {
    q = q.toLowerCase();
    Array.from(this._tbody.children).forEach((tr) => {
      tr.style.display = tr.dataset.domain.toLowerCase().includes(q) ? "" : "none";
    });
  }
  _exportCsv() {
    const esc = (v) => `"${String(v).replace(/"/g, '""')}"`;
    const lines = ["domain,status,signals"].concat(
      this._rows.map((r) => [esc(r.domain), esc(r.status), esc(r.signals)].join(","))
    );
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "domains.csv";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
customElements.define("dt-modal", DtModal);
