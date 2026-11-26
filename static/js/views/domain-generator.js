export const meta = { id: "domain-generator", label: "Domain Generator" };

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <h1>Domain Generator</h1>
      <div class="sub">keywords → brandable domain ideas</div>
    </div>

    <div class="panel">
      <h2>Keywords</h2>
      <div class="field-row">
        <dt-input id="kw" label="Seed words, space separated" placeholder="coffee roast" value="coffee roast"></dt-input>
      </div>

      <div style="margin-top:18px;">
        <dt-chip-group id="tlds" label="TLDs"
          options="com,io,co,app,dev,net,ai,org"
          selected="com,io,co,app,dev"></dt-chip-group>
      </div>

      <div class="opts-row">
        <dt-toggle id="hyphens" label="hyphenated variants"></dt-toggle>
        <dt-toggle id="check" label="check availability (DNS)" checked></dt-toggle>
        <dt-toggle id="php" label="flag live PHP sites"></dt-toggle>
        <label class="numfield">results <input type="text" id="count" value="25"></label>
        <label class="numfield">max len <input type="text" id="maxlen" value="15"></label>
      </div>

      <div class="actions">
        <button class="primary" id="run">Generate</button>
        <span class="hint" id="inlineStatus"></span>
      </div>
    </div>
  `;

  const runBtn = container.querySelector("#run");
  const inlineStatus = container.querySelector("#inlineStatus");
  const modal = document.getElementById("resultsModal");

  async function run() {
    const keywords = container.querySelector("#kw").value.split(/\s+/).filter(Boolean);
    if (!keywords.length) {
      inlineStatus.textContent = "Enter at least one keyword.";
      return;
    }

    const tlds = container.querySelector("#tlds").value;
    if (!tlds.length) {
      inlineStatus.textContent = "Select at least one TLD.";
      return;
    }

    const clamp = (val, min, max, fallback) => {
      const n = parseInt(val, 10);
      if (Number.isNaN(n)) return fallback;
      return Math.max(min, Math.min(max, n));
    };

    const body = {
      keywords,
      tlds,
      max_length: clamp(container.querySelector("#maxlen").value, 3, 63, 15),
      hyphens: container.querySelector("#hyphens").checked,
      count: clamp(container.querySelector("#count").value, 1, 500, 25),
      check: container.querySelector("#check").checked,
      php: container.querySelector("#php").checked,
    };

    const controller = new AbortController();
    runBtn.disabled = true;
    inlineStatus.textContent = "";
    modal.open(() => controller.abort());
    modal.setSendToScanner((targets) => {
      window.dispatchEvent(new CustomEvent("xplota:send-to-scanner", { detail: { targets } }));
    });

    let found = 0;
    try {
      if (!body.check && !body.php) {
        const res = await fetch("/api/generate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        data.domains.forEach((d) => {
          modal.addRow(d, null, [], null);
          found++;
        });
        modal.finish(`${found} idea(s) generated.`);
      } else {
        modal.setStatus(`Scanning domains with DNS${body.php ? " + PHP fingerprint" : ""}...`);
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
          signal: controller.signal,
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        const handleLine = (line) => {
          if (!line.trim()) return;
          const r = JSON.parse(line);
          modal.addRow(r.domain, r.available, r.php_signals, r.error);
          found++;
          modal.setStatus(`${found} result(s) so far...`);
        };
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          const lines = buf.split("\n");
          buf = lines.pop();
          for (const line of lines) handleLine(line);
        }
        buf += decoder.decode();
        if (buf.trim()) handleLine(buf);
        modal.finish(`Done — ${found} result(s).`);
      }
    } catch (e) {
      if (e.name !== "AbortError") {
        modal.finish("Error: " + e.message);
      }
    } finally {
      runBtn.disabled = false;
    }
  }

  runBtn.onclick = run;
  container.querySelector("#kw").addEventListener("keydown", (e) => {
    if (e.key === "Enter") run();
  });
}
