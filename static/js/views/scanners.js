export const meta = { id: "scanners", label: "Scanners" };

// UI shell only -- no scanning logic lives here. Wire these cards up to
// your own backend endpoints when you're ready to add real functionality.
const PLANNED_TOOLS = [
  { name: "Port Scanner", desc: "Sweep hosts for open TCP/UDP ports." },
  { name: "Service Detector", desc: "Fingerprint running services and versions." },
  { name: "Web Tech Scanner", desc: "Identify CMS, frameworks and server stack." },
  { name: "Subdomain Finder", desc: "Enumerate subdomains for a target domain." },
];

export function render(container) {
  container.innerHTML = `
    <div class="view-header">
      <h1>Scanners</h1>
      <div class="sub">ui shell · not yet wired up</div>
    </div>
    <div class="panel">
      <h2>Planned tools</h2>
      <div class="tool-grid" id="toolGrid"></div>
    </div>
  `;

  const grid = container.querySelector("#toolGrid");
  PLANNED_TOOLS.forEach((tool) => {
    const card = document.createElement("div");
    card.className = "tool-card";
    card.innerHTML = `
      <h3>${tool.name} <span class="badge soon">soon</span></h3>
      <p>${tool.desc}</p>
      <button disabled>Run</button>
    `;
    grid.appendChild(card);
  });
}
