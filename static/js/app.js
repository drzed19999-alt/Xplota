// Side-effect imports: each defines its custom element.
import "./components/dt-input.js";
import "./components/dt-chip-group.js";
import "./components/dt-toggle.js";
import "./components/dt-modal.js";

import * as domainGenerator from "./views/domain-generator.js";
import * as scanners from "./views/scanners.js";
import * as exploits from "./views/exploits.js";

const views = [domainGenerator, scanners, exploits];
const mainEl = document.getElementById("mainView");
const navButtons = Array.from(document.querySelectorAll(".nav-item"));

function showView(id, state = null) {
  const view = views.find((v) => v.meta.id === id) || views[0];
  navButtons.forEach((btn) => btn.classList.toggle("active", btn.dataset.view === view.meta.id));
  view.render(mainEl, state);
  history.replaceState(null, "", `#${view.meta.id}`);
}

window.addEventListener("xplota:send-to-scanner", (e) => {
  showView("scanners", { targets: e.detail?.targets || [] });
});

navButtons.forEach((btn) => {
  btn.addEventListener("click", () => showView(btn.dataset.view));
});

const initial = location.hash.replace("#", "") || "domain-generator";
showView(initial);
