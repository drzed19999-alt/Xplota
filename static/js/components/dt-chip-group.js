class DtChipGroup extends HTMLElement {
  connectedCallback() {
    const label = this.getAttribute("label") || "";
    const options = (this.getAttribute("options") || "").split(",").filter(Boolean);
    const selected = new Set((this.getAttribute("selected") || "").split(",").filter(Boolean));
    this.innerHTML = `<label>${label}</label><div class="chip-row"></div>`;
    const row = this.querySelector(".chip-row");
    this._selected = selected;
    options.forEach((opt) => {
      const chip = document.createElement("div");
      chip.className = "chip" + (selected.has(opt) ? " on" : "");
      chip.textContent = "." + opt;
      chip.onclick = () => {
        if (selected.has(opt)) selected.delete(opt);
        else selected.add(opt);
        chip.classList.toggle("on");
      };
      row.appendChild(chip);
    });
  }
  get value() {
    return Array.from(this._selected);
  }
}
customElements.define("dt-chip-group", DtChipGroup);
