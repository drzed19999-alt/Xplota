class DtToggle extends HTMLElement {
  connectedCallback() {
    const label = this.getAttribute("label") || "";
    this.innerHTML = `<div class="switch"></div><span class="t-label">${label}</span>`;
    this.addEventListener("click", () => {
      this.hasAttribute("checked")
        ? this.removeAttribute("checked")
        : this.setAttribute("checked", "");
    });
  }
  get checked() {
    return this.hasAttribute("checked");
  }
}
customElements.define("dt-toggle", DtToggle);
