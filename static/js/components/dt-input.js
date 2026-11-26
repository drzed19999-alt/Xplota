class DtInput extends HTMLElement {
  connectedCallback() {
    const label = this.getAttribute("label") || "";
    const placeholder = this.getAttribute("placeholder") || "";
    const value = this.getAttribute("value") || "";
    this.innerHTML = `<label>${label}</label><input type="text" placeholder="${placeholder}" value="${value}">`;
    this._input = this.querySelector("input");
  }
  get value() {
    return this._input.value.trim();
  }
}
customElements.define("dt-input", DtInput);
