import { LitElement, html } from "lit";
import "#js/network-location.js";

/** Open the network behind an address in a dialog. */
export class IpAddress extends LitElement {
  static properties = {
    address: { type: String },
  };

  constructor() {
    super();
    this.address = "";
  }

  createRenderRoot() {
    return this;
  }

  open() {
    this.querySelector("dialog")?.showModal();
  }

  closeOnBackdrop(event) {
    // A click on the dialog itself misses the card, so it hits the backdrop.
    if (event.target === event.currentTarget) {
      event.currentTarget.close();
    }
  }

  render() {
    const { map: mapLabel, unavailable, retry } = this.dataset;
    return html`
      <button
        type="button"
        class="link cursor-pointer font-mono"
        aria-haspopup="dialog"
        @click=${this.open}
      >
        ${this.address}
      </button>
      <dialog
        class="m-auto w-full max-w-md bg-transparent p-0 backdrop:bg-black/80"
        aria-label=${this.address}
        @click=${this.closeOnBackdrop}
      >
        <network-location
          address=${this.address}
          map
          data-map=${mapLabel}
          data-unavailable=${unavailable}
          data-retry=${retry}
        ></network-location>
      </dialog>
    `;
  }
}

customElements.define("ip-address", IpAddress);
