import { LitElement, html } from "lit";
import "#js/network-location.js";

/** Open the network behind an address in a dialog. */
export class IpAddress extends LitElement {
  /** Declare the properties the element renders from. */
  static properties = {
    /** Address used for both the trigger label and the lookup. */
    address: { type: String },
  };

  /** Initialise the address before Lit applies attributes. */
  constructor() {
    super();
    this.address = "";
  }

  /** Return the light DOM so the dialog reaches the page styles. */
  createRenderRoot() {
    return this;
  }

  /** Open the dialog. */
  open() {
    this.querySelector("dialog")?.showModal();
  }

  /** Close the dialog when the backdrop is clicked. */
  closeOnBackdrop(event) {
    // A click on the dialog itself misses the card, so it hits the backdrop.
    if (event.target === event.currentTarget) {
      event.currentTarget.close();
    }
  }

  /** Render the address trigger and its dialog. */
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
        class="m-auto w-[calc(100%-2rem)] max-w-md bg-transparent p-0 backdrop:bg-black/80"
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
