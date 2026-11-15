// Field classification shared by the content script and its unit tests.
// What a focused input is for (login, card, …), plus the DOM helpers fill and the
// menu need: open-shadow walks, dialog scope, top-layer hosts. Closed shadow roots
// stay invisible here (the content script can't open them); Nyx Browser's actor can.

(function (root) {
  const textLike = (el) => ["text", "email", "tel", "number", ""].includes(el.type);
  // Username cues. Bare "account" is omitted: checkout forms use it for payment, not sign-in.
  const USERNAME_WORDS = /user.?name|user|login|e.?mail|identifier|signin|sign.?in|session.?key|loginfmt|member/;
  const CARD_WORDS =
    /(?:^|[^a-z])(?:pan|cardnum|card.?no|cc.?num)|card.?number|credit.?card|payment.?card|card.?holder|name.?on.?card|cvc|cvv|csc|security.?code|expir|exp.?date|mm.?yy/;

  function describe(el) {
    let labels = "";
    try {
      labels = [...(el.labels ?? [])].map((l) => l.textContent ?? "").join(" ");
    } catch {}
    return `${el.name} ${el.id} ${el.placeholder ?? ""} ${el.getAttribute("aria-label") ?? ""} ${el.autocomplete ?? ""} ${labels}`.toLowerCase();
  }

  /** Shown on screen. Read-only is allowed for detection (some pages unlock on click). */
  function visible(el) {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && el.checkVisibility?.({ visibilityProperty: true }) !== false && !el.disabled;
  }

  const composedParent = (el) => el.parentElement ?? el.getRootNode?.()?.host ?? null;

  function dialogOf(el) {
    for (let node = el; node; node = composedParent(node)) {
      if (node.localName === "dialog" || ["dialog", "alertdialog"].includes(node.getAttribute?.("role")) || node.getAttribute?.("aria-modal") === "true") {
        return node;
      }
    }
    return null;
  }

  const scopeOf = (el) => el.form ?? dialogOf(el) ?? el.ownerDocument;

  /** Every input under `root`, through open shadow roots, in document order. */
  function deepInputs(root) {
    const out = [];
    const walk = (node) => {
      if (!node) return;
      if (node.querySelectorAll) {
        for (const el of node.querySelectorAll("input")) out.push(el);
        for (const el of node.querySelectorAll("*")) {
          if (el.shadowRoot) walk(el.shadowRoot);
        }
      }
    };
    walk(root);
    return out;
  }

  function topLayerOf(el) {
    for (let node = el; node; node = composedParent(node)) {
      try {
        if (node.matches?.("dialog:modal, :popover-open")) return node;
      } catch {}
    }
    return null;
  }

  function ccAutocomplete(ac) {
    return ac.split(/\s+/).some((token) => token === "cc" || token.startsWith("cc-") || token.includes("cc-"));
  }

  function paymentKeypad(el, scope) {
    const numeric = el.type === "tel" || el.type === "number" || (el.getAttribute("inputmode") || "").toLowerCase() === "numeric";
    if (!numeric) return false;
    const max = el.maxLength > 0 ? el.maxLength : 0;
    const withCard = deepInputs(scope).some(
      (i) => i !== el && visible(i) && (ccAutocomplete((i.autocomplete || "").toLowerCase()) || CARD_WORDS.test(describe(i))),
    );
    if (withCard && max >= 3 && max <= 19) return true;
    if (withCard && !max) return true;
    return max >= 13 && max <= 19;
  }

  function signInStep(scope) {
    if (!scope || scope === scope.ownerDocument || scope.nodeType === 9) return false;
    const fields = deepInputs(scope).filter((i) => visible(i) && !["hidden", "checkbox", "radio", "submit", "button", "search"].includes(i.type));
    if (!fields.length || fields.length > 2) return false;
    const labels = [...scope.querySelectorAll('button, input[type="submit"], [role="button"], a')]
      .map((b) => `${b.textContent} ${b.value ?? ""} ${b.getAttribute("aria-label") ?? ""}`)
      .join(" ");
    return /next|continue|sign.?in|log.?in/i.test(labels) && !/subscribe|newsletter|join|sign.?up|register/i.test(labels);
  }

  /** What a field is for, or null. */
  function kindOf(el) {
    if (!(el instanceof (root.HTMLInputElement || globalThis.HTMLInputElement)) || !visible(el)) return null;
    const ac = (el.autocomplete || "").toLowerCase();
    const t = describe(el);
    if (ac.includes("one-time-code") || /(^|[^a-z])(otp|totp|2fa|mfa)|one.?time|verification.?code|auth.?code/.test(t)) return "otp";
    const scope = scopeOf(el);
    if (ccAutocomplete(ac) || CARD_WORDS.test(t) || paymentKeypad(el, scope)) return "card";
    if (el.type === "password") {
      const passwords = deepInputs(scope).filter((i) => i.type === "password" && visible(i));
      return ac.includes("new-password") || passwords.length > 1 || /new|confirm|repeat|create/.test(t) ? "new-password" : "login";
    }
    if (textLike(el)) {
      if (ac.includes("username") || ac === "webauthn") return "login";
      const usernameCue = /\bemail\b/.test(ac) || ac.includes("username") || USERNAME_WORDS.test(t) || el.type === "email";
      if (usernameCue) {
        const near = deepInputs(scope).some((i) => i.type === "password" && visible(i));
        if (near || signInStep(scope)) return "login";
      }
      if (/given-name|family-name|street-address|address-line|postal-code|country/.test(ac) || /first.?name|last.?name|address|postal|zip|city/.test(t)) {
        return "identity";
      }
      if (/\btel\b/.test(ac) || (el.type === "tel" && /phone|mobile|tel/.test(t))) return "identity";
    }
    return null;
  }

  const eventTarget = (e) => {
    const path = typeof e.composedPath === "function" ? e.composedPath() : [];
    return path[0] ?? e.target;
  };

  root.NyxFieldKind = {
    textLike,
    USERNAME_WORDS,
    CARD_WORDS,
    describe,
    visible,
    composedParent,
    dialogOf,
    scopeOf,
    deepInputs,
    topLayerOf,
    ccAutocomplete,
    paymentKeypad,
    signInStep,
    kindOf,
    eventTarget,
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
