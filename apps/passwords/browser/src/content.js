// Runs in every page frame (isolated from the page's own scripts). It notices login,
// sign-up, one-time-code, card and address fields, and opens this extension's menu
// under them; it reports submitted logins (for the save bar) and clicks on "Sign in
// with …" buttons, and shows the passkey card. It never sees a vault value: filling is
// done by the background script, into this frame, after the app checked the page.

(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (globalThis.__nyxPasswords) return;
  globalThis.__nyxPasswords = true;

  const visible = (el) => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && el.checkVisibility?.({ visibilityProperty: true }) !== false && !el.disabled && !el.readOnly;
  };
  const shown = (el) => el.getClientRects().length > 0;
  const textLike = (el) => ["text", "email", "tel"].includes(el.type);
  const text = (el) => `${el.name} ${el.id} ${el.placeholder ?? ""} ${el.getAttribute("aria-label") ?? ""} ${el.autocomplete ?? ""}`.toLowerCase();

  // A form with one or two fields and a Next or Sign in button: a sign-in's first step,
  // not a newsletter box.
  function signInStep(form) {
    if (!form) return false;
    const fields = [...form.querySelectorAll("input")].filter((i) => visible(i) && !["hidden", "checkbox", "radio", "submit", "button", "search"].includes(i.type));
    if (!fields.length || fields.length > 2) return false;
    const labels = [...form.querySelectorAll('button, input[type="submit"], [role="button"]')]
      .map((b) => `${b.textContent} ${b.value ?? ""} ${b.getAttribute("aria-label") ?? ""}`)
      .join(" ");
    return /next|continue|sign.?in|log.?in/i.test(labels) && !/subscribe|newsletter|join|sign.?up|register/i.test(labels);
  }

  /// What a field is for, or null.
  function kindOf(el) {
    if (!(el instanceof HTMLInputElement) || !visible(el)) return null;
    const ac = (el.autocomplete || "").toLowerCase();
    const t = text(el);
    if (ac.includes("one-time-code") || /(^|[^a-z])(otp|totp|2fa|mfa)|one.?time|verification.?code|auth.?code/.test(t)) return "otp";
    if (ac.startsWith("cc-") || /card.?number|cc.?num|cvc|cvv|csc|card.?holder|expir/.test(t)) return "card";
    if (el.type === "password") {
      const passwords = [...(el.form ?? document).querySelectorAll('input[type="password"]')].filter(visible);
      return ac.includes("new-password") || passwords.length > 1 || /new|confirm|repeat|create/.test(t) ? "new-password" : "login";
    }
    if (textLike(el)) {
      if (ac.includes("username")) return "login";
      if (/email/.test(ac) || /user|login|e.?mail|account/.test(t)) {
        // A username with a password near it, or a sign-in's first step.
        const password = [...(el.form ?? document).querySelectorAll('input[type="password"]')].some(visible);
        if (password || signInStep(el.form)) return "login";
      }
      if (/given-name|family-name|street-address|address-line|postal-code|country|tel$/.test(ac) || /first.?name|last.?name|address|postal|zip|city/.test(t)) {
        return "identity";
      }
    }
    return null;
  }

  // The menu opens for the person, not for the page: after a click or a key, never on a
  // field the page focused itself or one a fill just moved the cursor to.
  let lastInput = 0;
  for (const type of ["pointerdown", "keydown"]) {
    document.addEventListener(type, (e) => e.isTrusted && (lastInput = Date.now()), true);
  }
  const byUser = () => Date.now() - lastInput < 1000;
  const filling = () => Date.now() - (globalThis.__nyxFilling ?? 0) < 600;

  // A modal dialog or popover is drawn above everything else (and the rest of the page
  // can't be clicked), so the menu and cards go inside it.
  function topLayer(el) {
    try {
      return (el ? el.closest("dialog:modal, :popover-open") : [...document.querySelectorAll("dialog:modal, :popover-open")].pop()) ?? null;
    } catch {
      return null;
    }
  }

  // ---- the menu under a field ----

  let host = null;
  let frame = null;
  let anchor = null;
  let opening = null;
  let closing = null;

  function closeMenu() {
    host?.remove();
    host = frame = anchor = null;
    globalThis.__nyxAnchor = null;
  }

  function place() {
    if (!host || !anchor) return;
    if (!anchor.isConnected) return closeMenu();
    const r = anchor.getBoundingClientRect();
    const width = Math.min(380, Math.max(300, r.width));
    const height = frame?.offsetHeight ?? 220;
    // Below the field, or above it where there's no room below.
    const top = r.bottom + 4 + height > innerHeight && r.top - 4 - height > 0 ? r.top - 4 - height : r.bottom + 4;
    host.style.top = `${top}px`;
    host.style.left = `${Math.max(4, Math.min(r.left, innerWidth - width - 4))}px`;
    host.style.width = `${width}px`;
  }

  async function openMenu(el, field) {
    if (anchor === el || opening === el) return;
    closeMenu();
    opening = el;
    const answer = await api.runtime.sendMessage({ cmd: "field", field }).catch(() => null);
    opening = null;
    if (!answer?.token || document.activeElement !== el) return;
    closeMenu();
    // A closed shadow root: the page can't reach the frame or style it.
    host = document.createElement("nyx-passwords-menu");
    const shadow = host.attachShadow({ mode: "closed" });
    host.style.cssText = "position:fixed;z-index:2147483647;height:0;display:block;margin:0;padding:0;";
    frame = document.createElement("iframe");
    frame.src = api.runtime.getURL(`menu.html#${answer.token}`);
    frame.style.cssText = "border:0;width:100%;height:220px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.3),0 1px 3px rgba(0,0,0,.2);background:transparent;color-scheme:normal;";
    frame.setAttribute("allowtransparency", "true");
    shadow.append(frame);
    (topLayer(el) ?? document.documentElement).append(host);
    anchor = el;
    // The fills in background.js keep to this field's form.
    globalThis.__nyxAnchor = el;
    place();
  }

  document.addEventListener(
    "focusin",
    (e) => {
      clearTimeout(closing);
      if (e.target === host) return;
      const field = kindOf(e.target);
      if (field && byUser() && !filling()) openMenu(e.target, field);
      else if (e.target !== anchor) closeMenu();
    },
    true,
  );
  document.addEventListener(
    "focusout",
    (e) => {
      if (e.target === anchor) closing = setTimeout(() => document.activeElement !== host && closeMenu(), 250);
    },
    true,
  );
  // A click in the field that already has the cursor (the page put it there, or the
  // menu was closed with Escape) opens the menu too.
  document.addEventListener(
    "click",
    (e) => {
      if (!e.isTrusted || e.target === anchor || e.target !== document.activeElement) return;
      const field = kindOf(e.target);
      if (field) openMenu(e.target, field);
    },
    true,
  );
  document.addEventListener("keydown", (e) => e.key === "Escape" && closeMenu(), true);
  // Scrolling the page or any panel inside it.
  document.addEventListener("scroll", place, { capture: true, passive: true });
  window.addEventListener("resize", place, { passive: true });

  // ---- the save bar ----

  let bar = null;
  let barFrame = null;
  function showBar(t) {
    bar?.remove();
    bar = document.createElement("nyx-passwords-bar");
    const shadow = bar.attachShadow({ mode: "closed" });
    bar.style.cssText = "position:fixed;top:12px;right:12px;z-index:2147483647;display:block;";
    barFrame = document.createElement("iframe");
    barFrame.src = api.runtime.getURL(`bar.html#${t}`);
    barFrame.style.cssText = "border:0;width:400px;height:152px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.3),0 1px 3px rgba(0,0,0,.2);background:transparent;";
    shadow.append(barFrame);
    (topLayer() ?? document.documentElement).append(bar);
    const mine = bar;
    setTimeout(() => {
      if (bar !== mine) return;
      bar.remove();
      bar = barFrame = null;
    }, 60000);
  }

  // ---- the passkey card ----

  // The page may restyle, cover or move the card: its style is put back, it goes back
  // where it was, and the background accepts an answer only while `cardOnTop()`.
  const CARD_CSS = [
    "position:fixed", "top:12px", "right:12px", "left:auto", "bottom:auto", "width:auto", "height:auto", "margin:0", "padding:0",
    "z-index:2147483647", "display:block", "opacity:1", "visibility:visible", "transform:none", "filter:none", "clip-path:none",
    "mask:none", "pointer-events:auto",
  ].map((d) => `${d} !important`).join(";");
  let card = null;
  let cardFrame = null;
  let cardStyle = "";
  let cardKeeper = null;

  function closeCard() {
    cardKeeper?.disconnect();
    card?.remove();
    card = cardFrame = cardKeeper = null;
  }

  function showCard(t) {
    closeCard();
    if (document.fullscreenElement) return false;
    card = document.createElement("nyx-passwords-passkey");
    const shadow = card.attachShadow({ mode: "closed" });
    cardFrame = document.createElement("iframe");
    cardFrame.src = api.runtime.getURL(`passkey.html#${t}`);
    cardFrame.style.cssText = "border:0;display:block;width:380px;height:180px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.3),0 1px 3px rgba(0,0,0,.2);background:transparent;color-scheme:normal;";
    cardFrame.setAttribute("allowtransparency", "true");
    cardFrame.addEventListener("load", () => cardFrame?.focus(), { once: true });
    shadow.append(cardFrame);
    card.style.cssText = CARD_CSS;
    cardStyle = card.style.cssText;
    (topLayer() ?? document.documentElement).append(card);
    cardKeeper = new MutationObserver(() => {
      if (!card) return;
      if (card.style.cssText !== cardStyle) card.style.cssText = CARD_CSS;
      if (!card.isConnected) (topLayer() ?? document.documentElement).append(card);
    });
    cardKeeper.observe(card, { attributes: true });
    cardKeeper.observe(document.documentElement, { childList: true, subtree: true });
    return true;
  }

  function cardOnTop() {
    if (!card?.isConnected || !cardFrame || card.style.cssText !== cardStyle) return false;
    for (let el = card; el; el = el.parentElement) {
      const s = getComputedStyle(el);
      if (Number(s.opacity) < 1 || s.visibility !== "visible" || s.filter !== "none") return false;
    }
    const r = cardFrame.getBoundingClientRect();
    if (r.width < 100 || r.height < 60) return false;
    const points = [[0.5, 0.5], [0.15, 0.2], [0.85, 0.2], [0.15, 0.8], [0.85, 0.8]];
    return points.every(([x, y]) => document.elementFromPoint(r.left + r.width * x, r.top + r.height * y) === card);
  }

  api.runtime.onMessage.addListener((message, sender, respond) => {
    if (message.cmd === "menu.close") closeMenu();
    if (window !== window.top) return;
    if (message.cmd === "bar") showBar(message.token);
    if (message.cmd === "passkey-card") respond(showCard(message.token));
    if (message.cmd === "passkey-check") respond(cardOnTop());
    if (message.cmd === "passkey-close") closeCard();
  });

  // The menu, the bar and the card close and size themselves (only their own frames:
  // a page's message comes from another window).
  window.addEventListener("message", (e) => {
    if (e.source === window) return;
    if (e.data?.nyx === "bar-close" && barFrame && e.source === barFrame.contentWindow) {
      bar?.remove();
      bar = barFrame = null;
    }
    if (e.data?.nyx === "menu-close" && frame && e.source === frame.contentWindow) closeMenu();
    if (e.data?.nyx === "menu-height" && frame && e.source === frame.contentWindow) {
      frame.style.height = `${Math.min(320, Math.max(48, Number(e.data.height) || 0))}px`;
      place();
    }
    if (cardFrame && e.source === cardFrame.contentWindow) {
      if (e.data?.nyx === "passkey-close") closeCard();
      if (e.data?.nyx === "passkey-height") cardFrame.style.height = `${Math.min(480, Math.max(80, Number(e.data.height) || 0))}px`;
    }
  });

  // ---- submitted logins ----

  // The login typed into a form, read as it's submitted. It goes to the background
  // script, which asks the app whether it's new or changed before offering to save.
  function capture(form) {
    const scope = form ?? document;
    const fields = [...scope.querySelectorAll("input")].filter(shown);
    const passwords = fields.filter((el) => el.type === "password" && el.value);
    if (!passwords.length) return captureUsernameStep(form, fields);
    // A change-password form: current, then new (and confirm). A sign-up's two are the same.
    const chosen = passwords.find((el) => el.autocomplete === "new-password") ?? passwords[passwords.length - 1];
    const current =
      passwords.find((el) => el.autocomplete === "current-password" && el !== chosen) ??
      (passwords.length >= 2 && passwords[0].value !== chosen.value ? passwords[0] : null);
    const before = fields.slice(0, fields.indexOf(passwords[0])).reverse();
    // Sites put a hidden username field beside a password step for password managers.
    const user =
      before.find((el) => /username|email/.test(el.autocomplete) && el.value) ??
      before.find((el) => textLike(el) && el.value) ??
      [...scope.querySelectorAll('input[autocomplete~="username"]')].find((el) => el.type !== "password" && el.value);
    api.runtime
      .sendMessage({ cmd: "submitted", username: user?.value ?? "", password: chosen.value, current: current?.value ?? "", change: Boolean(current) })
      .catch(() => {});
  }

  // A sign-in's first step: its username, for the password step on the next page.
  function captureUsernameStep(form, fields) {
    if (!form || !signInStep(form)) return;
    const user =
      fields.find((el) => /username|email/.test(el.autocomplete) && el.value) ??
      fields.find((el) => textLike(el) && el.value && /user|login|e.?mail|account/.test(text(el)));
    if (user) api.runtime.sendMessage({ cmd: "username-step", username: user.value }).catch(() => {});
  }

  document.addEventListener("submit", (e) => capture(e.target), true);
  // Enter in a sign-in field, where the page signs in without a form submit.
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key !== "Enter" || !(e.target instanceof HTMLInputElement)) return;
      if (e.target.type === "password" || kindOf(e.target) === "login") capture(e.target.form);
    },
    true,
  );
  document.addEventListener(
    "click",
    (e) => {
      const button = e.target.closest?.('a, button, input[type="submit"], [role="button"]');
      if (!button) return;
      const label = `${button.textContent} ${button.value ?? ""} ${button.getAttribute("aria-label") ?? ""}`;
      if (button.tagName !== "A" && /log.?in|sign.?(in|up)|register|create|continue|next|submit|save/i.test(label)) {
        capture(button.closest("form"));
      }
      // Universal sign-on: "Sign in with Google" and the like.
      const href = button.href ?? button.closest("a")?.href ?? "";
      const providers = {
        google: /google/i, apple: /apple/i, microsoft: /microsoft|outlook/i, github: /github/i, facebook: /facebook/i,
        gitlab: /gitlab/i, twitter: /twitter/i, linkedin: /linkedin/i, amazon: /amazon/i, slack: /slack/i,
      };
      const domains = {
        google: /accounts\.google\.com/, apple: /appleid\.apple\.com/, microsoft: /login\.(microsoftonline|live)\.com/,
        github: /github\.com\/login\/oauth/, facebook: /facebook\.com\/.*oauth/, gitlab: /gitlab\.com\/oauth/,
      };
      for (const [name, word] of Object.entries(providers)) {
        if ((word.test(label) && /sign|log|continue|with/i.test(label)) || domains[name]?.test(href)) {
          api.runtime.sendMessage({ cmd: "provider", provider: name }).catch(() => {});
          break;
        }
      }
    },
    true,
  );

  // ---- filling as the page loads ----

  // Once per address, when a login form shows (as the page loads, or drawn later by its
  // scripts); the background and the app decide whether to fill, and only empty fields.
  let askedFor = "";
  function maybeFillOnLoad() {
    if (askedFor === location.href) return;
    const password = [...document.querySelectorAll('input[type="password"]')].find(visible);
    if (!password || kindOf(password) !== "login") return;
    askedFor = location.href;
    api.runtime.sendMessage({ cmd: "loaded" }).catch(() => {});
  }
  if (document.readyState === "complete") maybeFillOnLoad();
  else window.addEventListener("load", maybeFillOnLoad, { once: true });
  let watchTimer = null;
  new MutationObserver(() => {
    watchTimer ??= setTimeout(() => {
      watchTimer = null;
      maybeFillOnLoad();
    }, 500);
  }).observe(document.documentElement, { childList: true, subtree: true });

  // ---- passkeys, relayed from the page script ----

  window.addEventListener("message", async (e) => {
    if (e.source !== window || e.data?.nyx !== "webauthn" || !e.data.id) return;
    const { id, kind, options } = e.data;
    // page.js uses the browser's own when nothing here answers (this script loads after it).
    window.postMessage({ nyx: "webauthn-ack", id }, location.origin);
    const answer = await api.runtime.sendMessage({ cmd: "passkey", kind, options }).catch(() => ({ fallback: true }));
    window.postMessage({ nyx: "webauthn-reply", id, answer: answer ?? { fallback: true } }, location.origin);
  });
})();
