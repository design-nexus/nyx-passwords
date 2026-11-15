// Table-driven checks for field-kind.js (no network, no extra packages).
//
//   node apps/passwords/browser/test/field-kind.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, "../src/field-kind.js"), "utf8");

// ---- minimal DOM ----

class FakeInput {
  constructor(attrs = {}, doc) {
    this.localName = "input";
    this.tagName = "INPUT";
    this.nodeType = 1;
    this.name = attrs.name ?? "";
    this.id = attrs.id ?? "";
    this.type = attrs.type ?? "text";
    this.autocomplete = attrs.autocomplete ?? "";
    this.placeholder = attrs.placeholder ?? "";
    this.maxLength = attrs.maxLength != null ? Number(attrs.maxLength) : -1;
    this.disabled = false;
    this.readOnly = false;
    this.value = "";
    this.ownerDocument = doc;
    this.parentElement = null;
    this.form = null;
    this._attrs = { ...attrs };
    this._labelText = attrs.label ?? "";
    this.shadowRoot = null;
  }
  get labels() {
    return this._labelText ? [{ textContent: this._labelText }] : [];
  }
  getAttribute(name) {
    if (name === "aria-label") return this._attrs["aria-label"] ?? null;
    if (name === "inputmode") return this._attrs.inputmode ?? null;
    if (name === "role") return this._attrs.role ?? null;
    if (name === "aria-modal") return this._attrs["aria-modal"] ?? null;
    return this._attrs[name] ?? null;
  }
  getBoundingClientRect() {
    return { width: 120, height: 24, top: 0, left: 0, bottom: 24, right: 120 };
  }
  checkVisibility() {
    return true;
  }
  matches(sel) {
    if (sel.includes("dialog:modal")) return this.localName === "dialog" && this._attrs.open != null;
    return false;
  }
}

class FakeNode {
  constructor(localName, attrs = {}, doc) {
    this.localName = localName;
    this.tagName = localName.toUpperCase();
    this.nodeType = 1;
    this.ownerDocument = doc;
    this.parentElement = null;
    this.children = [];
    this._attrs = attrs;
    this.textContent = attrs.textContent ?? "";
    this.value = attrs.value ?? "";
    this.shadowRoot = null;
    this.form = null;
  }
  getAttribute(name) {
    return this._attrs[name] ?? null;
  }
  matches(sel) {
    try {
      if (sel.includes("dialog:modal")) return this.localName === "dialog" && "open" in this._attrs;
      if (sel.includes(":popover-open")) return this._attrs.popover != null && this._attrs.open != null;
    } catch {}
    return false;
  }
  querySelectorAll(sel) {
    const out = [];
    const walk = (node) => {
      for (const c of node.children ?? []) {
        if (match(c, sel)) out.push(c);
        walk(c);
      }
    };
    walk(this);
    return out;
  }
  querySelector(sel) {
    return this.querySelectorAll(sel)[0] ?? null;
  }
}

function match(el, sel) {
  if (sel === "input") return el.localName === "input";
  if (sel === "*") return true;
  if (sel === "select") return el.localName === "select";
  if (sel.startsWith("#")) return el.id === sel.slice(1);
  if (sel.includes(",")) return sel.split(",").some((s) => match(el, s.trim()));
  if (sel === 'button, input[type="submit"], [role="button"], a') {
    return el.localName === "button" || el.localName === "a" || (el.localName === "input" && el.type === "submit") || el.getAttribute?.("role") === "button";
  }
  return false;
}

function parseAttrs(raw) {
  const attrs = {};
  const re = /([:@\w-]+)(?:=(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m;
  while ((m = re.exec(raw))) {
    attrs[m[1]] = m[2] ?? m[3] ?? m[4] ?? "";
  }
  return attrs;
}

function build(html) {
  const doc = {
    nodeType: 9,
    localName: "#document",
    ownerDocument: null,
    parentElement: null,
    children: [],
    body: null,
    querySelectorAll(sel) {
      return this.documentElement.querySelectorAll(sel);
    },
    querySelector(sel) {
      return this.querySelectorAll(sel)[0] ?? null;
    },
  };
  doc.ownerDocument = null;
  const root = new FakeNode("html", {}, doc);
  const body = new FakeNode("body", {}, doc);
  root.children.push(body);
  body.parentElement = root;
  doc.documentElement = root;
  doc.body = body;
  doc.children = [root];

  const stack = [body];
  const tokens = html.replace(/\n/g, " ").match(/<\/?[^>]+>|[^<]+/g) ?? [];
  for (const tok of tokens) {
    if (/^<\/\w/.test(tok)) {
      stack.pop();
      continue;
    }
    if (/^</.test(tok) && !tok.startsWith("</")) {
      const m = tok.match(/^<([\w-]+)([^>]*)\/?>$/);
      if (!m) continue;
      const [, name, attrRaw] = m;
      const attrs = parseAttrs(attrRaw);
      const parent = stack[stack.length - 1];
      let el;
      if (name === "input") {
        el = new FakeInput(
          {
            ...attrs,
            maxLength: attrs.maxlength ?? attrs.maxLength,
          },
          doc,
        );
        // Inherit label text from a wrapping <label>.
        for (let p = parent; p; p = p.parentElement) {
          if (p.localName === "label" && p.textContent) {
            el._labelText = (el._labelText + " " + p.textContent).trim();
            break;
          }
        }
      } else {
        el = new FakeNode(name, attrs, doc);
      }
      el.parentElement = parent;
      parent.children.push(el);
      // form association
      if (el.localName === "input") {
        for (let p = parent; p; p = p.parentElement) {
          if (p.localName === "form") {
            el.form = p;
            break;
          }
        }
      }
      if (!tok.endsWith("/>") && name !== "input") stack.push(el);
      continue;
    }
    // text
    const parent = stack[stack.length - 1];
    if (parent) parent.textContent += tok.trim() ? tok : "";
  }
  return doc;
}

function loadKind() {
  const sandbox = vm.createContext({ console });
  sandbox.globalThis = sandbox;
  sandbox.HTMLInputElement = FakeInput;
  vm.runInContext(src, sandbox, { filename: "field-kind.js" });
  return sandbox.NyxFieldKind;
}

/** Same rules as field-kind.js kindOf, without cross-realm instanceof. */
function classify(K, el) {
  if (el?.localName !== "input" || !K.visible(el)) return null;
  const ac = (el.autocomplete || "").toLowerCase();
  const t = K.describe(el);
  if (ac.includes("one-time-code") || /(^|[^a-z])(otp|totp|2fa|mfa)|one.?time|verification.?code|auth.?code/.test(t)) return "otp";
  const scope = K.scopeOf(el);
  if (K.ccAutocomplete(ac) || K.CARD_WORDS.test(t) || K.paymentKeypad(el, scope)) return "card";
  if (el.type === "password") {
    const passwords = K.deepInputs(scope).filter((i) => i.type === "password" && K.visible(i));
    return ac.includes("new-password") || passwords.length > 1 || /new|confirm|repeat|create/.test(t) ? "new-password" : "login";
  }
  if (K.textLike(el)) {
    if (ac.includes("username") || ac === "webauthn") return "login";
    const usernameCue = /\bemail\b/.test(ac) || ac.includes("username") || K.USERNAME_WORDS.test(t) || el.type === "email";
    if (usernameCue) {
      const near = K.deepInputs(scope).some((i) => i.type === "password" && K.visible(i));
      if (near || K.signInStep(scope)) return "login";
    }
    if (/given-name|family-name|street-address|address-line|postal-code|country/.test(ac) || /first.?name|last.?name|address|postal|zip|city/.test(t)) {
      return "identity";
    }
    if (/\btel\b/.test(ac) || (el.type === "tel" && /phone|mobile|tel/.test(t))) return "identity";
  }
  return null;
}

const cases = [
  ["cc-number autocomplete", `<form><input id="n" autocomplete="cc-number"></form>`, "#n", "card"],
  ["tel card label", `<label>Card number <input id="n" type="tel"></label>`, "#n", "card"],
  ["name=pan", `<form><input id="n" name="pan"></form>`, "#n", "card"],
  ["securityCode CVV", `<form><input id="n" name="securityCode" autocomplete="cc-csc"></form>`, "#n", "card"],
  [
    "card in dialog with page login",
    `<form id="login"><input name="user" autocomplete="username"><input type="password"></form>
     <dialog open id="pay"><label>Card number <input id="n" type="tel" maxlength="19"></label>
     <input name="cvc" placeholder="CVC" maxlength="4"></dialog>`,
    "#n",
    "card",
  ],
  ["username near password", `<form><input id="u" name="username" autocomplete="username"><input type="password"></form>`, "#u", "login"],
  ["email near password", `<form><input id="u" type="email" autocomplete="email"><input type="password"></form>`, "#u", "login"],
  ["phone identity alone", `<form><input id="p" type="tel" name="phone" autocomplete="tel"></form>`, "#p", "identity"],
  ["otp field", `<form><input id="o" autocomplete="one-time-code"></form>`, "#o", "otp"],
  ["section billing cc", `<form><input id="n" autocomplete="section-billing cc-number"></form>`, "#n", "card"],
  [
    "email in checkout dialog not login",
    `<form id="login"><input type="password"></form>
     <dialog open><input id="e" type="email" name="receipt" autocomplete="email"><input id="n" autocomplete="cc-number"></dialog>`,
    "#e",
    null,
  ],
];

const K = loadKind();
for (const [name, html, sel, want] of cases) {
  try {
    const document = build(html);
    const el = document.querySelector(sel);
    if (!el) throw new Error(`no ${sel}`);
    const got = classify(K, el);
    if (got !== want) {
      console.error(`FAIL ${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
      process.exitCode = 1;
    } else {
      console.log(`ok ${name}`);
    }
  } catch (e) {
    console.error(`FAIL ${name}: ${e.message}`);
    process.exitCode = 1;
  }
}

if (!process.exitCode) console.log("All field-kind checks passed.");
