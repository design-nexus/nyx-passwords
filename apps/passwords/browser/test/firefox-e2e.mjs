// The extension in a real, headless Firefox, against a scratch Passwords daemon (run by
// the `firefox_extension` test in apps/passwords/tests/daemon.rs, which sets up the
// daemon, the account and the native host, and confirms the pairing). Pages come from a
// local https server; Firefox is driven over WebDriver BiDi. No window is ever shown.
//
// Environment: NYX_E2E_EXT (the unpacked extension), NYX_E2E_PROFILE, NYX_E2E_PORT,
// NYX_E2E_CERT and NYX_E2E_KEY (for 127.0.0.1), NYX_E2E_CARD_ID.
// Prints `E2E {json}` with what it found; exits non-zero on failure.

import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import https from "node:https";

const env = process.env;
const PORT = Number(env.NYX_E2E_PORT);
const UUID = "5d8c43c2-0f37-4f5b-9e0f-0b5d3a6f1e2a";
const EXT_ID = "nyx-passwords@design-nexus.github.io";
const origin = `https://127.0.0.1:${PORT}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = {};

// ---- the pages ----

const pages = {
  "/login": `<form id="f" action="/done"><input id="user" name="username" autocomplete="username"><input id="pass" type="password" name="password"><button>Sign in</button></form>`,
  "/signup": `<form id="f" action="/done" method="get"><input id="email" type="email" name="email" autocomplete="email"><input id="p1" type="password" autocomplete="new-password"><input id="p2" type="password" autocomplete="new-password"><button id="go">Create account</button></form>`,
  "/checkout": `<form><input id="ccname" autocomplete="cc-name"><input id="ccnum" autocomplete="cc-number"><input id="cvc" autocomplete="cc-csc"></form>`,
  "/step1": `<form action="/step2"><input id="who" name="username" autocomplete="username"><button id="next">Next</button></form>`,
  "/step2": `<form action="/done"><input id="pw" type="password" autocomplete="current-password"><button id="in">Sign in</button></form>`,
  "/change": `<form action="/done"><input id="cur" type="password" autocomplete="current-password"><input id="n1" type="password" autocomplete="new-password"><input id="n2" type="password" autocomplete="new-password"><button id="save">Save</button></form>`,
  "/done": `<p>Signed in.</p>`,
  "/social": `<p>Welcome</p><a id="google" href="/social-back?code=1">Sign in with Google</a><form><input id="who" autocomplete="username"><input type="password" id="pw"></form>`,
  "/social-back": `<p>Signed in with Google.</p>`,
  "/webauthn": `<script>
    const b = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
    window.result = {};
    window.makeKey = async () => {
      const c = await navigator.credentials.create({ publicKey: {
        rp: { id: "127.0.0.1", name: "Local" }, user: { id: b("user-1"), name: "octo", displayName: "Octo" },
        challenge: b("challenge-1"), pubKeyCredParams: [{ type: "public-key", alg: -7 }] } });
      window.result.made = { type: c.type, id: c.id, raw: c.rawId.byteLength, attestation: c.response.attestationObject.byteLength,
        client: JSON.parse(new TextDecoder().decode(c.response.clientDataJSON)), isCredential: c instanceof PublicKeyCredential };
    };
    window.useKey = async () => {
      const c = await navigator.credentials.get({ publicKey: { challenge: b("challenge-2"), rpId: "127.0.0.1" } });
      window.result.used = { id: c.id, signature: c.response.signature.byteLength, data: c.response.authenticatorData.byteLength,
        user: new TextDecoder().decode(c.response.userHandle), client: JSON.parse(new TextDecoder().decode(c.response.clientDataJSON)) };
    };
  </script>`,
};
const server = https.createServer({ cert: readFileSync(env.NYX_E2E_CERT), key: readFileSync(env.NYX_E2E_KEY) }, (req, res) => {
  const page = pages[req.url.split("?")[0]];
  res.writeHead(page ? 200 : 404, { "content-type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><html><body>${page ?? "not found"}</body></html>`);
});
await new Promise((r) => server.listen(PORT, "127.0.0.1", r));

// ---- Firefox ----

mkdirSync(env.NYX_E2E_PROFILE, { recursive: true });
writeFileSync(
  `${env.NYX_E2E_PROFILE}/user.js`,
  [
    `user_pref("extensions.webextensions.uuids", ${JSON.stringify(JSON.stringify({ [EXT_ID]: UUID }))});`,
    `user_pref("browser.shell.checkDefaultBrowser", false);`,
    `user_pref("datareporting.policy.dataSubmissionEnabled", false);`,
    `user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);`,
    `user_pref("browser.startup.homepage_override.mstone", "ignore");`,
    `user_pref("signon.rememberSignons", false);`,
  ].join("\n"),
);
const debugPort = PORT + 1;
const firefox = spawn("firefox", ["--headless", "--no-remote", "--profile", env.NYX_E2E_PROFILE, "--remote-debugging-port", String(debugPort), "-remote-allow-system-access"], {
  env: { ...env, MOZ_HEADLESS: "1" },
  stdio: ["ignore", "ignore", "pipe"],
});
let ready;
const listening = new Promise((r) => (ready = r));
firefox.stderr.on("data", (d) => /WebDriver BiDi listening/.test(String(d)) && ready());
await Promise.race([listening, sleep(30000)]);

const ws = new WebSocket(`ws://127.0.0.1:${debugPort}/session`);
await new Promise((r, e) => {
  ws.onopen = r;
  ws.onerror = e;
});
let nextId = 1;
const pending = new Map();
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
  }
};
function bidi(method, params = {}) {
  const id = nextId++;
  ws.send(JSON.stringify({ id, method, params }));
  return new Promise((resolve, reject) =>
    pending.set(id, (msg) => (msg.error ? reject(new Error(`${method}: ${msg.error} ${msg.message}`)) : resolve(msg.result))),
  );
}
/// Evaluates in a context; the value comes back as JSON (BiDi's own serialization of
/// objects is a tree of typed entries).
async function run(context, expression) {
  const wrapped = `(async () => JSON.stringify(await (${expression})) ?? "null")()`;
  const r = await bidi("script.evaluate", { expression: wrapped, target: { context }, awaitPromise: true, resultOwnership: "none" });
  if (r.type === "exception") throw new Error(`${expression}: ${r.exceptionDetails.text}`);
  return JSON.parse(r.result.value);
}
async function contexts() {
  const tree = await bidi("browsingContext.getTree", {});
  const all = [];
  const walk = (list, top) => list.forEach((c) => (all.push({ ...c, top }), walk(c.children ?? [], false)));
  walk(tree.contexts, true);
  return all;
}
const extPage = (page) => async () => (await contexts()).find((c) => c.url.startsWith(`moz-extension://${UUID}/${page}`));
const setValues = (pairs) =>
  `(() => { const s = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    for (const [sel, v] of ${JSON.stringify(pairs)}) s.call(document.querySelector(sel), v); })()`;
async function waitFor(what, test, ms = 15000) {
  const until = Date.now() + ms;
  for (;;) {
    const found = await test();
    if (found) return found;
    if (Date.now() > until) throw new Error(`timed out waiting for ${what}`);
    await sleep(300);
  }
}
async function clickIn(context, selector) {
  const node = await bidi("script.evaluate", { expression: `document.querySelector(${JSON.stringify(selector)})`, target: { context }, awaitPromise: false });
  await bidi("input.performActions", {
    context,
    actions: [{ type: "pointer", id: "mouse", actions: [{ type: "pointerMove", x: 4, y: 4, origin: { type: "element", element: node.result } }, { type: "pointerDown", button: 0 }, { type: "pointerUp", button: 0 }] }],
  });
}

let failed = null;
try {
  await bidi("session.new", { capabilities: { alwaysMatch: { acceptInsecureCerts: true } } });
  const installed = await bidi("webExtension.install", { extensionData: { type: "path", path: env.NYX_E2E_EXT } });
  results.installed = installed.extension;
  // Pairing, from the welcome tab the extension opens when installed (the test confirms
  // it on the daemon's side).
  const welcome = await waitFor("the welcome tab", async () => (await contexts()).find((c) => c.url.startsWith(`moz-extension://${UUID}/popup.html`)));
  const popup = welcome.context;
  const paired = await run(popup, `browser.runtime.sendMessage({ cmd: "pair" })`);
  results.pairing = paired.state;
  console.log(`PAIRING ${paired.code}`);
  await waitFor("pairing confirmed", async () => (await run(popup, `browser.runtime.sendMessage({ cmd: "status" })`)).state === "unlocked", 30000);
  await run(popup, `browser.runtime.sendMessage({ cmd: "set", key: "passkeys", value: true })`);
  results.search = (await run(popup, `browser.runtime.sendMessage({ cmd: "search", q: "local" })`)).items?.map((i) => i.name);
  const { context: tab } = await bidi("browsingContext.create", { type: "tab" });

  // Filling as the page loads.
  await bidi("browsingContext.navigate", { context: tab, url: `${origin}/login`, wait: "complete" });
  results.fillOnLoad = await waitFor("the login filled on load", async () => {
    const v = await run(tab, `({ user: document.querySelector("#user").value, pass: document.querySelector("#pass").value })`);
    return v.pass ? v : null;
  });

  // Picking the login from the menu fills it, and leaves no menu open.
  await clickIn(tab, "#user");
  const loginMenu = await waitFor("the login menu", extPage("menu.html"));
  await waitFor("its login", async () => run(loginMenu.context, `document.querySelectorAll(".row").length`));
  await clickIn(loginMenu.context, ".row");
  await sleep(1500);
  results.menuAfterPick = Boolean(await extPage("menu.html")());

  // Signing in with what was filled: nothing to save.
  await clickIn(tab, "#f button");
  await sleep(4000);
  results.barAfterFill = Boolean(await extPage("bar.html")());

  // A sign-in in two steps: the username, then the password on its own page.
  await bidi("browsingContext.navigate", { context: tab, url: `${origin}/step1`, wait: "complete" });
  await run(tab, setValues([["#who", "octo"]]));
  await clickIn(tab, "#next");
  await waitFor("the password step", async () => (await run(tab, `location.pathname`)) === "/step2");
  await sleep(800);
  await run(tab, setValues([["#pw", "canary-local-Pw!9"]]));
  await clickIn(tab, "#in");
  await sleep(4000);
  results.barAfterTwoSteps = Boolean(await extPage("bar.html")());

  // A change-password form: the bar offers to update the login with the new password.
  await bidi("browsingContext.navigate", { context: tab, url: `${origin}/change`, wait: "complete" });
  await run(tab, setValues([["#cur", "canary-local-Pw!9"], ["#n1", "canary-changed-Pw!9"], ["#n2", "canary-changed-Pw!9"]]));
  await clickIn(tab, "#save");
  const changeBar = await waitFor("the update bar", extPage("bar.html"));
  results.changeQuestion = await waitFor("its question", async () => run(changeBar.context, `document.querySelector("#question").textContent`));
  await clickIn(changeBar.context, "button.ghost");
  await sleep(500);

  // The menu under a card field: pick the card.
  await bidi("browsingContext.navigate", { context: tab, url: `${origin}/checkout`, wait: "complete" });
  await clickIn(tab, "#ccnum");
  const menu = await waitFor("the menu", async () => (await contexts()).find((c) => c.url.startsWith(`moz-extension://${UUID}/menu.html`)));
  await waitFor("the menu's card", async () => run(menu.context, `document.querySelectorAll(".row").length`));
  results.menuRows = await run(menu.context, `[...document.querySelectorAll(".row .title")].map((t) => t.textContent)`);
  await clickIn(menu.context, ".row");
  results.cardFill = await waitFor("the card filled", async () => {
    const v = await run(tab, `({ name: document.querySelector("#ccname").value, number: document.querySelector("#ccnum").value, cvc: document.querySelector("#cvc").value })`);
    return v.number ? v : null;
  });

  // Signing up: the bar offers to save the new login; save it.
  await bidi("browsingContext.navigate", { context: tab, url: `${origin}/signup`, wait: "complete" });
  await run(tab, setValues([["#email", "new@example.com"], ["#p1", "canary-signup-Pw!9"], ["#p2", "canary-signup-Pw!9"]]));
  await clickIn(tab, "#go");
  const bar = await waitFor("the save bar", async () => (await contexts()).find((c) => c.url.startsWith(`moz-extension://${UUID}/bar.html`)));
  await waitFor("the bar's question", async () => run(bar.context, `document.querySelector("#question").textContent`));
  results.barQuestion = await run(bar.context, `document.querySelector("#question").textContent`);
  await clickIn(bar.context, "button.primary");
  await sleep(1500);

  // Universal sign-on: "Sign in with Google", then back on the site: remember it; the
  // site's menu then offers it.
  await bidi("browsingContext.navigate", { context: tab, url: `${origin}/social`, wait: "complete" });
  await clickIn(tab, "#google");
  const remember = await waitFor("the remember bar", async () => {
    for (const c of await contexts()) {
      if (c.url.startsWith(`moz-extension://${UUID}/bar.html`) && (await run(c.context, `document.querySelector("#question").textContent`))?.includes("Google")) return c;
    }
    return null;
  });
  results.rememberQuestion = await run(remember.context, `document.querySelector("#question").textContent`);
  await clickIn(remember.context, "button.primary");
  await sleep(1500);
  await bidi("browsingContext.navigate", { context: tab, url: `${origin}/social`, wait: "complete" });
  await clickIn(tab, "#who");
  const socialMenu = await waitFor("the sign-in menu", async () => (await contexts()).find((c) => c.url.startsWith(`moz-extension://${UUID}/menu.html`)));
  results.socialMenu = await waitFor("the menu's rows", async () => {
    const rows = await run(socialMenu.context, `[...document.querySelectorAll(".row .title")].map((t) => t.textContent)`);
    return rows.length ? rows : null;
  });

  // Passkeys, on the card over the page (no window): make one (saved on a new login),
  // then sign in with it, the only one, after the card's countdown.
  await bidi("browsingContext.navigate", { context: tab, url: `${origin}/webauthn`, wait: "complete" });
  const making = run(tab, `window.makeKey().then(() => "ok", (e) => String(e))`);
  const makeCard = await waitFor("the passkey card", extPage("passkey.html"));
  results.passkeyCardInPage = !makeCard.top;
  await waitFor("its choices", async () => run(makeCard.context, `document.querySelectorAll("#choices .row").length`));
  await sleep(600);
  await run(makeCard.context, `document.querySelector("#choices .row").click()`);
  results.makeKey = await making;
  const using = run(tab, `window.useKey().then(() => "ok", (e) => String(e))`);
  const useCard = await waitFor("the sign-in card", extPage("passkey.html"));
  results.useCountdown = await waitFor("its countdown", async () => run(useCard.context, `Boolean(document.querySelector(".countdown"))`));
  results.useKey = await using;
  results.passkeyWindow = (await contexts()).some((c) => c.top && c.url.includes("/passkey.html"));
  results.webauthn = await run(tab, `window.result`);
} catch (e) {
  failed = String(e?.stack ?? e);
}
console.log(`E2E ${JSON.stringify({ ...results, failed })}`);
ws.close();
firefox.kill("SIGTERM");
server.close();
process.exit(failed ? 1 : 0);
