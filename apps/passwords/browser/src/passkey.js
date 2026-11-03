// Confirming a passkey on this extension's own card over the page (or, where the page
// can't show it, in a small window). Signing in: pick the account, or with one account
// let the countdown run. Making one: keep it on a login for the site, or a new one.

const { api, el, icon, tile } = NYX;
const token = location.hash.slice(1);
const $ = (id) => document.getElementById(id);
const AUTO_MS = 2000;
// A page could time a click for when the card appears: input that early doesn't count.
const SETTLE_MS = 400;
let shownAt = Infinity;
let inWindow = false;
let answered = false;
let countdown = null;

const close = () => (inWindow ? window.close() : parent.postMessage({ nyx: "passkey-close" }, "*"));
const fit = () => !inWindow && parent.postMessage({ nyx: "passkey-height", height: document.body.scrollHeight + 2 }, "*");

async function answer(choice, byUser = true) {
  if (answered || (byUser && Date.now() - shownAt < SETTLE_MS)) return;
  answered = true;
  clearTimeout(countdown);
  await api.runtime.sendMessage({ cmd: "passkey.answer", token, choice }).catch(() => {});
  close();
}

function row(lead, title, sub, choice) {
  const r = el("div", { class: "row", tabindex: "0" }, lead, el("div", { class: "text" }, el("div", { class: "title" }, title), el("div", { class: "sub" }, sub)));
  r.addEventListener("click", () => answer(choice));
  r.addEventListener("keydown", (e) => {
    if (e.key === "Enter") answer(choice);
    if (e.key === "ArrowDown") r.nextElementSibling?.focus();
    if (e.key === "ArrowUp") r.previousElementSibling?.focus();
  });
  $("choices").append(r);
}

function button(label, onclick, cls = "") {
  $("buttons").append(el("button", { class: cls, onclick }, label));
}

(async () => {
  $("mark").append(icon("passkey", 11));
  $("close").append(icon("close", 14));
  const s = await api.runtime.sendMessage({ cmd: "passkey.state", token }).catch(() => null);
  if (!s) return close();
  inWindow = s.inWindow;
  document.body.classList.toggle("window", inWindow);
  const site = s.host.replace(/^www\./, "");
  const title = $("title");
  const detail = $("detail");

  if (s.ask === "done") {
    // Nyx Biometrics confirmed it; this only says so.
    title.textContent = `Signed in to ${site}`;
    detail.textContent = s.user ? `With a passkey, as ${s.user}` : "With a passkey";
    $("close").addEventListener("click", () => answer(false, false));
    fit();
    setTimeout(() => answer(false, false), 2500);
    return;
  }

  $("close").addEventListener("click", () => answer(false));
  document.addEventListener("keydown", (e) => e.key === "Escape" && answer(false));
  if (s.ask === "get") {
    title.textContent = `Sign in to ${site}`;
    s.choices.forEach((c, index) => row(tile({ name: c.user_name || c.name, host: site }, 30), c.user_name || c.name, c.name, { index }));
    if (s.auto) {
      const who = s.choices[0].user_name || s.choices[0].name;
      detail.textContent = `With a passkey, as ${who}…`;
      const bar = el("div", { class: "countdown", style: `--wait:${AUTO_MS}ms` }, el("span"));
      $("timer").append(bar);
      countdown = setTimeout(() => answer({ index: 0 }, false), AUTO_MS);
    } else {
      detail.textContent = s.choices.length > 1 ? "With a passkey. Pick the account:" : "With a passkey:";
    }
  } else {
    title.textContent = `Save a passkey for ${site}`;
    detail.textContent = s.user ? `For ${s.user}. Keep it on:` : "Keep it on:";
    row(el("span", { class: "tile kind", style: "--size:30px" }, icon("plus", 15)), "A new login", s.rpId, { into: null, index: 0 });
    s.choices.forEach((c) => row(tile({ name: c.name, host: site }, 30), c.name, c.user_name || "No username", { into: c.id, index: 0 }));
  }
  button("Use the browser's own", () => answer(null), "ghost left");
  button("Cancel", () => answer(false));
  fit();
  shownAt = Date.now();
  $("choices").querySelector(".row")?.focus();
})();
