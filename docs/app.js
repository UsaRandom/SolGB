if (!globalThis.SolCodec) throw new Error("This page did not start.");
const {
  assembleSigBlob,
  b58encode,
  buildSignedTx,
  bytesToBase64,
  decodeAddress,
  encodeString,
  extractPayment,
  formatSol,
  parseSigPage,
  solToLamports,
} = globalThis.SolCodec;

function savedText(key) {
  try { return localStorage.getItem(key) || ""; }
  catch { return ""; }
}

function storeText(key, value) {
  try { localStorage.setItem(key, value); }
  catch { /* a private window has no storage */ }
}

const screen = document.getElementById("screen");
const backBtn = document.getElementById("back");
const dotsEl = document.getElementById("dots");

const state = {
  step: "home",
  scanFor: "wallet",
  scanError: "",
  formError: "",
  wallet: null,
  dest: null,
  destText: "",
  nonceText: savedText("solgb.nonce"),
  amountText: "",
  amountFromCode: false,
  balance: null,
  lookup: "idle",
  lookupGen: 0,
  plan: null,
  result: null,
  page: 0,
  draft: "",
  sigParts: [],
  sigCount: 0,
  txB64: "",
  txSig: "",
  sendError: "",
};

let scanGen = 0;
let sendGen = 0;
let stream = null;
let cameraAsked = false;
let idleCam = false;

function h(tag, props, children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props || {})) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), value);
    } else if (value === true) node.setAttribute(key, "");
    else if (value !== false && value != null) node.setAttribute(key, String(value));
  }
  for (const child of children || []) {
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function friendlySol(lamports) {
  const raw = formatSol(lamports);
  const neg = raw.startsWith("-");
  const body = neg ? raw.slice(1) : raw;
  const [whole, frac] = body.split(".");
  const trimmed = frac.replace(/0+$/, "");
  return (neg ? "-" : "") + (trimmed ? whole + "." + trimmed : whole);
}

function spaced(text) {
  return (text.match(/.{1,4}/g) || [text]).join(" ");
}

function stepIndex() {
  if (state.step === "pay") return 1;
  if (state.step === "review") return 2;
  if (state.step === "type" || state.step === "send" || state.step === "sent") return 3;
  if (state.step === "scan" && state.scanFor === "signed") return 3;
  return 0;
}

function stopCamera() {
  scanGen += 1;
  if (stream) {
    for (const track of stream.getTracks()) track.stop();
    stream = null;
  }
  const cam = document.getElementById("cam");
  if (cam) cam.srcObject = null;
}

function go(step) {
  state.formError = "";
  state.scanError = "";
  state.step = step;
  render();
}

function rememberPay() {
  const dest = document.getElementById("dest");
  const amount = document.getElementById("amount");
  const nonce = document.getElementById("nonce");
  if (dest) state.destText = dest.value;
  if (amount) state.amountText = amount.value;
  if (nonce) {
    state.nonceText = nonce.value;
    storeText("solgb.nonce", nonce.value);
  }
}

function hexEq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function parseJsonBig(text) {
  const safe = text.replace(/([:[,]\s*)(-?\d{15,})(?=\s*[,}\]])/g, '$1"$2"');
  return JSON.parse(safe);
}

function asBig(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "string") return BigInt(v);
  if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
  throw new Error("A coin value was too large to read.");
}

async function rpc(method, params) {
  const res = await fetch("https://api.mainnet-beta.solana.com", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error("lookup failed");
  const data = parseJsonBig(text);
  if (data.error) throw new Error(data.error.message || "lookup failed");
  return data.result;
}

async function lookup() {
  const gen = ++state.lookupGen;
  state.lookup = "loading";
  state.balance = null;
  if (state.step === "found" || state.step === "pay") render();
  try {
    const got = await rpc("getBalance", [state.wallet.text]);
    if (gen !== state.lookupGen) return;
    state.balance = asBig(got.value);
    state.lookup = "done";
  } catch {
    if (gen !== state.lookupGen) return;
    state.lookup = "error";
  }
  if (state.step === "found" || state.step === "pay") {
    rememberPay();
    render();
  }
}

async function readCode(raw, typed) {
  if (!String(raw).trim()) {
    return { error: typed ? "Type the whole address." : "That code is not a Solana address." };
  }
  let parsed;
  try { parsed = extractPayment(raw); }
  catch { return { error: typed ? "That address does not look right." : "That code is not a Solana address." }; }
  try {
    const decoded = await decodeAddress(parsed.address);
    return { decoded, amount: parsed.amount };
  } catch {
    return {
      error: typed
        ? "That address does not look right. Check it and try again."
        : "That did not read cleanly. Hold steady and try again.",
    };
  }
}

async function useWallet(raw, typed) {
  const found = await readCode(raw, typed);
  if (found.error) return found.error;
  state.wallet = found.decoded;
  state.balance = null;
  state.lookup = "loading";
  state.step = "found";
  state.formError = "";
  render();
  lookup();
  return "";
}

async function useDest(raw) {
  const found = await readCode(raw);
  if (found.error) return found.error;
  state.dest = found.decoded;
  state.destText = found.decoded.text;
  if (found.amount && !state.amountText) {
    try {
      solToLamports(found.amount);
      state.amountText = found.amount;
      state.amountFromCode = true;
    } catch { /* ignore a bad amount on the code */ }
  }
  state.step = "pay";
  state.formError = "";
  render();
  return "";
}

function typePages() {
  const pages = [];
  const groups = state.result.groups;
  for (let i = 0; i < groups.length; i += 2) {
    const items = [{ label: String(i + 1).padStart(2, "0"), text: groups[i] }];
    if (groups[i + 1]) items.push({ label: String(i + 2).padStart(2, "0"), text: groups[i + 1] });
    pages.push(items);
  }
  return pages;
}

function primary(label, onClick, disabled) {
  return h("button", { class: "primary", type: "button", onclick: onClick, disabled: !!disabled }, [label]);
}

function secondary(label, onClick) {
  return h("button", { class: "secondary", type: "button", onclick: onClick }, [label]);
}

function textButton(label, onClick) {
  return h("button", { class: "text", type: "button", onclick: onClick }, [label]);
}

function wide() {
  return window.matchMedia("(min-width: 800px)").matches;
}

function walletForm() {
  const input = h("input", {
    id: "wallet-draft",
    type: "text",
    value: state.draft,
    autocomplete: "off",
    spellcheck: "false",
    autocapitalize: "off",
    placeholder: "Solana address",
  });
  input.addEventListener("input", () => { state.draft = input.value; });
  return h("form", { class: "stack", onsubmit: async (e) => {
    e.preventDefault();
    state.draft = input.value;
    const err = await useWallet(input.value, true);
    if (err) {
      state.formError = err;
      render();
    }
  } }, [
    h("label", {}, ["Address on the Game Boy", input]),
    h("p", { class: "bad" }, [state.formError]),
    h("button", { class: "primary", type: "submit" }, ["Look it up"]),
  ]);
}

function renderHome() {
  if (wide()) {
    screen.append(
      h("h1", {}, ["Send SOL"]),
      h("p", { class: "lead" }, ["On your Game Boy, open the address code."]),
      h("p", { class: "lead" }, ["Type it here. Your words and your key stay on the Game Boy."]),
      walletForm(),
      h("div", { class: "actions" }, [
        secondary("Scan the code", () => startScan("wallet")),
      ])
    );
    return;
  }
  screen.append(
    h("h1", {}, ["Send SOL"]),
    h("p", { class: "lead" }, ["On your Game Boy, open the address code."]),
    h("p", { class: "lead" }, ["Then scan it with this phone. Your words and your key stay on the Game Boy."]),
    h("div", { class: "actions" }, [
      primary("Scan the code", () => startScan("wallet")),
      textButton("Type the address", () => go("typeWallet")),
    ])
  );
}

function renderTypeWallet() {
  screen.append(
    h("h1", {}, ["Type your address"]),
    h("p", { class: "lead" }, ["The code is on the Game Boy address screen. Type it here if the camera cannot see it."]),
    walletForm(),
    textButton("Scan instead", () => startScan("wallet"))
  );
}

function renderFound() {
  const bits = [
    h("h1", {}, ["Your Game Boy"]),
    h("p", { class: "addr" }, [spaced(state.wallet.text)]),
  ];
  if (state.lookup === "loading") {
    bits.push(h("p", { class: "money" }, ["Looking up your balance…"]));
  } else if (state.lookup === "error") {
    bits.push(h("p", { class: "bad" }, ["The lookup did not answer. Check your connection."]));
    bits.push(primary("Try again", () => lookup()));
  } else if (state.balance === 0n) {
    bits.push(h("p", { class: "money" }, ["There is no SOL here yet."]));
    bits.push(h("p", { class: "lead" }, ["Receive some on the Game Boy, then scan again."]));
    bits.push(primary("Scan a different wallet", () => startScan("wallet")));
  } else {
    bits.push(h("p", { class: "money" }, ["You have " + friendlySol(state.balance) + " SOL."]));
    bits.push(h("div", { class: "actions" }, [
      primary("Continue", () => go("pay")),
    ]));
  }
  screen.append(...bits);
}

function renderPay() {
  const dest = h("input", {
    id: "dest", type: "text", value: state.destText,
    autocomplete: "off", spellcheck: "false", autocapitalize: "off",
    placeholder: "Their address",
  });
  const amount = h("input", {
    id: "amount", type: "text", inputmode: "decimal", value: state.amountText,
    autocomplete: "off",
  });
  const nonce = h("input", {
    id: "nonce", type: "text", value: state.nonceText,
    autocomplete: "off", spellcheck: "false", autocapitalize: "off",
    placeholder: "Nonce account",
  });
  const bits = [
    h("h1", {}, ["Who are you paying?"]),
  ];
  if (state.lookup === "loading") bits.push(h("p", { class: "note" }, ["Looking up your balance…"]));
  else if (state.lookup === "done") {
    bits.push(h("p", { class: "money" }, [
      state.balance === 0n ? "There is no SOL to send yet." : "You have " + friendlySol(state.balance) + " SOL.",
    ]));
  } else if (state.lookup === "error") {
    bits.push(h("p", { class: "bad" }, ["The lookup did not answer."]));
  }
  if (state.amountFromCode) bits.push(h("p", { class: "note" }, ["The amount was filled in from their code."]));
  bits.push(secondary("Scan their code", () => { rememberPay(); startScan("dest"); }));
  bits.push(h("div", { class: "pay-fields" }, [
    h("label", {}, ["Their address", dest]),
    h("label", { class: "amount" }, ["How much?", amount]),
    h("label", {}, ["Nonce account", nonce]),
  ]));
  bits.push(h("p", { class: "note" }, [
    "Use a durable nonce account this wallet owns. The payment stays valid until it is sent.",
  ]));
  bits.push(h("p", { class: "bad" }, [state.formError]));
  bits.push(h("div", { class: "actions" }, [
    primary("Next", () => submitPay()),
  ]));
  screen.append(...bits);
}

function allZero(bytes) {
  for (const b of bytes) if (b) return false;
  return true;
}

const SYSTEM_OWNER = "11111111111111111111111111111111";

function b64ToBytes(text) {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function u32le(bytes, off) {
  return bytes[off]
    + bytes[off + 1] * 256
    + bytes[off + 2] * 65536
    + bytes[off + 3] * 16777216;
}

function u64le(bytes, off) {
  let n = 0n;
  for (let i = 7; i >= 0; i--) n = (n << 8n) + BigInt(bytes[off + i]);
  return n;
}

/* Nonce account data is 80 bytes: version, state, authority, nonce, fee. */
function readNonceAccount(value, walletPub) {
  if (!value || value.owner !== SYSTEM_OWNER) {
    return { error: "That account is not a durable nonce." };
  }
  const dataField = value.data;
  if (!dataField || dataField.length < 2 || dataField[1] !== "base64") {
    return { error: "That account is not a durable nonce." };
  }
  let data;
  try { data = b64ToBytes(dataField[0]); }
  catch { return { error: "That account is not a durable nonce." }; }
  if (data.length !== 80) return { error: "That account is not a durable nonce." };
  const version = u32le(data, 0);
  const st = u32le(data, 4);
  if ((version !== 0 && version !== 1) || st !== 1) {
    return { error: "That account is not a durable nonce." };
  }
  if (!hexEq(data.slice(8, 40), walletPub)) {
    return { error: "That nonce belongs to a different wallet." };
  }
  const nonce = data.slice(40, 72);
  if (allZero(nonce)) return { error: "That nonce is empty." };
  return { nonce, fee: u64le(data, 72) };
}

async function submitPay() {
  rememberPay();
  state.formError = "";
  if (state.lookup === "loading") {
    state.formError = "Still looking up your balance.";
    render();
    return;
  }
  if (state.lookup !== "done" || state.balance === null) {
    state.formError = "The lookup did not answer, so the balance is unknown.";
    render();
    return;
  }
  let dest;
  try { dest = decodeAddress(state.destText); }
  catch {
    state.formError = "Check their address and try again.";
    render();
    return;
  }
  if (allZero(dest.pubkey)) {
    state.formError = "That address is not a wallet.";
    render();
    return;
  }
  let lamports;
  try { lamports = solToLamports(state.amountText); }
  catch {
    state.formError = "Enter the amount in SOL.";
    render();
    return;
  }
  if (lamports <= 0n) {
    state.formError = "Enter an amount greater than zero.";
    render();
    return;
  }
  const nonceText = state.nonceText.trim();
  if (!nonceText) {
    state.formError = "Enter the nonce account.";
    render();
    return;
  }
  let nonceAcc;
  try { nonceAcc = decodeAddress(nonceText); }
  catch {
    state.formError = "Check the nonce account and try again.";
    render();
    return;
  }
  if (allZero(nonceAcc.pubkey) || hexEq(nonceAcc.pubkey, state.wallet.pubkey)) {
    state.formError = "The nonce account has to be its own account.";
    render();
    return;
  }
  let fee;
  let nonceValue;
  try {
    const info = await rpc("getAccountInfo", [
      nonceAcc.text, { encoding: "base64", commitment: "finalized" },
    ]);
    if (!info || info.value === null) {
      state.formError = "That nonce account was not found.";
      render();
      return;
    }
    const parsed = readNonceAccount(info.value, state.wallet.pubkey);
    if (parsed.error) {
      state.formError = parsed.error;
      render();
      return;
    }
    fee = parsed.fee;
    nonceValue = parsed.nonce;
    const destInfo = await rpc("getAccountInfo", [dest.text, { encoding: "base64" }]);
    if (!destInfo || destInfo.value === null) {
      const rent = asBig(await rpc("getMinimumBalanceForRentExemption", [0]));
      if (lamports < rent) {
        state.formError = "A new account needs at least " + friendlySol(rent) + " SOL.";
        render();
        return;
      }
    }
  } catch {
    state.formError = "The network did not answer. Check your connection.";
    render();
    return;
  }
  if (state.balance < lamports + fee) {
    state.formError = "You have " + friendlySol(state.balance) + " SOL. That is not enough.";
    render();
    return;
  }
  state.dest = dest;
  state.plan = {
    lamports,
    nonceAccount: nonceAcc.pubkey,
    nonce: nonceValue,
    nonceAccountText: nonceAcc.text,
    nonceText: b58encode(nonceValue),
    fee,
  };
  try {
    state.result = await encodeString({
      lamports,
      dest: dest.pubkey,
      nonceAccount: nonceAcc.pubkey,
      nonce: nonceValue,
    });
  } catch (problem) {
    state.formError = problem.message;
    render();
    return;
  }
  state.page = 0;
  state.sigParts = [];
  state.sigCount = 0;
  state.txB64 = "";
  state.txSig = "";
  state.sendError = "";
  state.step = "review";
  render();
}

function renderReview() {
  const plan = state.plan;
  const same = state.dest.text === state.wallet.text;
  const lines = [
    h("h1", {}, ["Check this"]),
    h("p", { class: "money" }, ["Send " + friendlySol(plan.lamports) + " SOL"]),
    h("p", { class: "addr" }, [spaced(state.dest.text)]),
    h("p", { class: "lead" }, ["Nonce " + plan.nonceText.slice(0, 8) + "…"]),
    h("p", { class: "addr" }, [spaced(plan.nonceAccountText)]),
    h("p", { class: "note" }, [
      "The fee locked in this nonce is " + friendlySol(plan.fee) + " SOL. It is not part of what the Game Boy signs.",
    ]),
    h("p", { class: "note" }, ["This nonce stays valid until the payment is sent."]),
  ];
  if (same) lines.push(h("p", { class: "note" }, ["This pays your own Game Boy. Only the network fee leaves."]));
  lines.push(h("div", { class: "actions" }, [
    primary("Show what to type", () => go("type")),
    textButton("Change the amount", () => go("pay")),
  ]));
  screen.append(...lines);
}

function renderType() {
  const rows = typePages().map((page) => h("div", { class: "type-row" }, page.map((item) => (
    h("div", { class: "group-block" }, [
      h("p", { class: "num" }, [item.label]),
      h("p", { class: "chars" }, [item.text]),
    ])
  ))));
  screen.append(
    h("h1", {}, ["Type this"]),
    h("p", { class: "lead" }, [
      "Type every character. " + state.result.groups.length + " groups. Skip the small number.",
    ]),
    h("div", { class: "type-sheet" }, [
      ...rows,
      h("details", {}, [
        h("summary", {}, ["Save a copy"]),
        textButton("Copy everything", copyAll),
      ]),
    ]),
    h("div", { class: "actions" }, [
      primary("Scan the signed codes", startSignedScan),
      textButton("Done", finishPay),
    ])
  );
}

async function copyAll(event) {
  const lines = [];
  for (const page of typePages()) lines.push(page.map((item) => item.text).join("  "));
  const btn = event.currentTarget;
  try {
    await navigator.clipboard.writeText(lines.join("\n"));
    btn.textContent = "Copied";
  } catch {
    btn.textContent = "Copy failed";
  }
}

function cameraAvailable() {
  return !!(navigator.mediaDevices && typeof navigator.mediaDevices.getUserMedia === "function");
}

function iphone() {
  return /iPhone|iPad|iPod/.test(navigator.userAgent) ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

function stopTracks(media) {
  if (!media) return;
  for (const track of media.getTracks()) track.stop();
}

function prepareCamera(video) {
  video.muted = true;
  video.defaultMuted = true;
  video.autoplay = true;
  video.playsInline = true;
  video.setAttribute("muted", "");
  video.setAttribute("autoplay", "");
  video.setAttribute("playsinline", "true");
  video.setAttribute("webkit-playsinline", "true");
}

function placeCamera() {
  const video = document.getElementById("cam");
  const slot = document.querySelector(".finder");
  if (!video || !slot || state.step !== "scan") return;
  // No camera running: keep the black video parked off screen.
  if (slot.classList.contains("cam-off")) { parkCamera(); return; }
  const box = slot.getBoundingClientRect();
  const vv = window.visualViewport;
  const offsetLeft = vv ? vv.offsetLeft : 0;
  const offsetTop = vv ? vv.offsetTop : 0;
  const edge = 3;
  video.style.left = (box.left + offsetLeft + edge) + "px";
  video.style.top = (box.top + offsetTop + edge) + "px";
  video.style.width = Math.max(1, box.width - edge * 2) + "px";
  video.style.height = Math.max(1, box.height - edge * 2) + "px";
  video.style.transform = "translateZ(0)";
  video.style.webkitTransform = "translateZ(0)";
  const frame = slot.querySelector(".frame");
  if (!frame) return;
  frame.style.position = "fixed";
  frame.style.zIndex = "3";
  frame.style.inset = "auto";
  const wantLeft = box.left + box.width * 0.12;
  const wantTop = box.top + box.height * 0.14;
  frame.style.left = (wantLeft + offsetLeft) + "px";
  frame.style.top = (wantTop + offsetTop) + "px";
  frame.style.width = (box.width * 0.76) + "px";
  frame.style.height = (box.height * 0.72) + "px";
  // A filter, transform or backdrop-filter on an ancestor turns "fixed" into
  // "relative to that ancestor". Measure where it landed and correct.
  const got = frame.getBoundingClientRect();
  const dx = wantLeft - got.left;
  const dy = wantTop - got.top;
  if (Math.abs(dx) > 0.5 || Math.abs(dy) > 0.5) {
    frame.style.left = (parseFloat(frame.style.left) + dx) + "px";
    frame.style.top = (parseFloat(frame.style.top) + dy) + "px";
  }
}

function parkCamera() {
  const video = document.getElementById("cam");
  if (!video) return;
  video.style.left = "";
  video.style.top = "";
  video.style.width = "";
  video.style.height = "";
  video.style.transform = "";
  video.style.webkitTransform = "";
}

function scanLead(live) {
  if (state.scanFor === "signed") return signedProgress();
  if (!live) {
    return "This browser cannot open a live camera here (Lockdown Mode, an in-app browser or a non-secure page). Take a photo of the code instead.";
  }
  if (!idleCam) return "Starting the camera…";
  if (state.scanFor === "dest") return "Point the camera at their code.";
  return "On your Game Boy, open the address code, then point this camera at it. Your words and your key stay on the Game Boy.";
}

function renderScan() {
  const live = cameraAvailable();
  const video = document.getElementById("cam");
  if (video) prepareCamera(video);
  const photo = h("input", { id: "photo", type: "file", accept: "image/*", capture: "environment" });
  photo.addEventListener("change", () => {
    const file = photo.files && photo.files[0];
    photo.value = "";
    readPhoto(file);
  });
  const signed = state.scanFor === "signed";
  const title = signed ? "Scan the signed codes" : (state.scanFor === "wallet" ? "Scan your Game Boy" : "Scan their code");
  const bits = [
    h("h1", {}, [title]),
    h("p", { class: "lead" }, [scanLead(live)]),
  ];
  if (live) bits.push(h("div", { class: idleCam ? "finder cam-off" : "finder" }, [h("div", { class: "frame" })]));
  bits.push(h("p", { class: "bad" }, [state.scanError]));
  if (live) {
    const retry = primary(idleCam ? "Start camera" : "Try camera again", retryCamera);
    retry.id = "retry-cam";
    bits.push(retry);
  }
  bits.push(h("label", {
    id: "take-photo",
    class: live ? "secondary pick" : "primary pick",
  }, [live ? "Take a photo instead" : "Take a photo", photo]));
  if (!signed) {
    bits.push(textButton("Type it instead", () => go(state.scanFor === "wallet" ? "typeWallet" : "pay")));
  }
  screen.append(...bits);
  if (live) placeCamera();
}

// iOS Safari only shows the camera prompt when getUserMedia is called inside
// the tap itself. So every button that opens the scanner calls this first,
// synchronously, before any render or await.
function beginCamera() {
  if (!cameraAvailable()) return null;
  try {
    return navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: { ideal: "environment" } },
    });
  } catch (err) {
    return Promise.reject(err);
  }
}

// Hook a started request to the scan screen that is now showing.
function attachCamera(request) {
  const gen = scanGen;
  const video = document.getElementById("cam");
  const retry = document.getElementById("retry-cam");
  if (!request) return;
  if (!video || state.step !== "scan") {
    request.then(stopTracks).catch(() => {});
    return;
  }
  cameraAsked = true;
  if (retry) retry.hidden = true;
  const finder = screen.querySelector(".finder");
  if (finder) finder.classList.remove("cam-off");
  prepareCamera(video);
  placeCamera();
  const prime = video.play();
  if (prime && prime.catch) prime.catch(() => {});
  requestAnimationFrame(placeCamera);
  request.then((got) => {
    gotCamera(gen, got);
  }).catch((err) => {
    cameraAsked = false;
    failCamera(gen, err);
  });
}

function retryCamera() {
  if (cameraAsked) return;
  idleCam = false;
  const request = beginCamera();
  state.scanError = "";
  const bad = screen.querySelector(".bad");
  if (bad) bad.textContent = "";
  const lead = screen.querySelector(".lead");
  if (lead && state.scanFor !== "signed") lead.textContent = "Starting the camera…";
  if (!request) { failCamera(scanGen, { name: "NotSupportedError" }); return; }
  attachCamera(request);
}

function failCamera(gen, problem) {
  if (gen !== scanGen || state.step !== "scan") return;
  cameraAsked = false;
  if (stream) {
    stopTracks(stream);
    stream = null;
  }
  const video = document.getElementById("cam");
  if (video) video.srcObject = null;
  scanGen += 1;
  const name = (problem && problem.name) || "Error";
  if (name === "NotAllowedError") {
    state.scanError = iphone()
      ? "Safari blocked the camera. Tap aA in the address bar, open Website Settings, and allow Camera."
      : "The browser blocked the camera. Allow it for this site, then tap Try camera again.";
  } else {
    state.scanError = "The live camera did not start (" + name + "). Take a photo instead.";
  }
  const bad = screen.querySelector(".bad");
  if (bad) bad.textContent = state.scanError;
  const finder = screen.querySelector(".finder");
  if (finder) finder.classList.add("cam-off");
  const lead = screen.querySelector(".lead");
  if (lead) {
    lead.textContent = state.scanFor === "signed"
      ? signedProgress()
      : "No live camera. Take a photo of the code, or type it.";
  }
  const button = document.getElementById("retry-cam");
  if (button) {
    button.hidden = false;
    button.disabled = false;
  }
  const photoBtn = document.getElementById("take-photo");
  if (photoBtn) photoBtn.className = "primary pick";
  requestAnimationFrame(placeCamera);
}

function gotCamera(gen, got) {
  if (gen !== scanGen) { stopTracks(got); return; }
  stream = got;
  const video = document.getElementById("cam");
  if (!video) { stopTracks(got); stream = null; return; }
  prepareCamera(video);
  video.srcObject = stream;
  let shown = false;
  const reveal = () => {
    if (gen !== scanGen || shown) return;
    shown = true;
    const lead = screen.querySelector(".lead");
    if (lead) {
      lead.textContent = state.scanFor === "signed"
        ? signedProgress()
        : "Fill the box with the code. Hold steady.";
    }
    const button = document.getElementById("retry-cam");
    if (button) button.hidden = true;
    const bad = screen.querySelector(".bad");
    if (bad && state.scanError === "") bad.textContent = "";
    placeCamera();
    requestAnimationFrame(placeCamera);
  };
  const show = () => {
    if (gen !== scanGen || shown) return;
    let started;
    try { started = video.play(); }
    catch (err) { failCamera(gen, err); return; }
    const done = started && started.then ? started : Promise.resolve();
    done.then(() => {
      if (gen !== scanGen) return;
      reveal();
    }).catch((err) => {
      if (gen !== scanGen || shown || video.readyState < 1) return;
      failCamera(gen, err);
    });
  };
  show();
  video.onloadedmetadata = show;
  setTimeout(() => {
    if (gen !== scanGen || shown) return;
    if (video.readyState >= 2) show();
    else failCamera(gen, { name: "TimeoutError" });
  }, 2000);
  listenForCodes(gen, video);
}

function qrBytes(code) {
  if (!code || !code.chunks) return null;
  const bytes = [];
  for (const chunk of code.chunks) {
    if (chunk.type === "byte" && chunk.bytes) {
      for (const b of chunk.bytes) bytes.push(b);
    }
  }
  return bytes.length ? new Uint8Array(bytes) : null;
}

function readJsQr(video, canvas, ctx) {
  if (typeof jsQR !== "function" || video.readyState < 2) return null;
  const scale = Math.min(1, 640 / (video.videoWidth || 640));
  canvas.width = Math.max(1, Math.floor(video.videoWidth * scale));
  canvas.height = Math.max(1, Math.floor(video.videoHeight * scale));
  ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
  const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
  return jsQR(image.data, image.width, image.height, { inversionAttempts: "attemptBoth" });
}

function listenForCodes(gen, video) {
  const signed = state.scanFor === "signed";
  let detector = null;
  // The signed codes are raw bytes. BarcodeDetector returns text and
  // would change those bytes, so that scan uses jsQR only.
  if (!signed && "BarcodeDetector" in window) {
    try { detector = new BarcodeDetector({ formats: ["qr_code"] }); }
    catch { detector = null; }
  }
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  let lastText = "";
  const tick = async () => {
    if (gen !== scanGen) return;
    try {
      let text = "";
      let bytes = null;
      let key = "";
      if (signed) {
        const code = readJsQr(video, canvas, ctx);
        if (code) {
          bytes = qrBytes(code);
          // Two signed pages can both fail as text. Compare the bytes.
          key = bytes ? [...bytes].join(",") : "unreadable";
        }
      } else if (detector) {
        const codes = await detector.detect(video);
        if (codes.length) text = codes[0].rawValue || "";
        key = text;
      } else {
        const code = readJsQr(video, canvas, ctx);
        if (code) text = code.data || "";
        key = text;
      }
      if (!key) lastText = "";
      else if (key !== lastText) {
        lastText = key;
        const err = signed ? await useSigned(bytes) : (
          state.scanFor === "wallet" ? await useWallet(text) : await useDest(text)
        );
        if (state.step !== "scan") return;
        noteScan(err);
      }
    } catch { /* keep looking */ }
    if (gen === scanGen) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

async function readPhoto(file) {
  if (!file || typeof jsQR !== "function") return;
  const url = URL.createObjectURL(file);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    const canvas = document.createElement("canvas");
    const scale = Math.min(1, 1200 / image.width);
    canvas.width = Math.floor(image.width * scale);
    canvas.height = Math.floor(image.height * scale);
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
    const pixels = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: "attemptBoth" });
    if (!code) {
      state.scanError = "That photo has no code. Try again, closer.";
      const bad = screen.querySelector(".bad");
      if (bad) bad.textContent = state.scanError;
      return;
    }
    const err = state.scanFor === "signed"
      ? await useSigned(qrBytes(code))
      : (state.scanFor === "wallet" ? await useWallet(code.data) : await useDest(code.data));
    if (state.step !== "scan") return;
    if (err && state.scanFor !== "signed") {
      state.scanError = err;
      render();
      return;
    }
    noteScan(err);
  } finally {
    URL.revokeObjectURL(url);
  }
}

function signedProgress() {
  if (!state.sigCount) return "Scan every code. Start with 00.";
  const have = state.sigParts.map((part) => part.page).sort((a, b) => a - b);
  const missing = [];
  for (let i = 0; i < state.sigCount; i++) {
    if (!have.includes(i)) missing.push(String(i).padStart(2, "0"));
  }
  const got = have.map((n) => String(n).padStart(2, "0")).join(" ");
  if (!missing.length) return "Got " + got + ".";
  return "Got " + got + ". Still need " + missing.join(" ") + ".";
}

function noteScan(err) {
  state.scanError = err || "";
  const bad = screen.querySelector(".bad");
  if (bad) bad.textContent = state.scanError;
  if (state.scanFor === "signed") {
    const lead = screen.querySelector(".lead");
    if (lead) lead.textContent = signedProgress();
  }
}

function clearSigned() {
  state.sigParts = [];
  state.sigCount = 0;
  state.txB64 = "";
  state.txSig = "";
  state.sendError = "";
}

function finishPay() {
  sendGen += 1;
  state.page = 0;
  state.amountText = "";
  state.amountFromCode = false;
  state.plan = null;
  state.result = null;
  clearSigned();
  state.step = "home";
  render();
}

function startSignedScan() {
  if (!state.plan || !state.wallet || !state.dest) return;
  state.scanFor = "signed";
  state.scanError = "";
  state.step = "scan";
  cameraAsked = false;
  render();
}

async function useSigned(bytes) {
  if (!state.plan || !state.wallet || !state.dest) return "Go back and check the payment first.";
  if (!bytes) return "That code is not a signed page.";
  let part;
  try { part = parseSigPage(bytes); }
  catch (problem) { return problem.message; }
  if (state.sigCount && part.count !== state.sigCount) return "That code is from a different set.";
  state.sigCount = part.count;
  state.sigParts = state.sigParts.filter((got) => got.page !== part.page);
  state.sigParts.push(part);
  if (state.sigParts.length < state.sigCount) return "";
  try {
    const blob = assembleSigBlob(state.sigParts);
    const wire = buildSignedTx({
      walletPub: state.wallet.pubkey,
      dest: state.dest.pubkey,
      nonceAccount: state.plan.nonceAccount,
      nonce: state.plan.nonce,
      lamports: state.plan.lamports,
    }, blob);
    state.txB64 = bytesToBase64(wire);
  } catch (problem) {
    return problem.message;
  }
  state.step = "send";
  state.sendError = "";
  render();
  broadcast();
  return "";
}

function plainSendError(message) {
  const text = String(message || "");
  if (/nonce|blockhash|expired/i.test(text)) {
    return "That nonce was already used. Start the payment again.";
  }
  if (/insufficient/i.test(text)) return "The network did not take it. The balance was not enough.";
  if (/signature/i.test(text)) return "The network did not take it. The signature did not match.";
  if (text && text.length < 140) return text;
  return "The network did not take it.";
}

async function broadcast() {
  const gen = ++sendGen;
  const tx = state.txB64;
  if (!tx) {
    state.sendError = "There is no payment to send.";
    if (state.step === "send") render();
    return;
  }
  try {
    const res = await fetch("https://api.mainnet-beta.solana.com", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "sendTransaction",
        params: [tx, { encoding: "base64", preflightCommitment: "finalized" }],
      }),
    });
    const text = await res.text();
    let data = {};
    try { data = JSON.parse(text); }
    catch { data = {}; }
    if (gen !== sendGen || state.step !== "send") return;
    if (!res.ok || data.error) {
      const message = data.error && (data.error.message || data.error);
      state.sendError = plainSendError(message || "The network did not take it.");
      render();
      return;
    }
    state.txSig = String(data.result || "");
    state.step = "sent";
    render();
  } catch {
    if (gen !== sendGen || state.step !== "send") return;
    state.sendError = "The network did not answer. Check your connection.";
    render();
  }
}

function renderSend() {
  const bits = [
    h("h1", {}, ["Sending"]),
    h("p", { class: "lead" }, [
      state.sendError ? "The payment was not sent." : "The network is taking the payment.",
    ]),
    h("p", { class: "bad" }, [state.sendError]),
  ];
  if (state.sendError) {
    bits.push(h("div", { class: "actions" }, [
      primary("Try again", () => {
        state.sendError = "";
        render();
        broadcast();
      }),
    ]));
  }
  screen.append(...bits);
}

function renderSent() {
  const bits = [
    h("h1", {}, ["Sent"]),
    h("p", { class: "lead" }, ["The payment is on the network."]),
  ];
  if (state.txSig) bits.push(h("p", { class: "addr" }, [spaced(state.txSig)]));
  bits.push(h("div", { class: "actions" }, [
    primary("Done", finishPay),
  ]));
  screen.append(...bits);
}

function startScan(which) {
  const request = beginCamera();
  rememberPay();
  state.scanFor = which;
  state.scanError = "";
  state.step = "scan";
  cameraAsked = false;
  idleCam = false;
  render();
  attachCamera(request);
}

// The app opens on the wallet camera. Safari on iPhone only starts a camera
// from a tap, so it shows a Start camera button; other browsers start it
// at once when permission was already granted.
function autoStartCamera() {
  if (!idleCam || iphone() || !cameraAvailable() || !navigator.permissions) return;
  navigator.permissions.query({ name: "camera" }).then((p) => {
    if (p.state === "granted" && idleCam && state.step === "scan") retryCamera();
  }).catch(() => {});
}

function render() {
  let opening = false;
  if (state.step === "home") {
    state.step = "scan";
    state.scanFor = "wallet";
    state.scanError = "";
    idleCam = true;
    opening = true;
  }
  stopCamera();
  parkCamera();
  document.body.classList.toggle("scanning", state.step === "scan");
  document.body.classList.toggle("typing", state.step === "type");
  const step = stepIndex();
  dotsEl.replaceChildren();
  for (let i = 0; i < 4; i++) {
    dotsEl.append(h("span", { class: i === step ? "on" : "" }, ["●"]));
  }
  const showBack = !(state.step === "scan" && state.scanFor === "wallet");
  backBtn.hidden = !showBack;
  backBtn.onclick = () => {
    if (state.step === "scan") {
      if (state.scanFor === "signed") go("type");
      else go(state.scanFor === "dest" ? "pay" : "home");
    } else if (state.step === "typeWallet") go("home");
    else if (state.step === "found") go("home");
    else if (state.step === "pay") go(state.wallet ? "found" : "home");
    else if (state.step === "review") go("pay");
    else if (state.step === "type") go("review");
    else if (state.step === "send") go("type");
    else if (state.step === "sent") finishPay();
  };
  screen.replaceChildren();
  if (state.step === "home") renderHome();
  else if (state.step === "typeWallet") renderTypeWallet();
  else if (state.step === "found") renderFound();
  else if (state.step === "pay") renderPay();
  else if (state.step === "review") renderReview();
  else if (state.step === "type") renderType();
  else if (state.step === "scan") renderScan();
  else if (state.step === "send") renderSend();
  else if (state.step === "sent") renderSent();
  if (opening) autoStartCamera();
}

backBtn.addEventListener("click", () => {});
let wideNow = wide();
window.addEventListener("resize", () => {
  const next = wide();
  if (next !== wideNow) {
    wideNow = next;
    if (state.step === "home") render();
  }
  if (state.step === "scan") placeCamera();
});
if (window.visualViewport) {
  window.visualViewport.addEventListener("resize", () => {
    if (state.step === "scan") placeCamera();
  });
  window.visualViewport.addEventListener("scroll", () => {
    if (state.step === "scan") placeCamera();
  });
}
try {
  render();
} catch (problem) {
  screen.replaceChildren(document.createTextNode(
    problem && problem.message ? problem.message : "This page did not start."
  ));
}
