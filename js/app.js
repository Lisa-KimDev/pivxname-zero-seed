// PIVX Names — zero seeds. Static client for the PiNS protocol.
// Keys live in this tab's memory only. CSP allows calls ONLY to:
//   registrar.pivx.name (check/pay/prices) + indexer.pivx.name (resolve/track)

const REGISTRAR = "https://registrar.pivx.name";
const INDEXER = "https://indexer.pivx.name";
import * as ed25519 from "./vendor/ed25519.js";
const ZONES = ["pivx", "private", "secure", "safe"];
const MEMO_MAX = 512;
const B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const $ = (id) => document.getElementById(id);
const show = (el) => el.classList.remove("hidden");
const hide = (el) => el.classList.add("hidden");

let toastTimer;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  show(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => hide(t), 2600);
}

async function api(url, opts) {
  const r = await fetch(url, opts);
  const j = await r.json();
  if (j.error) throw new Error(j.error.error_message || JSON.stringify(j.error));
  return j.response;
}
const regGet = (p) => api(REGISTRAR + p);
const regPost = (p, body, asText) => api(REGISTRAR + p, {
  method: "POST",
  headers: { "Content-Type": asText ? "text/plain" : "application/json" },
  body: JSON.stringify(body),
});
const idxGet = (p) => api(INDEXER + p);
const idxPost = (p) => api(INDEXER + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });

const zat = (z) => { const p = Number(z) / 1e8; return Number.isInteger(p) ? String(p) : String(p); };

// ---------------- bech32 / validation (port of indexer rules) ----------------
function b32Polymod(vals) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of vals) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) chk ^= (b >> i) & 1 ? G[i] : 0;
  }
  return chk;
}
function b32Expand(hrp) {
  const h = [...hrp].map((c) => c.charCodeAt(0));
  return [...h.map((x) => x >> 5), 0, ...h.map((x) => x & 31)];
}
function validShielded(addr) {
  if (!addr || addr !== addr.toLowerCase() || addr.length !== 78) return false;
  const pos = addr.lastIndexOf("1");
  if (pos < 1 || addr.length - pos - 1 < 6) return false; // ≥6 checksum chars after sep
  const hrp = addr.slice(0, pos);
  const data = [];
  for (const ch of addr.slice(pos + 1)) {
    const v = B32.indexOf(ch);
    if (v < 0) return false;
    data.push(v);
  }
  if (b32Polymod([...b32Expand(hrp), ...data]) !== 1) return false;
  return hrp === "ps";
}
function validDomain(d) {
  if (!d || d.length > 64 || (d.match(/\./g) || []).length !== 1) return false;
  const [label, zone] = d.split(".");
  if (!ZONES.includes(zone) || !label) return false;
  if (label.startsWith("-") || label.endsWith("-") || d.includes("--")) return false;
  return /^[a-z0-9-]+$/.test(label);
}
const validPubHex = (h) => /^[0-9a-f]{64}$/.test(h || "");

// ---------------- identity (noble ed25519, async APIs only) ----------------
const S = { domain: null, priceZat: null, priv: null, pub: null, memo: null, payAddr: null, amountPivx: null };

async function newIdentity() {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = await ed25519.getPublicKeyAsync(priv);
  return { priv, pub };
}
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => new Uint8Array(h.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
const enc = new TextEncoder();

async function signMsg(msgStr, priv) {
  return hex(await ed25519.signAsync(enc.encode(msgStr), priv));
}
async function selfVerify(memo) {
  const parts = memo.split(":");
  const op = parts[2];
  const pubIdx = ["REG", "UPD", "BUY"].includes(op) ? 5 : 4;
  // CHG: memo field is the NEW owner; signature must verify against the SIGNER (our key)
  const pub = op === "CHG" ? S.pub : unhex(parts[pubIdx]);
  const body = enc.encode(parts.slice(0, -1).join(":"));
  return ed25519.verifyAsync(unhex(parts[parts.length - 1]), body, pub);
}

function keyfile() {
  return JSON.stringify({
    v: 1,
    type: "pivxname-identity",
    note: "Name-ownership key. NOT a wallet key — cannot spend PIVX. Keep this file safe; it owns your names.",
    pubkey_hex: hex(S.pub),
    privkey_hex: hex(S.priv),
    created: new Date().toISOString(),
  }, null, 2);
}

function downloadKeyfile() {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([keyfile()], { type: "application/json" }));
  a.download = `pivxname-identity-${hex(S.pub).slice(0, 8)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

async function adoptKey(privBytes, viaImport) {
  S.priv = privBytes;
  S.pub = await ed25519.getPublicKeyAsync(privBytes);
  renderIdentity(viaImport);
  maybeUnlock(3);
  maybeUnlockM();
}

function renderIdentity(viaImport) {
  const box = $("identityBox");
  box.innerHTML = `
    <div class="line"><span class="k">${viaImport ? "imported key" : "new identity"}</span><span class="v good">✓ ready</span></div>
    <div class="line"><span class="k">pubkey</span><span class="v">${hex(S.pub)}</span></div>
    <div class="line"><span class="k">download</span><span class="v"><button class="btn primary tiny" id="btnDlKey">⬇ Save keyfile</button>
      <span class="hint">owns your names. Losing it = losing them. It can't spend PIVX.</span></span></div>`;
  show(box);
  $("btnDlKey").onclick = () => { downloadKeyfile(); toast("Keyfile downloaded — store it somewhere safe"); };
}

// ---------------- step unlocking ----------------
function maybeUnlock(step) {
  if (step >= 2 && S.domain !== null) show($("card-identity"));
  if (step >= 3 && S.pub) show($("card-resolve"));
  if (step >= 4 && validShielded($("resolveAddr").value.trim())) { renderSummary(); show($("card-pay")); }
}
function maybeUnlockM() {
  if (S.pub) { show($("mcard-op")); renderMIdentity(); }
}
function renderMIdentity() {
  const box = $("midentityBox");
  box.innerHTML = `<div class="line"><span class="k">identity</span><span class="v good">✓ ${hex(S.pub).slice(0, 24)}…</span></div>`;
  show(box);
}

// ---------------- STEP 1: search ----------------
$("btnSearch").onclick = async () => {
  const label = $("searchName").value.trim().toLowerCase();
  const domain = `${label}.${$("searchZone").value.replace(/^\./, "")}`;
  if (!validDomain(domain)) {
    $("searchResult").innerHTML = `<div class="line bad">Invalid name: use a–z, 0–9, single hyphens, no lead/trail hyphen.</div>`;
    show($("searchResult")); return;
  }
  const btn = $("btnSearch"); btn.disabled = true; btn.textContent = "checking…";
  try {
    const check = await regGet(`/v1.0/check/${domain}`);
    S.domain = domain;
    S.priceZat = check.price ? Number(check.price) : null;
    const box = $("searchResult");
    if (!check.exists) {
      box.innerHTML = `
        <div class="line"><span class="k">availability</span><span class="v good">✓ ${domain} is AVAILABLE</span></div>
        <div class="line"><span class="k">price</span><span class="v price">${zat(S.priceZat)} PIVX — one-time, no renewals</span></div>
        <div class="line"><span class="k">next</span><span class="v">create your ownership key below</span></div>`;
      maybeUnlock(2);
    } else if (S.priceZat) {
      const bound = await idxGet(`/v1.0/resolve/${domain}`).catch(() => null);
      box.innerHTML = `
        <div class="line"><span class="k">${domain}</span><span class="v">REGISTERED &amp; LISTED for sale</span></div>
        <div class="line"><span class="k">price</span><span class="v price">${zat(S.priceZat)} PIVX</span></div>
        ${bound ? `<div class="line"><span class="k">bound to</span><span class="v">${bound.target_address}</span></div>` : ""}
        <div class="line"><span class="k">buy it</span><span class="v">use the <b>Manage</b> tab → BUY with your key</span></div>`;
    } else {
      const bound = await idxGet(`/v1.0/resolve/${domain}`).catch(() => null);
      box.innerHTML = `
        <div class="line"><span class="k">${domain}</span><span class="v bad">already registered</span></div>
        ${bound ? `
          <div class="line"><span class="k">resolves to</span><span class="v">${bound.target_address}</span></div>
          <div class="line"><span class="k">owner</span><span class="v">${bound.owner_pubkey}</span></div>
          <div class="line"><span class="k">note</span><span class="v">if this is your key, open Manage to UPD/CHG/LST</span></div>` : ""}`;
    }
    show(box);
  } catch (e) {
    $("searchResult").innerHTML = `<div class="line bad">Registrar error: ${e.message}</div>`;
    show($("searchResult"));
  } finally { btn.disabled = false; btn.textContent = "Check"; }
};
$("searchName").addEventListener("keydown", (e) => e.key === "Enter" && $("btnSearch").click());

// ---------------- STEP 2: identity ----------------
$("btnGenKey").onclick = async () => {
  const { priv, pub } = await newIdentity();
  await adoptKey(priv, false);
  toast("Identity created — download the keyfile!");
};
$("fileKey").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  try {
    const txt = await f.text().then((t) => t.trim());
    let privHex = txt;
    if (txt.startsWith("{")) {
      const j = JSON.parse(txt);
      privHex = j.privkey_hex;
      if (j.type && j.type !== "pivxname-identity") throw new Error("not a pivxname keyfile");
    }
    if (!validPubHex(privHex)) throw new Error("keyfile must contain a 64-hex privkey_hex");
    await adoptKey(unhex(privHex), true);
    toast("Keyfile imported");
  } catch (err) {
    $("identityBox").innerHTML = `<div class="line bad">Import failed: ${err.message}</div>`;
    show($("identityBox"));
  }
  e.target.value = "";
});

// ---------------- STEP 3: resolve address ----------------
$("resolveAddr").addEventListener("input", () => {
  const v = $("resolveAddr").value.trim();
  const msg = $("resolveMsg");
  if (!v) { msg.innerHTML = ""; return; }
  if (validShielded(v)) {
    msg.innerHTML = `<div class="line good">✓ valid shielded address</div>`;
    maybeUnlock(4);
  } else {
    msg.innerHTML = `<div class="line bad">Not a mainnet shielded address — need ps1… exactly 78 chars (bech32). Transparent DQ…/testnet pts1… are refused by the registrar.</div>`;
    hide($("card-pay"));
  }
});

// ---------------- STEP 4: sign & pay ----------------
function renderSummary() {
  $("signSummary").innerHTML = `
    <b>${S.domain}</b> → resolves to <b>${$("resolveAddr").value.trim().slice(0, 20)}…</b><br>
    owner-key <b>${S.pub ? hex(S.pub).slice(0, 16) + "…" : "—"}</b> ·
    pay <b>${zat(S.priceZat)} PIVX</b> · settlement by pivx.name registrar (their fee, not ours — this site charges nothing)`;
}
$("resolveAddr").addEventListener("change", () => S.pub && renderSummary());

$("btnSign").onclick = async () => {
  const btn = $("btnSign"); btn.disabled = true; btn.textContent = "signing…";
  try {
    const target = $("resolveAddr").value.trim();
    const nonce = Math.floor(Date.now() / 1000);
    const base = `PiNS:1:REG:${S.domain}:${target}:${hex(S.pub)}:${nonce}`;
    if (base.length + 129 > MEMO_MAX) throw new Error("memo overflow");
    const memo = `${base}:${await signMsg(base, S.priv)}`;
    if (!(await selfVerify(memo))) throw new Error("self-verification failed");
    S.memo = memo;

    const pay = await regGet("/v1.0/getPaymentAddress");
    S.payAddr = pay.address;
    S.amountPivx = zat(S.priceZat);

    $("payAmount").value = `${S.amountPivx} PIVX`;
    $("payAddress").value = S.payAddr;
    $("payMemo").value = memo;

    // QR — same pivx: URI scheme the official app uses
    const uri = `pivx:${S.payAddr}?amount=${S.amountPivx}&memo=${encodeURIComponent(memo).replace(/%3A/g, ":")}`;
    const qr = qrcode(0, "L");
    qr.addData(uri);
    qr.make();
    $("payQr").innerHTML = qr.createImgTag(4, 8);

    $("fallbackContent").innerHTML = `
      <p class="explain">Payment 1 — no memo: send <b>${S.amountPivx} PIVX</b> to<br>
        <span class="v">${S.payAddr}</span></p>
      <p class="explain">Payment 2 — memo only: send <b>6 PIVX</b> (update fee) to the same address carrying this memo:<br>
        <span class="v">${memo}</span></p>
      <p class="hint">The registrar attaches any well-formed command to whatever payment funds it. Result is identical: your key owns the name.</p>`;

    show($("signBox"));
    show($("trackBox"));
    startTracking();
  } catch (e) {
    toast("Signing failed: " + e.message);
  } finally { btn.disabled = false; btn.textContent = "Sign registration"; }
};

document.querySelectorAll(".copybtn").forEach((b) => {
  b.onclick = () => {
    const el = $(b.dataset.copy);
    navigator.clipboard.writeText(el.value).then(() => toast("Copied"));
  };
});

// ---------------- tracking ----------------
let trackTimer = null;
function startTracking() {
  const status = $("trackStatus");
  const fill = $("trackBarFill");
  let elapsed = 0;
  clearInterval(trackTimer);
  trackTimer = setInterval(async () => {
    elapsed += 15;
    try {
      const check = await regGet(`/v1.0/check/${S.domain}`);
      if (check.exists) {
        clearInterval(trackTimer);
        fill.style.width = "100%";
        status.innerHTML = `<span class="good">✓ REGISTERED — ${S.domain} is live and bound to your address.</span>
          <br><span class="hint">Resolve check: <a class="v" target="_blank" rel="noopener" href="${INDEXER}/v1.0/resolve/${S.domain}">${S.domain}</a></span>`;
        return;
      }
      const mins = Math.floor(elapsed / 60);
      status.textContent = `Waiting for your payment… ~40 confirmations after it lands (${mins}m elapsed). Payment seen instantly once broadcast.`;
      fill.style.width = `${Math.min(95, elapsed / 4)}%`;
    } catch { /* registrar hiccup — keep polling */ }
  }, 15000);
}

// ---------------- MANAGE TAB ----------------
$("mbtnGenKey").onclick = async () => {
  const { priv } = await newIdentity();
  await adoptKey(priv, false);
};
$("mfileKey").addEventListener("change", async (e) => {
  const f = e.target.files[0]; if (!f) return;
  try {
    const txt = (await f.text()).trim();
    const privHex = txt.startsWith("{") ? (JSON.parse(txt).privkey_hex) : txt;
    if (!validPubHex(privHex)) throw new Error("bad keyfile");
    await adoptKey(unhex(privHex), true);
  } catch (err) { toast("Import failed: " + err.message); }
  e.target.value = "";
});

$("mOp").addEventListener("change", () => {
  const op = $("mOp").value;
  document.querySelectorAll("#mcard-op [data-ops]").forEach((lbl) => {
    lbl.classList.toggle("hidden", !lbl.dataset.ops.split(" ").includes(op));
  });
});

$("mbtnBuild").onclick = async () => {
  const res = $("mResult");
  const btn = $("mbtnBuild");
  btn.disabled = true; btn.textContent = "checking state…";
  try {
    if (!S.pub) throw new Error("load a keyfile first");
    const op = $("mOp").value;
    const domain = $("mDomain").value.trim().toLowerCase();
    if (!validDomain(domain)) throw new Error("invalid domain");

    const bound = await idxGet(`/v1.0/resolve/${domain}`).catch(() => null);
    const listed = bound && Number(bound.price) > 0;
    const owner = bound && bound.owner_pubkey;
    const isOwner = owner && owner === hex(S.pub);

    let base, amount, note = "";
    const nonce = Math.floor(Date.now() / 1000);
    const prices = await regPost("/v1.0/prices", { type: "upd" });
    const updFeeZat = Number(prices[String(Math.min(domain.split(".")[0].length, 7))]);

    if (op === "UPD") {
      const target = $("mTargetAddr").value.trim();
      if (!validShielded(target)) throw new Error("invalid target ps1 address");
      if (!bound) throw new Error("name not registered");
      if (!isOwner) throw new Error(`not your name — owner is ${owner ? owner.slice(0, 16) + "…" : "?"}`);
      if (listed) throw new Error("name is LISTED — ULT first (registrar refuses UPD/CHG on listed names)");
      base = `PiNS:1:UPD:${domain}:${target}:${hex(S.pub)}:${nonce}`;
      amount = updFeeZat; note = "changes the resolve address";
    } else if (op === "CHG") {
      const newOwner = $("mNewOwner").value.trim().toLowerCase();
      if (!validPubHex(newOwner)) throw new Error("new owner must be 64-hex pubkey (their keyfile → pubkey)");
      if (!bound) throw new Error("name not registered");
      if (!isOwner) throw new Error(`not your name — owner is ${owner.slice(0, 16)}…`);
      if (newOwner === hex(S.pub)) throw new Error("that's already the owner");
      if (listed) throw new Error("name is LISTED — ULT first");
      base = `PiNS:1:CHG:${domain}:${newOwner}:${nonce}`;
      amount = updFeeZat; note = "transfers ownership — after this YOU lose control, receiver gains it";
    } else if (op === "LST") {
      const piv = parseFloat($("mPrice").value);
      if (!(piv > 0)) throw new Error("set a listing price in PIVX");
      const priceZat = Math.round(piv * 1e8);
      if (!Number.isSafeInteger(priceZat) || priceZat <= 0) throw new Error("price out of range");
      if (!bound) throw new Error("name not registered");
      if (!isOwner) throw new Error(`not your name — owner is ${owner.slice(0, 16)}…`);
      base = `PiNS:1:LST:${domain}:${hex(S.pub)}:${priceZat}:${nonce}`;
      amount = updFeeZat; note = `lists for sale at ${piv} PIVX (memo price) — you PAY the ${zat(updFeeZat)} upd fee`;
    } else if (op === "ULT") {
      if (!bound) throw new Error("name not registered");
      if (!isOwner) throw new Error(`not your name — owner is ${owner.slice(0, 16)}…`);
      if (!listed) throw new Error("not listed — nothing to delist");
      base = `PiNS:1:ULT:${domain}:${hex(S.pub)}:${nonce}`;
      amount = updFeeZat; note = "removes the listing";
    } else if (op === "BUY") {
      const target = $("mTargetAddr").value.trim();
      if (!validShielded(target)) throw new Error("invalid target ps1 address (where the name will point)");
      if (!bound) throw new Error("name not registered");
      if (!listed) throw new Error("not listed for sale");
      if (isOwner) throw new Error("you already own it");
      base = `PiNS:1:BUY:${domain}:${target}:${hex(S.pub)}:${nonce}`;
      amount = Number(bound.price); note = `pays the seller's listed price exactly — sale proceeds go to their registrar balance`;
    }

    const memo = `${base}:${await signMsg(base, S.priv)}`;
    if (!(await selfVerify(memo))) throw new Error("self-verification failed");

    const pay = await regGet("/v1.0/getPaymentAddress");
    const amtPivx = zat(amount);
    const uri = `pivx:${pay.address}?amount=${amtPivx}&memo=${encodeURIComponent(memo).replace(/%3A/g, ":")}`;
    const qr = qrcode(0, "L"); qr.addData(uri); qr.make();

    res.innerHTML = `
      <div class="line good">✓ ${op} ${domain} — ${note}</div>
      <div class="paygrid">
        <div class="payqr" id="mQr"></div>
        <div>
          <label>Send exactly</label>
          <div class="copyrow"><input readonly class="mono" value="${amtPivx} PIVX"><button class="btn tiny copybtn2" data-v="${amtPivx}">copy</button></div>
          <label>To address</label>
          <div class="copyrow"><input readonly class="mono" value="${pay.address}"><button class="btn tiny copybtn2" data-v="${pay.address}">copy</button></div>
          <label>Memo</label>
          <div class="copyrow"><textarea readonly class="mono" rows="4">${memo}</textarea><button class="btn tiny copybtn2" data-v="${memo}">copy</button></div>
        </div>
      </div>`;
    $("mQr").innerHTML = qr.createImgTag(4, 8);
    show(res);
    res.querySelectorAll(".copybtn2").forEach((b) => {
      b.onclick = () => navigator.clipboard.writeText(b.dataset.v).then(() => toast("Copied"));
    });
  } catch (e) {
    res.innerHTML = `<div class="line bad">✗ ${e.message}</div>`;
    show(res);
  } finally { btn.disabled = false; btn.textContent = "Check state & sign"; }
};

// ---------------- tabs ----------------
document.querySelectorAll(".navlink[data-tab]").forEach((a) => {
  a.onclick = (e) => {
    e.preventDefault();
    document.querySelectorAll(".navlink[data-tab]").forEach((x) => x.classList.remove("active"));
    a.classList.add("active");
    document.querySelectorAll(".tab").forEach((t) => hide(t));
    show($(`tab-${a.dataset.tab}`));
  };
});
