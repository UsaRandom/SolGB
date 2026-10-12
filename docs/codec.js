globalThis.SolCodec = (function () {
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const LAMPORTS_PER_SOL = 1_000_000_000n;
const FORMAT_VERSION = 0x03;
const PAYLOAD_LEN = 105;
const MAX_GROUPS = 48;
/* SysvarRecentB1ockHashes11111111111111111111. The advance instruction
   names this account. The 1 in B1ock is part of the address. */
const SYSVAR_RECENT = new Uint8Array([
  0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
  0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
  0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
  0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
]);
const SYSTEM_PROGRAM = new Uint8Array(32);
const SIG_PAGE_DATA = 51;
const SIG_PAGE_MAX = 7;
const ADDRESS_RUN = /[1-9A-HJ-NP-Za-km-z]{32,44}/;

function alphabetIndex(ch) {
  const i = ALPHABET.indexOf(ch);
  if (i < 0) throw new Error("Character " + ch + " is not on the base58 keyboard.");
  return i;
}

function b58encode(data) {
  let n = 0n;
  for (const b of data) n = (n << 8n) + BigInt(b);
  let out = "";
  while (n > 0n) {
    const r = n % 58n;
    n /= 58n;
    out = ALPHABET[Number(r)] + out;
  }
  for (const b of data) {
    if (b === 0) out = "1" + out;
    else break;
  }
  return out || "1";
}

function b58decode(text) {
  let n = 0n;
  for (const ch of text) n = n * 58n + BigInt(alphabetIndex(ch));
  const body = [];
  while (n > 0n) {
    body.push(Number(n & 0xffn));
    n >>= 8n;
  }
  body.reverse();
  let zeros = 0;
  for (const ch of text) {
    if (ch === "1") zeros++;
    else break;
  }
  const raw = new Uint8Array(zeros + body.length);
  raw.set(body, zeros);
  return raw;
}

async function sha256(data) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

async function sha256d(data) {
  return sha256(await sha256(data));
}

function bytesEq(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function keyBytes(text) {
  const raw = b58decode(String(text).trim());
  if (raw.length !== 32) throw new Error("Address is not 32 bytes.");
  return raw;
}

function extractPayment(raw) {
  let text = String(raw).replace(/\0/g, " ").trim();
  let amount = null;
  const uri = text.match(/solana:([^?\s]+)(?:\?(\S+))?/i);
  if (uri) {
    text = decodeURIComponent(uri[1]);
    if (uri[2]) {
      const amountText = new URLSearchParams(uri[2]).get("amount");
      if (amountText) amount = amountText;
    }
  }
  const found = text.match(ADDRESS_RUN);
  if (!found) throw new Error("That code is not a Solana address.");
  keyBytes(found[0]);
  return { address: found[0], amount };
}

function decodeAddress(text) {
  const trimmed = String(text).trim();
  const pubkey = keyBytes(trimmed);
  return { text: trimmed, pubkey };
}

function solToLamports(text) {
  const s = String(text).trim();
  if (!/^\d+(\.\d{0,9})?$/.test(s)) {
    throw new Error("Amount must be a SOL number with at most 9 decimals.");
  }
  const [whole, frac = ""] = s.split(".");
  const padded = (frac + "000000000").slice(0, 9);
  return BigInt(whole) * LAMPORTS_PER_SOL + BigInt(padded);
}

function formatSol(lamports) {
  const neg = lamports < 0n;
  const v = neg ? -lamports : lamports;
  const whole = v / LAMPORTS_PER_SOL;
  const frac = (v % LAMPORTS_PER_SOL).toString().padStart(9, "0");
  return (neg ? "-" : "") + whole.toString() + "." + frac;
}

function writeU64(out, at, n) {
  let x = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out[at + i] = Number(x & 0xffn);
    x >>= 8n;
  }
}

function readU64(bytes, at) {
  let n = 0n;
  for (let i = 7; i >= 0; i--) n = (n << 8n) + BigInt(bytes[at + i]);
  return n;
}

function anyByte(bytes) {
  let z = 0;
  for (const b of bytes) z |= b;
  return z !== 0;
}

function encodePayload(payment) {
  if (payment.lamports <= 0n) throw new Error("Amount must be more than 0.");
  if (!payment.dest || payment.dest.length !== 32) {
    throw new Error("Destination is not 32 bytes.");
  }
  if (!payment.nonceAccount || payment.nonceAccount.length !== 32) {
    throw new Error("Nonce account is not 32 bytes.");
  }
  if (!payment.nonce || payment.nonce.length !== 32) {
    throw new Error("Nonce is not 32 bytes.");
  }
  if (!anyByte(payment.dest)) throw new Error("That address is not a wallet.");
  if (!anyByte(payment.nonceAccount) || !anyByte(payment.nonce)) {
    throw new Error("That nonce is empty.");
  }
  const out = new Uint8Array(PAYLOAD_LEN);
  out[0] = FORMAT_VERSION;
  writeU64(out, 1, payment.lamports);
  out.set(payment.dest, 9);
  out.set(payment.nonceAccount, 41);
  out.set(payment.nonce, 73);
  return out;
}

function decodePayload(bytes) {
  if (bytes.length < 1 || bytes[0] !== FORMAT_VERSION) {
    throw new Error("String from old app, reload signgb.app");
  }
  if (bytes.length !== PAYLOAD_LEN) {
    throw new Error("Payment payload is the wrong length.");
  }
  const lamports = readU64(bytes, 1);
  const dest = bytes.slice(9, 41);
  const nonceAccount = bytes.slice(41, 73);
  const nonce = bytes.slice(73, 105);
  if (lamports <= 0n) throw new Error("Amount must be more than 0.");
  if (!anyByte(dest)) throw new Error("That address is not a wallet.");
  if (!anyByte(nonceAccount) || !anyByte(nonce)) throw new Error("That nonce is empty.");
  return { lamports, dest, nonceAccount, nonce };
}

function sumIndex(chunk) {
  let sum = 0;
  for (const ch of chunk) sum += alphabetIndex(ch);
  return sum;
}

function checkChar(chunk, delta) {
  return ALPHABET[(sumIndex(chunk) + delta) % 58];
}

function groupDelta(group) {
  if (group.length !== 8) throw new Error("A group must be 8 characters.");
  const got = alphabetIndex(group[7]);
  const expect = sumIndex(group.slice(0, 7)) % 58;
  return (got - expect + 58) % 58;
}

function encodeFixed(bytes, width) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) + BigInt(b);
  let out = "";
  for (let i = 0; i < width; i++) {
    const r = n % 58n;
    n /= 58n;
    out = ALPHABET[Number(r)] + out;
  }
  if (n !== 0n) throw new Error("End hash does not fit.");
  return out;
}

function decodeFixed(text, nbytes) {
  let n = 0n;
  for (const ch of text) n = n * 58n + BigInt(alphabetIndex(ch));
  const out = new Uint8Array(nbytes);
  for (let i = nbytes - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  if (n !== 0n) throw new Error("End check is too large.");
  return out;
}

async function wireEncode(payload) {
  if (!(payload instanceof Uint8Array)) payload = Uint8Array.from(payload);
  if (payload.length < 1 || payload[0] === 0) throw new Error("Version byte is zero.");
  const d = b58encode(payload);
  const n = Math.ceil((d.length + 9) / 7);
  if (n < 2 || n > MAX_GROUPS) throw new Error("String is the wrong length.");
  const pad = 7 * n - 9 - d.length;
  const hashText = encodeFixed((await sha256d(payload)).slice(0, 5), 7);
  const body = ALPHABET[(n / 58) | 0] + ALPHABET[n % 58] + "1".repeat(pad) + d + hashText;
  if (body.length !== 7 * n) throw new Error("String is the wrong length.");
  const groups = [];
  for (let i = 0; i < n; i++) {
    const chunk = body.slice(i * 7, i * 7 + 7);
    groups.push(chunk + checkChar(chunk, 0));
  }
  return groups;
}

async function encodeString(payment) {
  const payload = encodePayload(payment);
  const groups = await wireEncode(payload);
  return {
    payload,
    groups,
    hashBytes: 5,
    typedCount: groups.length * 8,
  };
}

function stripTyped(text) {
  return text.replace(/\s+/g, "");
}

async function wireDecode(text) {
  const raw = stripTyped(text);
  if (raw.length < 16 || raw.length % 8 !== 0) throw new Error("String length is wrong.");
  const count = raw.length / 8;
  for (let i = 0; i < count; i++) {
    const group = raw.slice(i * 8, i * 8 + 8);
    if (groupDelta(group) !== 0) throw new Error("Group " + (i + 1) + " does not check.");
  }
  const n = alphabetIndex(raw[0]) * 58 + alphabetIndex(raw[1]);
  if (n !== count) throw new Error("String length is wrong.");
  let body = "";
  for (let i = 0; i < count; i++) body += raw.slice(i * 8, i * 8 + 7);
  const decoded = b58decode(body.slice(2, -7));
  let skip = 0;
  while (skip < decoded.length && decoded[skip] === 0) skip++;
  const payload = decoded.slice(skip);
  if (payload.length === 0) throw new Error("String ended early.");
  const got = decodeFixed(body.slice(-7), 5);
  const want = (await sha256d(payload)).slice(0, 5);
  for (let i = 0; i < 5; i++) {
    if (want[i] !== got[i]) throw new Error("The end check does not match.");
  }
  return payload;
}

async function decodeString(text) {
  const payload = await wireDecode(text);
  if (payload[0] !== FORMAT_VERSION) throw new Error("String from old app, reload signgb.app");
  return decodePayload(payload);
}

/* Legacy durable-nonce transfer. AdvanceNonceAccount is first, and the
   recent-blockhash field is the nonce value. One signature: the wallet,
   which is the fee payer and the nonce authority. */
function transferMessage(walletPub, destPub, nonceAccount, nonce, lamports) {
  if (walletPub.length !== 32 || destPub.length !== 32 ||
      nonceAccount.length !== 32 || nonce.length !== 32) {
    throw new Error("A transfer field is the wrong length.");
  }
  const keys = [];
  const add = (pub, signer, writable) => {
    for (const key of keys) {
      if (!bytesEq(key.pub, pub)) continue;
      key.signer = key.signer || signer;
      key.writable = key.writable || writable;
      return;
    }
    keys.push({ pub, signer, writable });
  };
  add(nonceAccount, false, true);
  add(SYSVAR_RECENT, false, false);
  add(walletPub, true, true);
  add(SYSTEM_PROGRAM, false, false);
  add(destPub, false, true);
  const signerW = keys.filter((k) => k.signer && k.writable);
  const signerR = keys.filter((k) => k.signer && !k.writable);
  const plainW = keys.filter((k) => !k.signer && k.writable);
  const plainR = keys.filter((k) => !k.signer && !k.writable);
  const ordered = signerW.concat(signerR, plainW, plainR);
  const at = (pub) => {
    for (let i = 0; i < ordered.length; i++) {
      if (bytesEq(ordered[i].pub, pub)) return i;
    }
    throw new Error("A transfer account is missing.");
  };
  const msg = new Uint8Array(3 + 1 + ordered.length * 32 + 32 + 1 + 10 + 17);
  let o = 0;
  msg[o++] = signerW.length + signerR.length;
  msg[o++] = signerR.length;
  msg[o++] = plainR.length;
  msg[o++] = ordered.length;
  for (const key of ordered) {
    msg.set(key.pub, o);
    o += 32;
  }
  msg.set(nonce, o); o += 32;
  msg[o++] = 2;
  msg[o++] = at(SYSTEM_PROGRAM);
  msg[o++] = 3;
  msg[o++] = at(nonceAccount);
  msg[o++] = at(SYSVAR_RECENT);
  msg[o++] = at(walletPub);
  msg[o++] = 4;
  msg[o++] = 4;
  msg[o++] = 0;
  msg[o++] = 0;
  msg[o++] = 0;
  msg[o++] = at(SYSTEM_PROGRAM);
  msg[o++] = 2;
  msg[o++] = at(walletPub);
  msg[o++] = at(destPub);
  msg[o++] = 12;
  msg[o++] = 2;
  msg[o++] = 0;
  msg[o++] = 0;
  msg[o++] = 0;
  writeU64(msg, o, lamports);
  return msg;
}

function buildSignedTx(payment, blob) {
  if (!blob || blob.length !== 96) {
    throw new Error("The codes do not match this payment.");
  }
  const pub = blob.slice(0, 32);
  const sig = blob.slice(32, 96);
  if (!bytesEq(pub, payment.walletPub)) throw new Error("That key is not this Game Boy.");
  const msg = transferMessage(
    pub, payment.dest, payment.nonceAccount, payment.nonce, payment.lamports
  );
  const wire = new Uint8Array(1 + 64 + msg.length);
  wire[0] = 1;
  wire.set(sig, 1);
  wire.set(msg, 65);
  return wire;
}

function parseSigPage(bytes) {
  if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
  if (bytes.length < 3 || bytes.length > SIG_PAGE_DATA + 2) {
    throw new Error("That code is not a signed page.");
  }
  const page = bytes[0];
  const count = bytes[1];
  if (count < 1 || count > SIG_PAGE_MAX || page >= count) {
    throw new Error("That code is not a signed page.");
  }
  const data = bytes.slice(2);
  if (data.length === 0 || (page + 1 < count && data.length !== SIG_PAGE_DATA)) {
    throw new Error("That code is not a signed page.");
  }
  return { page, count, data };
}

function assembleSigBlob(pages) {
  if (!pages.length) throw new Error("Scan the signed codes.");
  const count = pages[0].count;
  if (pages.length !== count) throw new Error("Scan every signed code.");
  const got = new Array(count);
  for (const part of pages) {
    if (part.count !== count || part.page >= count || got[part.page]) {
      throw new Error("Those codes are not one set.");
    }
    if (part.page + 1 < count && part.data.length !== SIG_PAGE_DATA) {
      throw new Error("That code is not a signed page.");
    }
    got[part.page] = part.data;
  }
  let n = 0;
  for (const part of got) n += part.length;
  const blob = new Uint8Array(n);
  let at = 0;
  for (const part of got) {
    blob.set(part, at);
    at += part.length;
  }
  return blob;
}

function bytesToBase64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

return {
  ALPHABET,
  LAMPORTS_PER_SOL,
  FORMAT_VERSION,
  MAX_GROUPS,
  alphabetIndex,
  b58encode,
  b58decode,
  sha256d,
  extractPayment,
  decodeAddress,
  solToLamports,
  formatSol,
  encodePayload,
  decodePayload,
  encodeString,
  stripTyped,
  decodeString,
  wireEncode,
  wireDecode,
  transferMessage,
  parseSigPage,
  assembleSigBlob,
  buildSignedTx,
  bytesToBase64,
};
})();
