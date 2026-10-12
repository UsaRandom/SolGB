globalThis.SolCodec = (function () {
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const LAMPORTS_PER_SOL = 1_000_000_000n;
const FORMAT_VERSION = 0x02;
const PAYLOAD_LEN = 105;
/* SysvarRecentB1ockHashes11111111111111111111. The advance instruction
   names this account. The 1 in B1ock is part of the address. */
const SYSVAR_RECENT = new Uint8Array([
  0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
  0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
  0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
  0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
]);
const SYSTEM_PROGRAM = new Uint8Array(32);
// Hash characters available for leftover counts 0..6, then the most bytes
// that still fit in that many base58 digits.
const HASH_CHARS = [7, 6, 12, 11, 10, 9, 8];
const HASH_BYTES = [5, 4, 8, 8, 7, 6, 5];
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
  if (bytes.length !== PAYLOAD_LEN || bytes[0] !== FORMAT_VERSION) {
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

function encodeGroups(dataChars, hashBytes) {
  const r = dataChars.length % 7;
  const groups = [];
  const full = dataChars.slice(0, dataChars.length - r);
  for (let i = 0; i < full.length; i += 7) {
    const chunk = full.slice(i, i + 7);
    groups.push(chunk + checkChar(chunk, 0));
  }
  const hashText = encodeFixed(hashBytes, HASH_CHARS[r]);
  if (r <= 1) {
    const line = dataChars.slice(full.length) + hashText;
    groups.push(line + checkChar(line, r + 1));
    return groups;
  }
  const firstHash = 7 - r;
  const line = dataChars.slice(full.length) + hashText.slice(0, firstHash);
  const rest = hashText.slice(firstHash);
  groups.push(line + checkChar(line, r + 1));
  groups.push(rest + checkChar(rest, 0));
  return groups;
}

async function encodeString(payment) {
  const payload = encodePayload(payment);
  const dataChars = b58encode(payload);
  const r = dataChars.length % 7;
  const hashBytes = HASH_BYTES[r];
  const groups = encodeGroups(dataChars, (await sha256d(payload)).slice(0, hashBytes));
  return {
    payload,
    groups,
    hashBytes,
    typedCount: groups.length * 8,
  };
}

function stripTyped(text) {
  return text.replace(/\s+/g, "");
}

async function decodeString(text) {
  const raw = stripTyped(text);
  if (raw.length < 8 || raw.length % 8 !== 0) throw new Error("String length is wrong.");
  let data = "";
  let hashText = null;
  let hashBytes = 0;
  let i = 0;
  let groupNo = 1;
  while (i < raw.length) {
    if (hashText !== null) throw new Error("String has extra characters.");
    const group = raw.slice(i, i + 8);
    const delta = groupDelta(group);
    if (delta === 0) {
      data += group.slice(0, 7);
      i += 8;
      groupNo++;
      continue;
    }
    if (delta > 7) throw new Error("Group " + groupNo + " does not check.");
    const r = delta - 1;
    data += group.slice(0, r);
    hashText = group.slice(r, 7);
    i += 8;
    groupNo++;
    if (r >= 2) {
      if (i >= raw.length) throw new Error("The end check is cut off.");
      const next = raw.slice(i, i + 8);
      if (groupDelta(next) !== 0) throw new Error("Group " + groupNo + " does not check.");
      hashText += next.slice(0, 7);
      i += 8;
    }
    if (hashText.length !== HASH_CHARS[r]) throw new Error("The end check is the wrong length.");
    hashBytes = HASH_BYTES[r];
  }
  if (hashText === null) throw new Error("The end check is missing.");
  const payload = b58decode(data);
  const got = decodeFixed(hashText, hashBytes);
  const want = (await sha256d(payload)).slice(0, hashBytes);
  for (let b = 0; b < hashBytes; b++) {
    if (want[b] !== got[b]) throw new Error("The end check does not match.");
  }
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
  HASH_CHARS,
  HASH_BYTES,
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
  transferMessage,
  parseSigPage,
  assembleSigBlob,
  buildSignedTx,
  bytesToBase64,
};
})();
