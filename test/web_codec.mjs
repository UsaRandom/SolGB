import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const sandbox = vm.createContext({
  crypto: globalThis.crypto,
  URLSearchParams: globalThis.URLSearchParams,
  btoa: (s) => Buffer.from(s, "binary").toString("base64"),
});
vm.runInContext(
  readFileSync(new URL("../docs/codec.js", import.meta.url), "utf8"),
  sandbox,
  { filename: "codec.js" }
);
const {
  decodeAddress,
  decodeString,
  solToLamports,
  encodeString,
  wireEncode,
  wireDecode,
  extractPayment,
  formatSol,
  assembleSigBlob,
  buildSignedTx,
  parseSigPage,
  transferMessage,
} = sandbox.SolCodec;

const known = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const knownPub = "f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7";
assert.equal(extractPayment(known).address, known);
assert.equal(extractPayment("  " + known + "\n").address, known);
assert.equal(extractPayment("solana:" + known + "?amount=1.5").amount, "1.5");
assert.equal(extractPayment("\0" + known).address, known);
assert.throws(() => extractPayment("hello"), /not a Solana/);

const addr = decodeAddress(known);
assert.equal(addr.text, known);
assert.equal(
  [...addr.pubkey].map((b) => b.toString(16).padStart(2, "0")).join(""),
  knownPub
);

assert.equal(solToLamports("1"), 1_000_000_000n);
assert.equal(solToLamports("1.5"), 1_500_000_000n);
assert.equal(solToLamports("0.000000001"), 1n);
assert.equal(formatSol(1_000_000_000n), "1.000000000");
assert.throws(() => solToLamports("1.1234567890"), /9 decimals/);

const dest = new Uint8Array(32).fill(0x22);
const nonceAccount = new Uint8Array(32).fill(0x55);
const nonce = new Uint8Array(32).fill(0x33);
const lamports = 1_500_000_000n;
const payment = { lamports, dest, nonceAccount, nonce };
const encoded = await encodeString(payment);
assert.equal(encoded.payload[0], 0x03);
assert.equal(encoded.payload.length, 105);
assert.equal(encoded.groups.length, 22);
assert.equal(encoded.hashBytes, 5);
assert.equal(encoded.typedCount, 176);
assert.ok(encoded.groups.every((g) => g.length === 8));
const back = await decodeString(encoded.groups.join(""));
assert.equal(back.lamports, lamports);
assert.equal(Buffer.from(back.dest).toString("hex"), Buffer.from(dest).toString("hex"));
assert.equal(Buffer.from(back.nonceAccount).toString("hex"), Buffer.from(nonceAccount).toString("hex"));
assert.equal(Buffer.from(back.nonce).toString("hex"), Buffer.from(nonce).toString("hex"));

const chars = encoded.groups[0].split("");
const swap = chars.slice();
const tmp = swap[0];
swap[0] = swap[1];
swap[1] = tmp;
const swapped = swap.join("") + encoded.groups.slice(1).join("");
await assert.rejects(decodeString(swapped), /String length is wrong|end check|does not check/);

const bad = chars.slice();
const nextCh = bad[0] === "2" ? "3" : "2";
bad[0] = nextCh;
const substituted = bad.join("") + encoded.groups.slice(1).join("");
await assert.rejects(decodeString(substituted), /Group 1 does not check/);

const slipped = encoded.groups.slice();
const slipChars = slipped[18].split("");
slipChars[7] = slipChars[7] === "E" ? "D" : "E";
slipped[18] = slipChars.join("");
await assert.rejects(decodeString(slipped.join("")), /Group 19 does not check/);

const vectorPayload = Buffer.from(
  "030faeab7cad092b33f79ee571edaf6bc756e95f749304fefed025820cdaef25" +
  "84b3100bedb47e2a67552727800804070864f69b704d9405666c1f7a6c4c448d" +
  "c81fed75ca7bf8df57ec2524829cca7999c510c378467921028f8951c841e7d7" +
  "646ce2ff034365be1f",
  "hex"
);
const vectorGroups = (
  "1P114SJA TQX1q7dv Xedziw3S QKcokA11 NwVuk6sN A91RthRh " +
  "GUgXTJM1 9mXE6D4z 7rf9fT2s bhyRkRaP uPDYuaqK xzZCz6cM " +
  "zoCqdBGr 3qe3fFPp 5bD95r72 YriDimrc Te8Ei9AS zyyP6vi1 " +
  "n1AJwrcc WLLQFfFh ywNSRtzy L7sQVCm8"
).split(/\s+/);
assert.equal((await wireEncode(vectorPayload)).join(" "), vectorGroups.join(" "));
assert.equal(
  Buffer.from(await wireDecode(vectorGroups.join(""))).toString("hex"),
  vectorPayload.toString("hex")
);

const oldPayload = new Uint8Array(encoded.payload);
oldPayload[0] = 0x02;
await assert.rejects(decodeString((await wireEncode(oldPayload)).join("")), /old app/);

const spaced = encoded.groups.join("  ");
const fromSpaces = await decodeString(spaced);
assert.equal(fromSpaces.lamports, lamports);

const pub = new Uint8Array(32).fill(0x11);
const sysvar = Buffer.from([
  0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
  0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
  0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
  0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00,
]);
const message = transferMessage(pub, dest, nonceAccount, nonce, lamports);
assert.equal(message.length, 224);
const expectMsg = Buffer.concat([
  Buffer.from([0x01, 0x00, 0x02, 0x05]),
  Buffer.from(pub),
  Buffer.from(nonceAccount),
  Buffer.from(dest),
  sysvar,
  Buffer.alloc(32),
  Buffer.from(nonce),
  Buffer.from([
    0x02,
    0x04, 0x03, 0x01, 0x03, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00,
    0x04, 0x02, 0x00, 0x02, 0x0c, 0x02, 0x00, 0x00, 0x00,
  ]),
  Buffer.from([0x00, 0x2f, 0x68, 0x59, 0x00, 0x00, 0x00, 0x00]),
]);
assert.equal(Buffer.from(message).toString("hex"), expectMsg.toString("hex"));

const selfMsg = transferMessage(pub, pub, nonceAccount, nonce, lamports);
assert.equal(selfMsg.length, 192);
assert.equal(selfMsg[3], 4);
assert.equal(selfMsg[3 + 1 + 32 * 4 + 32], 2);
assert.equal(selfMsg[3 + 1 + 32 * 4 + 32 + 1 + 10 + 3], 0);

const intoNonce = transferMessage(pub, nonceAccount, nonceAccount, nonce, lamports);
assert.equal(intoNonce.length, 192);
assert.equal(intoNonce[3 + 1 + 32 * 4 + 32 + 1 + 10 + 3], 1);

const sig = new Uint8Array(64).fill(0x44);
const blob = new Uint8Array(96);
blob.set(pub, 0);
blob.set(sig, 32);
const wire = buildSignedTx({
  walletPub: pub, dest, nonceAccount, nonce, lamports,
}, blob);
assert.equal(wire.length, 289);
assert.equal(wire[0], 1);
assert.equal(Buffer.from(wire.slice(1, 65)).toString("hex"), Buffer.from(sig).toString("hex"));
assert.equal(Buffer.from(wire.slice(65)).toString("hex"), expectMsg.toString("hex"));

const wrong = pub.slice();
wrong[0] ^= 1;
assert.throws(() => buildSignedTx({
  walletPub: wrong, dest, nonceAccount, nonce, lamports,
}, blob), /not this Game Boy/);

const page0 = new Uint8Array(53);
page0[0] = 0;
page0[1] = 2;
page0.set(blob.slice(0, 51), 2);
const page1 = new Uint8Array(2 + 45);
page1[0] = 1;
page1[1] = 2;
page1.set(blob.slice(51), 2);
const joined = assembleSigBlob([parseSigPage(page1), parseSigPage(page0)]);
assert.equal(Buffer.from(joined).toString("hex"), Buffer.from(blob).toString("hex"));
assert.throws(() => parseSigPage(page0.slice(0, 52)), /not a signed page/);
assert.throws(() => parseSigPage(Uint8Array.from([0, 9, 1, 2, 3])), /not a signed page/);

console.log("web codec ok", encoded.typedCount, "chars", encoded.groups.length, "groups");
