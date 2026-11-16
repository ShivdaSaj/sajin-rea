import test from "node:test"; import assert from "node:assert/strict";
import { ops, piHex } from "../public/ops/blocks.js";
const run = async (k, i, a = {}) => { const o = ops[k]; const d = Object.fromEntries((o.args || []).map((x) => [x.name, x.default ?? (x.type === "checkbox" ? false : x.options ? x.options[0] : "")])); return String(await o.run(i, { ...d, ...a })); };
const PT = "Attack at dawn!!";
test("π hex digits", () => { assert.equal(piHex(16), "243f6a8885a308d3"); });
test("DES / 3DES / Blowfish match published vectors and OpenSSL", async () => {
  assert.equal(await run("des-encrypt", "0123456789ABCDEF", { key: "133457799BBCDFF1", mode: "ECB", padding: "None", inputEncoding: "Hex" }), "85e813540f0ab405");
  assert.equal(await run("des-encrypt", PT, { key: "0123456789abcdef", mode: "ECB" }), "3c6ce1d3edf97e427859f4917bab46bf086f9a1d74c94d4e");
  const k3 = "0123456789abcdeffedcba98765432100123456789abcdef";
  assert.equal(await run("3des-encrypt", PT, { key: k3, iv: "0001020304050607" }), "e9a313ff10489efef7a91ecd414abe9e5d44e46534d24dda");
  assert.equal(await run("3des-decrypt", "e9a313ff10489efef7a91ecd414abe9e5d44e46534d24dda", { key: k3, iv: "0001020304050607" }), PT);
  assert.equal(await run("3des-encrypt", PT, { key: k3, iv: "0001020304050607", mode: "OFB", padding: "None" }), "13b1b4113efba980b6902b543a2818a4");
  assert.equal(await run("blowfish-encrypt", "0000000000000000", { key: "0000000000000000", mode: "ECB", padding: "None", inputEncoding: "Hex" }), "4ef997456198dd78");
  assert.equal(await run("blowfish-encrypt", PT, { key: "0123456789abcdeff0e1d2c3b4a59687", iv: "0001020304050607" }), "ab0b26b3c2c4ed1e40e806a970209560bb2f4806d692c39a");
  assert.equal(await run("blowfish-decrypt", "ab0b26b3c2c4ed1e40e806a970209560bb2f4806d692c39a", { key: "0123456789abcdeff0e1d2c3b4a59687", iv: "0001020304050607" }), PT);
});
test("RC6, PRESENT, Rabbit", async () => {
  assert.equal(await run("rc6-encrypt", "00000000000000000000000000000000", { key: "00000000000000000000000000000000", mode: "ECB", padding: "None", inputEncoding: "Hex" }), "8fc3a53656b1f778c129df4e9848a41e");
  assert.equal(await run("present-encrypt", "0000000000000000", { mode: "ECB", padding: "None", inputEncoding: "Hex" }), "5579c1387b228445");
  assert.equal(await run("present-encrypt", "0000000000000000", { key: "ffffffffffffffffffff", mode: "ECB", padding: "None", inputEncoding: "Hex" }), "e72c46c0f5945049");
  for (const k of ["rc6", "present"]) { const ct = await run(`${k}-encrypt`, PT, { mode: "CBC" }); assert.equal(await run(`${k}-decrypt`, ct, { mode: "CBC" }), PT, k); }
  // RFC 4503 A.1 prints S[0] as a 128-bit number (B1 57 … F7 02, MSB first); the byte stream is little-endian, as in the eSTREAM vectors.
  assert.match(await run("rabbit", "00000000000000000000000000000000", { inputEncoding: "Hex" }), /^02f74a1c26456bf5ecd6a536f05457b1/);
  assert.equal(await run("rabbit", await run("rabbit", PT, { key: "000102030405060708090a0b0c0d0e0f", iv: "0001020304050607" }), { key: "000102030405060708090a0b0c0d0e0f", iv: "0001020304050607", inputEncoding: "Hex", output: "Raw" }), PT);
});
test("bcrypt (OpenBSD vectors) and OpenSSL EVP_BytesToKey", async () => {
  const { bcrypt, bcryptParse } = await import("../public/ops/blocks.js");
  const p = bcryptParse("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW");
  assert.equal(bcrypt("U*U", 5, p.salt, "a"), "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW");
  assert.match(await run("bcrypt-compare", "U*U", { hash: "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" }), /MATCHES/);
  assert.match(await run("bcrypt-compare", "U*V", { hash: "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" }), /does NOT/);
  const h = await run("bcrypt-hash", "hunter2", { cost: 4 }); assert.match(h, /^\$2b\$04\$/); assert.match(await run("bcrypt-compare", "hunter2", { hash: h }), /MATCHES/);
  assert.equal(await run("evp-key", "secretpass"), "Key: 9bf1d7cfc1b3d0e34bdf3413400fa05ee2848ec653f36bc28d078ae971d9e26c\nIV:  c416993bb9786b2cd8608a0a83b513ee");
});
