import test from "node:test"; import assert from "node:assert/strict";
import { ops, argon2 } from "../public/ops/hashing3.js";
const run = async (k, i, a = {}) => { const o = ops[k]; const d = Object.fromEntries((o.args || []).map((x) => [x.name, x.default ?? (x.type === "checkbox" ? false : x.options ? x.options[0] : "")])); return String(await o.run(i, { ...d, ...a })); };
const hex = (s) => Uint8Array.from(s.match(/../g).map((x) => parseInt(x, 16)));
test("digest vectors", async () => {
  assert.equal(await run("sha0", "abc"), "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");
  assert.equal(await run("sm3", "abc"), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
  assert.equal(await run("whirlpool", ""), "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
  assert.equal(await run("whirlpool", "abc"), "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5");
  assert.equal(await run("blake3", ""), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
  assert.equal(await run("blake3", "abc"), "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
  const big = "a".repeat(5000); assert.equal((await run("blake3", big)).length, 64); // multi-chunk tree path
  assert.equal(await run("lm-hash", "password"), "E52CAC67419A9A224A3B108F3FA6CB6D");
});
test("Argon2id RFC 9106 test vector", () => {
  const tag = argon2(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), { t: 3, m: 32, p: 4, len: 32, type: "argon2id", secret: new Uint8Array(8).fill(3), ad: new Uint8Array(12).fill(4) });
  assert.equal(Buffer.from(tag).toString("hex"), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
  const tagI = argon2(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), { t: 3, m: 32, p: 4, len: 32, type: "argon2i", secret: new Uint8Array(8).fill(3), ad: new Uint8Array(12).fill(4) });
  assert.equal(Buffer.from(tagI).toString("hex"), "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8");
  const tagD = argon2(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), { t: 3, m: 32, p: 4, len: 32, type: "argon2d", secret: new Uint8Array(8).fill(3), ad: new Uint8Array(12).fill(4) });
  assert.equal(Buffer.from(tagD).toString("hex"), "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb");
});
test("Argon2 encode/compare round-trip and SSDEEP behaviour", async () => {
  const enc = (await run("argon2", "pw", { m: 64, t: 2 })).split("\n")[0];
  assert.match(await run("argon2-compare", "pw", { hash: enc }), /MATCHES/); assert.match(await run("argon2-compare", "px", { hash: enc }), /NOT/);
  const { randomBytes } = await import("node:crypto"); const base = randomBytes(20000); const edited = Buffer.from(base); edited[10000] ^= 1;
  const h1 = await ops.ssdeep.run({ bytes: base }); const h2 = await ops.ssdeep.run({ bytes: edited }); const h3 = await ops.ssdeep.run({ bytes: randomBytes(20000) });
  assert.match(h1, /^\d+:[A-Za-z0-9+/]+:[A-Za-z0-9+/]*$/);
  assert.equal(await run("ssdeep-compare", h1, { other: h1 }), "Similarity score: 100 / 100");
  assert.ok(+(await run("ssdeep-compare", h1, { other: h2 })).match(/\d+/)[0] >= 80, "one flipped byte stays very similar");
  assert.equal(await run("ssdeep-compare", h1, { other: h3 }), "Similarity score: 0 / 100");
  assert.equal(await ops.ssdeep.run({ bytes: new Uint8Array() }), "3::");
});
