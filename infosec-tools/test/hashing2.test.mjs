import test from "node:test"; import assert from "node:assert/strict";
import { ops } from "../public/ops/hashing2.js";
const run = async (k, i, a = {}) => { const o = ops[k]; const d = Object.fromEntries((o.args || []).map((x) => [x.name, x.default ?? (x.type === "checkbox" ? false : x.options ? x.options[0] : "")])); return String(await o.run(i, { ...d, ...a })); };
test("SHA-3 / Keccak / SHAKE vectors", async () => {
  assert.equal(await run("sha3", ""), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
  assert.equal(await run("sha3", "abc"), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
  assert.equal(await run("sha3", "abc", { size: "512" }), "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
  assert.equal(await run("keccak", ""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(await run("shake", "", { capacity: "128", length: 32 }), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
});
test("MD4 / NT / RIPEMD-160 / BLAKE2 vectors", async () => {
  assert.equal(await run("md4", "abc"), "a448017aaf21d8525fc10ae87aa6729d");
  assert.equal(await run("nt-hash", "password"), "8846F7EAEE8FB117AD06BDD830B7586C");
  assert.equal(await run("ripemd160", "abc"), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
  assert.equal(await run("ripemd160", ""), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
  assert.equal(await run("blake2b", "abc"), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
  assert.equal(await run("blake2s", "abc"), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
});
test("checksums", async () => {
  assert.equal(await run("crc-any", "123456789", { algorithm: "CRC-32" }), "cbf43926");
  assert.equal(await run("crc-any", "123456789", { algorithm: "CRC-32C" }), "e3069283");
  assert.equal(await run("crc-any", "123456789", { algorithm: "CRC-16/CCITT-FALSE" }), "29b1");
  assert.equal(await run("crc-any", "123456789", { algorithm: "CRC-16/MODBUS" }), "4b37");
  assert.equal(await run("crc-any", "123456789", { algorithm: "CRC-8" }), "f4");
  assert.equal(await run("fletcher", "abcde", { bits: "16" }), "c8f0");
  assert.equal(await run("fletcher", "abcde", { bits: "32" }), "f04fc729");
  assert.match(await run("murmur3", "hello"), /^hex: 248bfa47/);
  assert.equal(await run("inet-checksum", "4500003c1c4640004006 0000ac100a63ac100a0c".replace(/ /g, "")), "b1e6");
  assert.equal(await run("cmac", "6bc1bee22e409f96e93d7e117393172a"), "070a16b46b4d4144f79bdd9dd04a287c");
  assert.equal(await run("cmac", ""), "bb1d6929e95937287fa37d129b756746");
});
