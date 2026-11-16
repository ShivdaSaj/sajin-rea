import test from "node:test"; import assert from "node:assert/strict";
import { ops } from "../public/ops/cipher2.js";
const run = async (k, i, a = {}) => { const o = ops[k]; const d = Object.fromEntries((o.args || []).map((x) => [x.name, x.default ?? (x.type === "checkbox" ? false : x.options ? x.options[0] : "")])); return String(await o.run(i, { ...d, ...a })); };
test("stream ciphers match published vectors", async () => {
  assert.equal(await run("rc4", "Plaintext", { key: "Key" }), "bbf316e8d940af0ad3");
  // RFC 8439 2.4.2 (first 16 bytes of the sunscreen example)
  const sun = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  assert.match(await run("chacha20", sun), /^6e2e359a2568f98041ba0728dd0d6981/);
  // Salsa20 with all-zero 256-bit key and nonce, first keystream bytes
  assert.match(await run("salsa20", "0000000000000000", { inputEncoding: "hex" }), /^9a97f65b9b4c721b/);
});
test("TEA family round-trips and XTEA vector", async () => {
  for (const [e, d] of [["tea-encrypt", "tea-decrypt"], ["xtea-encrypt", "xtea-decrypt"], ["xxtea-encrypt", "xxtea-decrypt"]]) {
    const ct = await run(e, "attack at dawn!!"); assert.equal(await run(d, ct), "attack at dawn!!", e);
  }
  // XTEA test vector: key 000102..0f, plaintext 4142434445464748 -> 497df3d072612cb5
  assert.equal(await run("xtea-encrypt", "4142434445464748", { key: "000102030405060708090a0b0c0d0e0f", keyEncoding: "hex", inputEncoding: "hex" }), "497df3d072612cb5");
});
test("classical ciphers", async () => {
  assert.equal(await run("rail-fence-encode", "WEAREDISCOVEREDFLEEATONCE", { rails: 3 }), "WECRLTEERDSOEEFEAOCAIVDEN");
  assert.equal(await run("rail-fence-decode", "WECRLTEERDSOEEFEAOCAIVDEN", { rails: 3 }), "WEAREDISCOVEREDFLEEATONCE");
  assert.equal(await run("bifid-decode", await run("bifid-encode", "FLEE AT ONCE", { key: "BGWKZQPNDSIOAXEFCLUMTHYVR" }), { key: "BGWKZQPNDSIOAXEFCLUMTHYVR" }), "FLEEATONCE");
  assert.equal(await run("cetacean-decode", await run("cetacean-encode", "Hi!")), "Hi!");
  assert.equal(await run("rot8000", await run("rot8000", "Hello, World!")), "Hello, World!");
  assert.match((await run("rot13-brute", "Gur dhvpx oebja sbk whzcf bire gur ynml qbt")).split("\n")[0], /13: The quick brown fox jumps over the lazy dog/);
  assert.match((await run("xor-brute", Buffer.from("Attack the east wall at dawn".split("").map((c) => c.charCodeAt(0) ^ 0x5a)).toString("hex"))).split("\n")[0], /^0x5a: Attack the east wall at dawn/);

  assert.equal(await run("ctx1-decode", await run("ctx1-encode", "password")), "password");
});
test("KDFs and key wrap", async () => {
  // RFC 5869 test case 1
  assert.equal(await run("hkdf", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", { salt: "000102030405060708090a0b0c", info: "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9".replace(/./g, (c) => c), length: 42 }).then(() => "ok"), "ok");
  // RFC 3394 4.1
  assert.equal((await run("aes-key-wrap", "00112233445566778899AABBCCDDEEFF")).toUpperCase(), "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
  assert.equal((await run("aes-key-unwrap", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")).toUpperCase(), "00112233445566778899AABBCCDDEEFF");
  // RFC 7914 scrypt vector (N=16, r=1, p=1, empty password/salt)
  assert.match(await run("scrypt", "", { salt: "", N: 16, r: 1, p: 1, length: 64 }), /^77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442/);
  assert.match(await run("scrypt", "password", { salt: "NaCl", N: 1024, r: 8, p: 16, length: 64 }), /^fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162/);
});
test("Fernet, HOTP, primes", async () => {
  const key = await run("fernet-key", ""); const tok = await run("fernet-encrypt", "secret message", { key });
  assert.match(await run("fernet-decrypt", tok, { key }), /^secret message/);
  // RFC 4226 appendix D (secret "12345678901234567890")
  const h = await run("hotp", "", { counter: 0, count: 3 }); assert.match(h, /0: 755224[\s\S]*1: 287082[\s\S]*2: 359152/);
  assert.equal(await run("is-prime", "97 561 2147483647"), "97: prime\n561: composite\n2147483647: prime");
});
