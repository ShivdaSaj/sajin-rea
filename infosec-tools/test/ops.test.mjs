// Known-answer tests for the client-side ops. Run: node --test test/
import test from "node:test"; import assert from "node:assert/strict";
import { registry } from "../public/ops/index.js";
const run = async (key, input, args = {}) => { const op = registry[key]; assert.ok(op, `missing op ${key}`); const a = Object.fromEntries((op.args || []).map((x) => [x.name, x.default ?? (x.type === "checkbox" ? false : "")])); return String(await op.run(input, { ...a, ...args })); };
test("encodings round-trip", async () => {
  assert.equal(await run("base64-encode", "hello"), "aGVsbG8=");
  assert.equal(await run("base64-decode", "aGVsbG8="), "hello");
  assert.equal(await run("base32-encode", "foobar"), "MZXW6YTBOI======");
  assert.equal(await run("base32-decode", "MZXW6YTBOI======"), "foobar");
  assert.equal(await run("base58-encode", "hello world"), "StV1DL6CwTryKyV");
  assert.equal(await run("hex-encode", "Hi", { delimiter: "None" }), "4869");
  assert.equal(await run("rot13", "Hello"), "Uryyb");
  assert.equal(await run("rot47", "Hello"), "w6==@");
  assert.equal(await run("morse-decode", await run("morse-encode", "SOS 1")), "SOS 1");
  assert.equal(await run("html-decode", "&lt;a&gt; &#65; &#x42;"), "<a> A B");
  assert.equal(await run("vigenere-decode", await run("vigenere-encode", "Attack at dawn", { key: "lemon" }), { key: "lemon" }), "Attack at dawn");
});
test("hashes match published vectors", async () => {
  assert.equal(await run("md5", "abc"), "900150983cd24fb0d6963f7d28e17f72");
  assert.equal(await run("md5", ""), "d41d8cd98f00b204e9800998ecf8427e");
  assert.equal(await run("sha1", "abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
  assert.equal(await run("sha256", "abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(await run("crc32", "The quick brown fox jumps over the lazy dog"), "414fa339");
  assert.equal(await run("hmac", "The quick brown fox jumps over the lazy dog", { key: "key" }), "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
  assert.match(await run("luhn-check", "4539 1488 0343 6467"), /^Valid/);
});
test("crypto ops", async () => {
  const enc = await run("aes-encrypt", "secret text", { key: "pw" });
  const iv = enc.match(/IV \(hex\): (\w+)/)[1], ct = enc.match(/base64\): (\S+)/)[1];
  assert.equal(await run("aes-decrypt", ct, { key: "pw", iv }), "secret text");
  const jwt = await run("jwt-sign", '{"sub":"1"}', { secret: "s" });
  assert.match(await run("jwt-verify", jwt, { secret: "s" }), /VALID/);
  assert.match(await run("jwt-decode", jwt), /"sub": "1"/);
  assert.match(await run("uuid", ""), /^[0-9a-f]{8}-[0-9a-f]{4}-4/);
});
test("network math", async () => {
  const s = await run("subnet-calc", "192.168.10.37/26");
  assert.match(s, /Network:\s+192\.168\.10\.0\/26/); assert.match(s, /Broadcast:\s+192\.168\.10\.63/); assert.match(s, /Usable hosts:\s+62/);
  assert.equal(await run("range-to-cidr", "192.168.0.0 - 192.168.0.255"), "192.168.0.0/24");
  assert.equal(await run("range-to-cidr", "10.0.0.1 - 10.0.0.6"), "10.0.0.1/32\n10.0.0.2/31\n10.0.0.4/31\n10.0.0.6/32");
  assert.equal(await run("cidr-summarize", "10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/23"), "10.0.0.0/22");
  assert.equal(await run("mask-to-cidr", "255.255.252.0"), "255.255.252.0 → /22");
  assert.equal(await run("ipv6-compress", "2001:0db8:0000:0000:0000:0000:0000:0001"), "2001:db8::1");
  assert.equal(await run("ipv6-expand", "::ffff:192.0.2.1"), "0000:0000:0000:0000:0000:ffff:c000:0201");
  assert.equal(await run("cidr-diff", "10.0.0.0/23", { remove: "10.0.1.0/24" }), "10.0.0.0/24");
  assert.match(await run("reverse-dns-name", "203.0.113.7"), /7\.113\.0\.203\.in-addr\.arpa/);
});
test("data and text", async () => {
  assert.equal(await run("json-minify", '{ "a": [1, 2] }'), '{"a":[1,2]}');
  assert.equal(await run("csv-to-json", "a,b\n1,\"x,y\""), JSON.stringify([{ a: "1", b: "x,y" }], null, 2));
  assert.equal(await run("roman", "1994"), "MCMXCIV"); assert.equal(await run("roman", "MCMXCIV"), "1994");
  assert.equal(await run("case-convert", "hello world-foo", { case: "camelCase" }), "helloWorldFoo");
  assert.equal((await run("chmod", "755")).split("\n")[1], "Symbolic: rwxr-xr-x");
  assert.equal(await run("defang-url", "https://evil.com"), "hxxps[://]evil[.]com");
  assert.equal(await run("fang-url", "hxxps[://]evil[.]com"), "https://evil.com");
  assert.match(await run("extract-ipv4", "a 10.0.0.1 b 999.1.1.1 c 8.8.8.8"), /2 found\n10\.0\.0\.1\n8\.8\.8\.8/);
});
