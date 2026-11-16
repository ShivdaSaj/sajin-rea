import test from "node:test"; import assert from "node:assert/strict";
import fs from "node:fs"; import { createHash } from "node:crypto";
import { registry } from "../public/ops/index.js";
const run = async (k, i, a = {}) => { const o = registry[k]; assert.ok(o, `missing ${k}`); const d = Object.fromEntries((o.args || []).map((x) => [x.name, x.default ?? (x.type === "checkbox" ? false : x.options ? x.options[0] : "")])); return String(await o.run(i, { ...d, ...a })); };
const fx = (f) => fs.readFileSync(new URL(`./fixtures/${f}`, import.meta.url), "utf8");
test("TLS fingerprints match Wireshark/tshark 4.2.2", async () => {
  assert.match(await run("ja3", fx("tls-clienthello.hex")), /^JA3: d67b094811e5145139d7cea5f014309f/);
  assert.match(await run("ja4", fx("tls-clienthello.hex")), /^JA4: t13d5212h2_b262b3658495_8e6e362c5eac/);
  assert.match(await run("ja3s", fx("tls-serverhello.hex")), /^JA3S: 15af977ce25de452b96affa2addb1036/);
  assert.match(await run("parse-tls-record", fx("tls-clienthello.hex")), /SNI\s+example\.com/);
});
test("packet parsers, HTTP, protobuf, HASSH", async () => {
  const ip = await run("parse-ipv4", "4500003c1c4640004006b1e6ac100a63ac100a0c"); assert.match(ip, /✓ correct/); assert.match(ip, /Source\s+172\.16\.10\.99/); assert.match(ip, /Protocol\s+6 \(TCP\)/);
  assert.match(await run("parse-tcp", "c3500050000000010000000050182000abcd0000"), /Flags\s+PSH, ACK/);
  assert.equal(await run("dechunk-http", "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"), "Wikipedia");
  assert.equal(await run("protobuf-encode", '{"1":150}'), "089601"); assert.equal(await run("protobuf-encode", '{"2":"testing"}'), "120774657374696e67");
  assert.match(await run("protobuf-decode", "089601120774657374696e671a03089601"), /1 \(varint\): 150[\s\S]*2 \(string\): "testing"[\s\S]*3: \{\n  1 \(varint\): 150/);
  const lists = ["curve25519-sha256,diffie-hellman-group14-sha256", "ssh-ed25519", "aes128-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-512", "none", "zlib", "", ""]; const enc = (s) => { const b = Buffer.from(s); const l = Buffer.alloc(4); l.writeUInt32BE(b.length); return Buffer.concat([l, b]); };
  const kex = Buffer.concat([Buffer.from([20]), Buffer.alloc(16), ...lists.map(enc), Buffer.from([0, 0, 0, 0, 0])]);
  const want = createHash("md5").update("curve25519-sha256,diffie-hellman-group14-sha256;aes128-ctr;hmac-sha2-256;none").digest("hex");
  assert.match(await run("hassh", kex.toString("hex")), new RegExp(`^HASSH: ${want}`));
});
test("formats: float, Bech32, Base92, BSON, text encodings, MIME", async () => {
  assert.equal(await run("to-float", "3.14159"), "40490fd0"); assert.equal(await run("from-float", "40490fd0"), "3.14159012");
  assert.match(await run("bech32-decode", "A12UEL5L"), /HRP: a\nVariant: Bech32/);
  assert.match(await run("bech32-decode", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), /SegWit v0 program: 751e76e8199196d454941c45d1b3a323f1433bd6/);
  assert.match(await run("bech32-decode", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"), /Variant: Bech32m/);
  assert.match(await run("bech32-decode", await run("bech32-encode", "deadbeef", { hrp: "test" })), /Data \(bytes\): deadbeef/);
  assert.equal(await run("base92-encode", "hello world"), "Fc_$aOTdKnsM*k"); assert.equal(await run("base92-decode", "Fc_$aOTdKnsM*k"), "hello world");
  assert.equal(await run("bson-serialise", '{"hello":"world"}'), "160000000268656c6c6f0006000000776f726c640000");
  assert.deepEqual(JSON.parse(await run("bson-deserialise", await run("bson-serialise", '{"a":[1,2.5,true,null],"b":{"c":"d"}}'))), { a: [1, 2.5, true, null], b: { c: "d" } });
  assert.equal(await run("encode-text", "Hi"), "48006900"); assert.equal(await run("encode-text", "€", { charset: "windows-1252" }), "80"); assert.equal(await run("decode-text", "48006900", { charset: "utf-16le" }), "Hi");
  assert.equal(await run("mime-decode", "=?UTF-8?B?SGVsbG8gV29ybGQg8J+Riw==?= =?ISO-8859-1?Q?caf=E9?="), "Hello World 👋café");
  assert.match(await run("base64-offsets", "secret"), /Offset 0: c2VjcmV0\n  stable: c2VjcmV0/);
});
test("Enigma, BIP39, Magic, JS minify", async () => {
  assert.match(await run("enigma", "AAAAA"), /^BDZGO/);
  assert.match(await run("enigma", await run("enigma", "HELLOWORLD", { plugboard: "AB CD", positions: "QEV" }).then((x) => x.split("\n")[0]), { plugboard: "AB CD", positions: "QEV" }), /^HELLOWORLD/);
  assert.equal(await run("bip39-from-entropy", "00000000000000000000000000000000"), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
  const chk = await run("bip39-check", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", { passphrase: "TREZOR" });
  assert.match(chk, /✓ valid/); assert.match(chk, /c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04/);
  assert.match(await run("bip39-check", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"), /INVALID/);
  assert.match(await run("magic", Buffer.from("the flag is in the password file").toString("base64")), /#1  From Base64\n    the flag is in the password file/);
  assert.equal(await run("js-minify", "// c\nfunction add (a, b) {\n  /* sum */ return a + b; // x\n}\nconst s = \"a  // b\";"), 'function add(a,b){return a+b;}const s="a  // b";');
  assert.equal(await run("js-minify", "function f() {\n  return\n  42\n}"), "function f(){return\n42}", "keeps ASI-significant newline after return");
});
