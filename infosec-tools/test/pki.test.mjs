import test from "node:test"; import assert from "node:assert/strict";
import fs from "node:fs";
import { ops } from "../public/ops/pki.js";
const fx = (f) => fs.readFileSync(new URL(`./fixtures/${f}`, import.meta.url), "utf8");
const run = async (k, i, a = {}) => { const o = ops[k]; const d = Object.fromEntries((o.args || []).map((x) => [x.name, x.default ?? (x.type === "checkbox" ? false : x.options ? x.options[0] : "")])); return String(await o.run(i, { ...d, ...a })); };
test("X.509 certificate parsing matches OpenSSL", async () => {
  const out = await run("parse-x509", fx("cert.pem"));
  assert.match(out, new RegExp(`SHA-256 fingerprint: ${fx("cert.sha256").trim()}`));
  assert.ok(out.includes(`Serial: ${fx("cert.serial").trim().toLowerCase().match(/../g).join(":")}`), "serial matches OpenSSL");
  assert.match(out, /Subject: C=IN, O=Infosec Tools, CN=test\.example/);
  assert.match(out, /subjectAltName: DNS:test\.example, DNS:www\.test\.example, IP:10\.1\.2\.3/);
  assert.match(out, /extKeyUsage: serverAuth/);
  assert.match(out, /Public key: RSA 2048-bit, exponent 65537/);
  assert.match(out, /Self-signed: yes/);
});
test("CSR and ASN.1", async () => {
  const csr = await run("parse-csr", fx("req.csr"));
  assert.match(csr, /Subject: CN=csr\.example/); assert.match(csr, /subjectAltName: DNS:csr\.example/);
  assert.match(await run("parse-asn1", fx("cert.pem")), /OBJECT IDENTIFIER 1\.2\.840\.113549\.1\.1\.11 \(sha256WithRSAEncryption\)/);
  assert.equal(await run("oid-to-hex", "1.2.840.113549.1.1.11"), "2a864886f70d01010b");
  assert.match(await run("hex-to-oid", "2a864886f70d01010b"), /^1\.2\.840\.113549\.1\.1\.11/);
});
test("keys: PKCS#1/SEC1 import, public key derivation, JWK round-trip", async () => {
  const fromPriv = await run("pubkey-from-private", fx("rsa-pkcs1.key"));
  const fromCert = await run("pubkey-from-cert", fx("cert.pem"));
  assert.equal(fromPriv, fromCert, "public key from PKCS#1 private key equals the certificate's");
  const jwk = await run("pem-to-jwk", fx("ec.key")); assert.match(jwk, /"crv": "P-256"/);
  assert.match(await run("jwk-to-pem", jwk), /BEGIN PRIVATE KEY/);
});
test("signatures and encryption", async () => {
  const sig = await run("rsa-sign", "hello", { key: fx("rsa-pkcs8.key") });
  assert.match(await run("rsa-verify", "hello", { key: fx("cert.pem"), signature: sig }), /VALID/);
  assert.match(await run("rsa-verify", "hellO", { key: fx("cert.pem"), signature: sig }), /INVALID/);
  const ct = await run("rsa-encrypt", "secret", { key: fx("cert.pem") });
  assert.equal(await run("rsa-decrypt", ct, { key: fx("rsa-pkcs1.key") }), "secret");
  const es = await run("ecdsa-sign", "msg", { key: fx("ec.key") });
  const pub = await run("pubkey-from-private", fx("ec.key"));
  assert.match(await run("ecdsa-verify", "msg", { key: pub, signature: es }), /VALID/);
  const raw = (await run("ecdsa-sig-convert", es)).replace("Raw r||s: ", "");
  assert.match(await run("ecdsa-verify", "msg", { key: pub, signature: raw }), /VALID/);
});
test("SSH host key fingerprint (GitHub's published Ed25519 key)", async () => {
  const out = await run("parse-ssh-key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl github.com");
  assert.match(out, /Fingerprint SHA256:\+DiY3wvvV6TuJJhbpZisF\/zLDA0zPMSvHdkr4UvCOqU/);
  assert.match(out, /Comment: github\.com/);
});
