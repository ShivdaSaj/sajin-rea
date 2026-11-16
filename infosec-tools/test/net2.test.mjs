import test from "node:test"; import assert from "node:assert/strict";
import { ops } from "../public/ops/net2.js";
import { ops as refs } from "../public/ops/reference.js";
const run = async (k, i, a = {}) => { const o = ops[k] || refs[k]; assert.ok(o, `missing ${k}`); const d = Object.fromEntries((o.args || []).map((x) => [x.name, x.default ?? (x.type === "checkbox" ? false : x.options ? x.options[0] : "")])); return String(await o.run(i, { ...d, ...a })); };
test("DNSSEC vectors (RFC 5155, RFC 4034)", async () => {
  assert.equal(await run("nsec3-hash", "example", { salt: "aabbccdd", iterations: 12 }), "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom");
  assert.equal(await run("nsec3-hash", "a.example", { salt: "aabbccdd", iterations: 12 }), "35mthgpgcu1qg68fab165klnsnk3dpvl");
  const key = "dskey.example.com. 86400 IN DNSKEY 256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==";
  assert.match(await run("dnskey-tag", key), /^Key tag: 60485/);
  assert.match(await run("ds-gen", key, { digest: "1 (SHA-1, legacy)" }), /DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118$/);
});
test("IPv6 transition tools", async () => {
  const t = await run("teredo-decode", "2001:0:4136:e378:8000:63bf:3fff:fdd2");
  assert.match(t, /Teredo server: 65\.54\.227\.120/); assert.match(t, /Client public IPv4: 192\.0\.2\.45/); assert.match(t, /port: 40000/);
  assert.match(await run("solicited-node", "2001:db8::1:2:3"), /→ ff02::1:ff02:3/);
  assert.equal(await run("nat64", "192.0.2.33"), "192.0.2.33 → 64:ff9b::c000:221");
  assert.match(await run("ipv6-to-ipv4", "2002:c000:0204::1"), /6to4 → 192\.0\.2\.4/);
  assert.equal(await run("nth-ip", "192.168.1.0/24", { n: -2 }), "192.168.1.254");
  assert.match(await run("ip-distance", "10.0.0.1", { other: "10.0.1.0" }), /^255 addresses apart/);
});
test("DNS builders and zone tools", async () => {
  assert.equal(await run("reverse-zones", "10.20.0.0/22"), "0.20.10.in-addr.arpa.\n1.20.10.in-addr.arpa.\n2.20.10.in-addr.arpa.\n3.20.10.in-addr.arpa.");
  assert.match(await run("reverse-zones", "192.0.2.0/26"), /^0-26\.2\.0\.192\.in-addr\.arpa\./);
  assert.match(await run("reverse-zone-gen", "192.0.2.0/30"), /1\.2\.0\.192\.in-addr\.arpa\.\s+IN PTR host-192-0-2-1\.example\.com\./);
  assert.match(await run("txt-escape", 'v=spf1 "x"'), /^"v=spf1 \\"x\\""/);
  assert.match(await run("spf-builder", ""), /"v=spf1 mx include:_spf\.mail\.hostinger\.com ~all"/);
  assert.match(await run("dmarc-builder", "", { p: "reject" }), /_dmarc IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example\.com"/);
  assert.match(await run("dns-record-validate", "@ IN CNAME example.org.\nwww IN A 999.1.1.1"), /✗ @ IN CNAME[\s\S]*apex[\s\S]*✗ www IN A 999\.1\.1\.1\n    - rdata is not an IPv4 address/);
  const zone = "$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1 hostmaster ( 1 7200 3600 1209600 300 )\n@ IN NS ns1\nns1 IN A 192.0.2.1\nwww IN CNAME example.com\nwww IN A 192.0.2.2\n";
  const lint = await run("zone-lint", zone); assert.match(lint, /only 1 apex NS/); assert.match(lint, /www\.example\.com\.: CNAME coexists/); assert.match(lint, /lacks a trailing dot/);
  assert.match(await run("zone-diff", zone, { other: zone.replace("192.0.2.2", "192.0.2.3") }), /- www\.example\.com\. A 192\.0\.2\.2\n\+ www\.example\.com\. A 192\.0\.2\.3/);
  assert.match(await run("ttl-calc", "1h30m"), /^5400 seconds = 1h 30m/);
});
test("DHCP encoders", async () => {
  assert.match(await run("dhcp-opt121", "10.0.0.0/8 192.168.1.254"), /Wire \(hex\): 7906080ac0a801fe/);
  assert.match(await run("dhcp-opt3", "192.168.1.1"), /Wire \(hex\): 0304c0a80101/);
  assert.match(await run("dhcp-opt119", "eng.apple.com"), /Wire \(hex\): 770f03656e67056170706c6503636f6d00/);
  assert.match(await run("dhcp-opt51", "86400"), /Wire \(hex\): 330400015180/);
  assert.match(await run("dhcp-opt61", "00:11:22:33:44:55"), /Wire \(hex\): 3d0701001122334455/);
  assert.match(await run("iaid-calc", "00:11:22:33:44:55"), /IAID \(last 4 bytes of MAC\): 573785173/);
  assert.match(await run("dhcp-fingerprint", "1,121,3,6,15,108,114,119,252,95,44,46"), /^100%  Apple/);
});
test("references are filterable", async () => {
  assert.match(await run("ref-cidr", "/26"), /255\.255\.255\.192/);
  assert.match(await run("ref-multicast", ""), /224\.0\.0\.251  mDNS/);
});
