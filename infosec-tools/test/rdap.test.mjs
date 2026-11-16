// RDAP bootstrap routing, with IANA and registry responses mocked.
import test from "node:test"; import assert from "node:assert/strict";
const BOOT = {
  dns: { services: [[["online"], ["https://rdap.centralnic.com/online/"]], [["com", "net"], ["https://rdap.verisign.com/com/v1/"]]] },
  ipv4: { services: [[["1.0.0.0/8"], ["https://rdap.apnic.net/"]], [["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]]] },
  ipv6: { services: [[["2600::/12"], ["https://rdap.arin.net/registry/"]], [["2a00::/12"], ["https://rdap.db.ripe.net/"]]] },
  asn: { services: [[["13312-18431"], ["https://rdap.arin.net/registry/"]], [["196608-213403"], ["https://rdap.db.ripe.net/"]]] },
};
const asked = [];
globalThis.fetch = async (url) => {
  const u = String(url); asked.push(u);
  const b = u.match(/data\.iana\.org\/rdap\/(\w+)\.json/); if (b) return new Response(JSON.stringify(BOOT[b[1]]));
  return new Response(JSON.stringify({ ldhName: "X", name: "NET-X", startAutnum: 13335, events: [] }), { headers: { "content-type": "application/rdap+json" } });
};
const { serverOps } = await import("../lib/server-ops.mjs");
test("routes each query to its authoritative registry", async () => {
  await serverOps.whois.run("https://www.sajinshivdas.online/path", {});
  assert.ok(asked.includes("https://rdap.centralnic.com/online/domain/sajinshivdas.online"), asked.join("\n"));
  await serverOps.whois.run("example.com", {});
  assert.ok(asked.includes("https://rdap.verisign.com/com/v1/domain/example.com"));
  await serverOps["ip-whois"].run("1.1.1.1", {});
  assert.ok(asked.includes("https://rdap.apnic.net/ip/1.1.1.1"));
  await serverOps["ip-whois"].run("2606:4700:4700::1111", {});
  assert.ok(asked.includes("https://rdap.arin.net/registry/ip/2606%3A4700%3A4700%3A%3A1111"));
  await serverOps["asn-lookup"].run("AS13335", {});
  assert.ok(asked.includes("https://rdap.arin.net/registry/autnum/13335"));
  assert.equal(asked.filter((u) => u.includes("data.iana.org/rdap/dns.json")).length, 1, "bootstrap file is cached");
});
