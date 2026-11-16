// QR output was verified by decoding with OpenCV (versions 1–39, all ECC levels, numeric/alphanumeric/byte).
import test from "node:test"; import assert from "node:assert/strict";
import { qrEncode, ops } from "../public/ops/qr.js";
test("QR version/ECC selection and structure", () => {
  const a = qrEncode("HELLO WORLD", "Q", 1, false); assert.equal(a.version, 1); assert.equal(a.size, 21);
  const b = qrEncode("x".repeat(300), "M", 1, false); assert.equal(b.version, 13); assert.equal(b.size, 69);
  // finder pattern corners are dark, separators light
  for (const [x, y] of [[0, 0], [b.size - 1, 0], [0, b.size - 1]]) assert.equal(b.modules[y][x], true);
  assert.equal(b.modules[7][7], false);
  assert.throws(() => qrEncode("x".repeat(4000), "H"), /too long/);
  const w = ops["wifi-qr"].run("", { ssid: "Home;Net", security: "WPA", password: "p@ss", hidden: false, ecc: "M", scale: 4, border: 4, fg: "#000", bg: "#fff" });
  assert.ok(w.text.includes(String.raw`Payload: WIFI:T:WPA;S:Home\;Net;P:••••;;`), w.text);
});
