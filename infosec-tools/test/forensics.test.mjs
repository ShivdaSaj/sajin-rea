import test from "node:test"; import assert from "node:assert/strict";
import fs from "node:fs"; import path from "node:path"; import os from "node:os";
import { ops, lz4Frame, lz4Decompress, xpress } from "../public/ops/forensics.js";
const fx = (f) => new Uint8Array(fs.readFileSync(new URL(`./fixtures/${f}`, import.meta.url)));
const run = async (k, file, a = {}) => { const o = ops[k]; const d = Object.fromEntries((o.args || []).map((x) => [x.name, x.default ?? (x.type === "checkbox" ? false : x.options ? x.options[0] : "")])); return o.run(file, { ...d, ...a }); };
const file = (name) => ({ bytes: fx(name), name });
const text = (r) => (typeof r === "string" ? r : r.text);
test("LZ4 interoperates with python-lz4", async () => {
  const data = fx("data.bin");
  assert.deepEqual(lz4Decompress(fx("py.lz4")), data, "decompress python-lz4 frame");
  const mine = lz4Frame(data); assert.ok(mine.length < data.length * 0.5, "actually compresses"); assert.deepEqual(lz4Decompress(mine), data, "round trip");
  fs.writeFileSync(path.join(os.tmpdir(), "infosec-mine.lz4"), mine);
});
test("ZIP and TAR interoperate with Python zipfile/tarfile", async () => {
  const z = await run("unzip", file("py.zip")); assert.match(z.text, /2 entries/); assert.match(z.text, /folder\/hello\.txt/); assert.match(z.text, /CRC OK/); assert.match(z.text, /Hello from Python zipfile/);
  const t = text(await run("untar", file("py.tar"))); assert.match(t, /docs\/readme\.txt/); assert.match(t, /tar payload/);
  const myZip = new Uint8Array(await (await run("zip", { bytes: fx("data.bin"), name: "data.bin" })).download.data.arrayBuffer()); fs.writeFileSync(path.join(os.tmpdir(), "infosec-mine.zip"), myZip);
  const back = await run("unzip", { bytes: myZip, name: "x.zip" }); assert.match(back.text, /CRC OK/);
  const myTar = new Uint8Array(await (await run("tar", { bytes: fx("data.bin"), name: "data.bin" })).download.data.arrayBuffer()); fs.writeFileSync(path.join(os.tmpdir(), "infosec-mine.tar"), myTar);
});
test("plist (binary + XML), EXIF, ELF, ID3, file types, XPRESS", async () => {
  const want = { Name: "Infosec", Version: 3, Enabled: true, Tags: ["a", "b"], Nested: { x: 1.5 } };
  assert.deepEqual(JSON.parse(await run("plist-viewer", file("bin.plist"))), want); assert.deepEqual(JSON.parse(await run("plist-viewer", file("xml.plist"))), want);
  const ex = await run("extract-exif", file("exif.jpg")); assert.match(ex, /Make\s+Canon/); assert.match(ex, /Model\s+EOS Test/); assert.match(ex, /GPS \(decimal\)\s+51\.500700, -0\.124600/);
  const clean = await run("remove-exif", file("exif.jpg")); const cleanBytes = new Uint8Array(await new Blob([clean.download.data]).arrayBuffer()); assert.match(await run("extract-exif", { bytes: cleanBytes, name: "c.jpg" }), /No EXIF/);
  const node = new Uint8Array(fs.readFileSync(process.execPath).subarray(0, 1 << 20)); if (node[0] === 0x7f && node[1] === 0x45) { const e = await run("elf-info", { bytes: new Uint8Array(fs.readFileSync(process.execPath)), name: "node" }); assert.match(e, /Class: ELF64/); assert.match(e, /Machine: (x86-64|AArch64)/); }
  const id3 = new Uint8Array([0x49, 0x44, 0x33, 3, 0, 0, 0, 0, 0, 23, 0x54, 0x49, 0x54, 0x32, 0, 0, 0, 7, 0, 0, 0, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0, 0, 0, 0, 0, 0]);
  assert.match(await run("extract-id3", { bytes: id3, name: "a.mp3" }), /Title\s+Hello!/);
  assert.match(await run("detect-file-type", file("py.zip")), /ZIP archive/); assert.match(await run("detect-file-type", file("exif.jpg")), /JPEG image/); assert.match(await run("detect-file-type", file("bin.plist")), /Binary property list/);
  const xp = new Uint8Array([0x3f, 0, 0, 0, ...new TextEncoder().encode("abcdefghijklmnopqrstuvwxyz")]); assert.equal(new TextDecoder().decode(xpress(xp)), "abcdefghijklmnopqrstuvwxyz");
  const xp2 = new Uint8Array([0xff, 0xff, 0xff, 0x1f, 0x61, 0x62, 0x63, 0x17, 0x00, 0x0f, 0xff, 0x26, 0x01]); assert.equal(new TextDecoder().decode(xpress(xp2)), "abc".repeat(100));
});
test("LZNT1 matches dissect.util on compressed and stored chunks", async () => {
  const { lznt1 } = await import("../public/ops/forensics.js");
  for (const k of [2, 3]) assert.deepEqual(lznt1(fx(`lznt1_${k}.bin`)), fx(`lznt1_${k}.raw`), `sample ${k}`);
});
