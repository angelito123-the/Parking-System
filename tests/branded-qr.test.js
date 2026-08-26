const test = require("node:test");
const assert = require("node:assert/strict");
const { PNG } = require("pngjs");
const { generateBrandedQrPng } = require("../lib/branded-qr");

test("generates a branded, high-resolution PNG QR code", async () => {
  const buffer = await generateBrandedQrPng("http://localhost:3000/verify/example-token", { size: 600 });
  assert.deepEqual([...buffer.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);

  const png = PNG.sync.read(buffer);
  assert.equal(png.width, 600);
  assert.equal(png.height, 600);

  const badgeSampleOffset = ((png.width * 300) + 260) << 2;
  assert.deepEqual(
    [...png.data.subarray(badgeSampleOffset, badgeSampleOffset + 4)],
    [37, 99, 235, 255]
  );
});

test("rejects an empty QR payload", async () => {
  await assert.rejects(() => generateBrandedQrPng(""), /payload is required/i);
});
