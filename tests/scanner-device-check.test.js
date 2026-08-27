const test = require("node:test");
const assert = require("node:assert/strict");
const { classifyDevice, evaluateCapabilities } = require("../public/js/scanner-device-check");

test("device classifier recognizes common scanner form factors", () => {
  assert.equal(classifyDevice(390, "Mozilla/5.0 iPhone Mobile"), "mobile");
  assert.equal(classifyDevice(900, "Mozilla/5.0 iPad Tablet"), "tablet");
  assert.equal(classifyDevice(1440, "Mozilla/5.0 Windows NT 10.0"), "desktop");
});

test("device readiness requires secure camera and offline storage", () => {
  const result = evaluateCapabilities({
    secureContext: true,
    camera: true,
    indexedDb: true,
    serviceWorker: true,
    barcodeDetector: true,
    torch: false
  });
  assert.equal(result.ready, true);
  assert.equal(result.grade, "excellent");

  const missingCamera = evaluateCapabilities({ secureContext: true, camera: false, indexedDb: true });
  assert.equal(missingCamera.ready, false);
  assert.equal(missingCamera.grade, "needs-attention");
});
