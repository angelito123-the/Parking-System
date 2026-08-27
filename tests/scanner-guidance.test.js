const test = require("node:test");
const assert = require("node:assert/strict");

const ScannerGuidance = require("../public/js/scanner-guidance");

test("scanner guidance asks for more light before other adjustments", () => {
  const result = ScannerGuidance.chooseGuidance({
    brightness: 45,
    detectedRegion: true,
    areaRatio: 0.03,
    confidence: 0.2
  });
  assert.equal(result.key, "lighting");
});

test("scanner guidance asks the user to move closer for a small QR", () => {
  const result = ScannerGuidance.chooseGuidance({
    brightness: 140,
    detectedRegion: true,
    areaRatio: 0.04,
    confidence: 0.5
  });
  assert.equal(result.key, "closer");
});

test("scanner guidance asks the user to hold steady on a weak read", () => {
  const result = ScannerGuidance.chooseGuidance({
    brightness: 140,
    detectedRegion: true,
    areaRatio: 0.2,
    confidence: 0.24,
    threshold: 0.35
  });
  assert.equal(result.key, "steady");
});

test("scanner guidance reports an active read for a strong QR region", () => {
  const result = ScannerGuidance.chooseGuidance({
    brightness: 140,
    detectedRegion: true,
    areaRatio: 0.2,
    confidence: 0.72,
    threshold: 0.35
  });
  assert.equal(result.key, "reading");
});

test("scanner guidance uses a low learned-readiness recommendation", () => {
  const result = ScannerGuidance.chooseGuidance({
    brightness: 140,
    detectedRegion: true,
    areaRatio: 0.2,
    confidence: 0.72,
    threshold: 0.35,
    readinessScore: 0.34,
    readinessGuidance: "steady"
  });
  assert.equal(result.key, "steady");
});
