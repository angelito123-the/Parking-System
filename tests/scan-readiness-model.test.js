const test = require("node:test");
const assert = require("node:assert/strict");

const {
  ScanReadinessModel,
  normalizeFeatures
} = require("../public/js/scan-readiness-model");

function quality(overrides = {}) {
  return {
    brightness: 138,
    contrastScore: 0.82,
    edgeScore: 0.78,
    areaRatio: 0.19,
    stabilityScore: 0.9,
    confidence: 0.8,
    detectedRegion: true,
    ...overrides
  };
}

test("scan readiness ranks a clear, stable QR above a poor frame", () => {
  const model = new ScanReadinessModel({ storage: null });
  const ready = model.assess(quality()).score;
  const poor = model.assess(quality({
    brightness: 28,
    contrastScore: 0.12,
    edgeScore: 0.15,
    areaRatio: 0.025,
    stabilityScore: 0.12,
    confidence: 0.16
  })).score;

  assert.ok(ready > poor);
  assert.ok(ready > 0.7);
  assert.ok(poor < 0.4);
});

test("the online model learns from successful scans", () => {
  const model = new ScanReadinessModel({ storage: null, learningRate: 0.2 });
  const frame = quality({ brightness: 92, contrastScore: 0.55, confidence: 0.46 });
  const before = model.assess(frame).score;

  for (let index = 0; index < 18; index += 1) {
    model.observe(frame, true);
  }

  const after = model.assess(frame);
  assert.ok(after.score > before);
  assert.equal(after.trained, true);
  assert.equal(model.getStatus().successes, 18);
});

test("readiness guidance targets the weakest camera condition", () => {
  const model = new ScanReadinessModel({ storage: null });
  assert.equal(model.assess(quality({ brightness: 35 })).guidance, "lighting");
  assert.equal(model.assess(quality({ areaRatio: 0.025 })).guidance, "closer");
  assert.equal(model.assess(quality({ stabilityScore: 0.05, edgeScore: 0.12 })).guidance, "steady");
});

test("feature normalization treats overexposed frames as lower quality", () => {
  const balanced = normalizeFeatures(quality({ brightness: 135 })).brightness;
  const overexposed = normalizeFeatures(quality({ brightness: 245 })).brightness;
  assert.ok(balanced > overexposed);
});
