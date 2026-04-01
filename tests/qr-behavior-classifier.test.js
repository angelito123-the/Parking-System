const test = require("node:test");
const assert = require("node:assert/strict");

const classifier = require("../public/js/qr-behavior-classifier.js");

test("flags high risk payloads with script signatures and IP URLs", () => {
  const sample = "http://192.168.1.10/pay?next=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";
  const result = classifier.classify(sample);

  assert.equal(result.riskLevel, "high");
  assert.ok(result.riskScore >= 0.72);
  assert.equal(result.features.ip_based_url, 1);
  assert.equal(result.features.known_bad_signature, 1);
});

test("marks campus verify token format as low risk", () => {
  const sample = "https://parking-system-production-acd8.up.railway.app/verify/1f2e3d4c5b6a798011223344";
  const result = classifier.classify(sample);

  assert.equal(result.riskLevel, "low");
  assert.ok(result.riskScore < 0.42);
  assert.equal(result.features.looks_verify_payload, 1);
});

test("returns medium risk for shortened redirect URL", () => {
  const sample = "https://bit.ly/3xAbCde?redirect=https%3A%2F%2Funknown-example.top%2Fpay";
  const result = classifier.classify(sample);

  assert.equal(result.riskLevel === "medium" || result.riskLevel === "high", true);
  assert.equal(result.features.uses_shortener, 1);
  assert.equal(result.features.redirect_signal, 1);
});
