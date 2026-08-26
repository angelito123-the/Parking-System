const test = require("node:test");
const assert = require("node:assert/strict");
const parser = require("../public/js/qr-token-parser");

test("extracts student sticker tokens from absolute and relative verify URLs", () => {
  assert.equal(parser.extract("https://parking.test/verify/student-token-123"), "student-token-123");
  assert.equal(parser.extract("/verify/student-token-456", "https://parking.test"), "student-token-456");
});

test("extracts visitor tokens without returning the visitor route segment", () => {
  assert.equal(parser.extract("https://parking.test/verify/visitor/visitor-token-123"), "visitor-token-123");
  assert.equal(parser.extract("/verify/visitor/visitor-token-456", "https://parking.test"), "visitor-token-456");
});

test("preserves raw tokens and rejects empty payloads", () => {
  assert.equal(parser.extract(" raw-token-123 "), "raw-token-123");
  assert.equal(parser.extract("   "), "");
});
