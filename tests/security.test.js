const test = require("node:test");
const assert = require("node:assert/strict");
const {
  SlidingWindowRateLimiter,
  decryptSecret,
  encryptSecret,
  generateTotpToken,
  validatePassword,
  verifyTotpToken
} = require("../lib/security");

test("TOTP implementation matches the RFC 6238 SHA-1 vector", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const token = generateTotpToken(secret, 59_000, { digits: 8 });
  assert.equal(token, "94287082");
  assert.equal(verifyTotpToken(secret, token, { timestampMs: 59_000, digits: 8, window: 0 }), true);
  assert.equal(verifyTotpToken(secret, "00000000", { timestampMs: 59_000, digits: 8, window: 0 }), false);
});

test("two-factor secrets are encrypted and authenticated", () => {
  const encrypted = encryptSecret("JBSWY3DPEHPK3PXP", "session-secret-for-test");
  assert.notEqual(encrypted, "JBSWY3DPEHPK3PXP");
  assert.equal(decryptSecret(encrypted, "session-secret-for-test"), "JBSWY3DPEHPK3PXP");
  assert.throws(() => decryptSecret(encrypted, "wrong-secret"));
});

test("password policy rejects weak or predictable values", () => {
  assert.equal(validatePassword("short").valid, false);
  assert.equal(validatePassword("adminParking2026").valid, false);
  assert.equal(validatePassword("RampAccess2026").valid, true);
});

test("login limiter blocks repeated failures and resets", () => {
  const limiter = new SlidingWindowRateLimiter({ limit: 2, windowMs: 60_000 });
  assert.equal(limiter.check("client", 1_000).allowed, true);
  limiter.recordFailure("client", 1_000);
  limiter.recordFailure("client", 2_000);
  assert.equal(limiter.check("client", 2_001).allowed, false);
  limiter.reset("client");
  assert.equal(limiter.check("client", 2_002).allowed, true);
});
