const test = require("node:test");
const assert = require("node:assert/strict");
const {
  SlidingWindowRateLimiter,
  validatePassword
} = require("../lib/security");

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

test("generic limiter records security-sensitive actions", () => {
  const limiter = new SlidingWindowRateLimiter({ limit: 2, windowMs: 60_000 });
  limiter.record("admin", 1_000);
  assert.equal(limiter.check("admin", 1_001).allowed, true);
  limiter.record("admin", 2_000);
  assert.equal(limiter.check("admin", 2_001).allowed, false);
});
