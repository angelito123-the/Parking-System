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


test('limiter releases expired entries for clients that never return', () => {
  const limiter = new SlidingWindowRateLimiter({ limit: 2, windowMs: 1000 });
  for (let index = 0; index < 200; index += 1) limiter.record('old-' + index, 1000);
  limiter.record('active', 1900);
  limiter.record('active', 1950);
  assert.equal(limiter.check('new-client', 2001).allowed, true);
  assert.equal(limiter.entries.size, 1);
  assert.equal(limiter.check('active', 2001).allowed, false, 'cleanup must preserve active rate limits');
});
