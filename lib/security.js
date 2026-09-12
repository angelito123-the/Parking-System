const crypto = require("node:crypto");

function clampInteger(value, min, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(number)));
}

const { validatePassword } = require('../public/js/password-policy');

function hashIdentifier(value, secret) {
  return crypto.createHmac("sha256", String(secret || "local-audit-key"))
    .update(String(value || "unknown"))
    .digest("hex")
    .slice(0, 24);
}

class SlidingWindowRateLimiter {
  constructor(options = {}) {
    this.limit = clampInteger(options.limit, 1, 100, 5);
    this.windowMs = clampInteger(options.windowMs, 1000, 24 * 60 * 60 * 1000, 15 * 60 * 1000);
    this.entries = new Map();
    this.nextCleanupAt = 0;
  }

  prune(key, now = Date.now()) {
    const cutoff = now - this.windowMs;
    const recent = (this.entries.get(String(key)) || []).filter((timestamp) => timestamp > cutoff);
    if (recent.length) this.entries.set(String(key), recent);
    else this.entries.delete(String(key));
    return recent;
  }

  check(key, now = Date.now()) {
    // Expire clients that never return, without scanning the map on every request.
    if (now >= this.nextCleanupAt) {
      for (const entryKey of this.entries.keys()) this.prune(entryKey, now);
      this.nextCleanupAt = now + Math.min(this.windowMs, 60_000);
    }
    const recent = this.prune(key, now);
    const allowed = recent.length < this.limit;
    const retryAfterSeconds = allowed || !recent.length
      ? 0
      : Math.max(1, Math.ceil((recent[0] + this.windowMs - now) / 1000));
    return {
      allowed,
      remaining: Math.max(0, this.limit - recent.length),
      retryAfterSeconds
    };
  }

  record(key, now = Date.now()) {
    const recent = this.prune(key, now);
    recent.push(now);
    this.entries.set(String(key), recent);
    return this.check(key, now);
  }

  recordFailure(key, now = Date.now()) {
    return this.record(key, now);
  }

  reset(key) {
    this.entries.delete(String(key));
  }
}

module.exports = {
  SlidingWindowRateLimiter,
  hashIdentifier,
  validatePassword
};
