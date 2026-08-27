const crypto = require("node:crypto");

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function clampInteger(value, min, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(number)));
}

function encodeBase32(buffer) {
  const bytes = Buffer.from(buffer || []);
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function decodeBase32(value) {
  const input = String(value || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let accumulator = 0;
  const output = [];
  for (const character of input) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) continue;
    accumulator = (accumulator << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((accumulator >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateTotpSecret(byteLength = 20) {
  return encodeBase32(crypto.randomBytes(clampInteger(byteLength, 16, 64, 20)));
}

function generateTotpToken(secret, timestampMs = Date.now(), options = {}) {
  const stepSeconds = clampInteger(options.stepSeconds, 15, 120, 30);
  const digits = clampInteger(options.digits, 6, 8, 6);
  const counter = Math.floor(Number(timestampMs) / 1000 / stepSeconds);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac("sha1", decodeBase32(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = (
    ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff)
  ) >>> 0;
  return String(binary % (10 ** digits)).padStart(digits, "0");
}

function verifyTotpToken(secret, token, options = {}) {
  const input = String(token || "").replace(/\s+/g, "");
  const digits = clampInteger(options.digits, 6, 8, 6);
  if (!new RegExp(`^\\d{${digits}}$`).test(input)) return false;
  const timestampMs = Number(options.timestampMs) || Date.now();
  const window = clampInteger(options.window, 0, 3, 1);
  const stepSeconds = clampInteger(options.stepSeconds, 15, 120, 30);
  const supplied = Buffer.from(input);
  for (let offset = -window; offset <= window; offset += 1) {
    const expected = Buffer.from(generateTotpToken(
      secret,
      timestampMs + (offset * stepSeconds * 1000),
      { digits, stepSeconds }
    ));
    if (expected.length === supplied.length && crypto.timingSafeEqual(expected, supplied)) return true;
  }
  return false;
}

function encryptionKey(secret) {
  return crypto.createHash("sha256").update(String(secret || "")).digest();
}

function encryptSecret(value, secret) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(secret), iv);
  const encrypted = Buffer.concat([cipher.update(String(value || ""), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", iv.toString("base64url"), tag.toString("base64url"), encrypted.toString("base64url")].join(":");
}

function decryptSecret(payload, secret) {
  const [version, ivText, tagText, encryptedText] = String(payload || "").split(":");
  if (version !== "v1" || !ivText || !tagText || !encryptedText) throw new Error("Invalid encrypted secret.");
  const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(secret), Buffer.from(ivText, "base64url"));
  decipher.setAuthTag(Buffer.from(tagText, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedText, "base64url")),
    decipher.final()
  ]).toString("utf8");
}

function validatePassword(password) {
  const value = String(password || "");
  const issues = [];
  if (value.length < 10) issues.push("Use at least 10 characters.");
  if (!/[a-z]/.test(value)) issues.push("Add a lowercase letter.");
  if (!/[A-Z]/.test(value)) issues.push("Add an uppercase letter.");
  if (!/\d/.test(value)) issues.push("Add a number.");
  if (/^(password|admin|guard|naap)/i.test(value)) issues.push("Avoid predictable words at the beginning.");
  return { valid: issues.length === 0, issues };
}

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
  }

  prune(key, now = Date.now()) {
    const cutoff = now - this.windowMs;
    const recent = (this.entries.get(String(key)) || []).filter((timestamp) => timestamp > cutoff);
    if (recent.length) this.entries.set(String(key), recent);
    else this.entries.delete(String(key));
    return recent;
  }

  check(key, now = Date.now()) {
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

  recordFailure(key, now = Date.now()) {
    const recent = this.prune(key, now);
    recent.push(now);
    this.entries.set(String(key), recent);
    return this.check(key, now);
  }

  reset(key) {
    this.entries.delete(String(key));
  }
}

module.exports = {
  SlidingWindowRateLimiter,
  decodeBase32,
  decryptSecret,
  encodeBase32,
  encryptSecret,
  generateTotpSecret,
  generateTotpToken,
  hashIdentifier,
  validatePassword,
  verifyTotpToken
};
