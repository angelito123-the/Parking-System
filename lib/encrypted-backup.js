const crypto = require("crypto");

const BACKUP_FORMAT = "naap-encrypted-backup";
const BACKUP_VERSION = 1;
const MAX_ENCRYPTED_BACKUP_BYTES = 20 * 1024 * 1024;

class BackupValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "BackupValidationError";
    this.code = "INVALID_BACKUP";
  }
}

function validateBackupPassphrase(passphrase) {
  const value = String(passphrase || "");
  if (value.length < 12 || value.length > 256) {
    throw new BackupValidationError("Backup passphrase must contain between 12 and 256 characters.");
  }
  return value;
}

function deriveKey(passphrase, salt) {
  return crypto.scryptSync(validateBackupPassphrase(passphrase), salt, 32, {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024
  });
}

function encryptBackup(payload, passphrase) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new BackupValidationError("Backup payload must be an object.");
  }
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  if (plaintext.length > MAX_ENCRYPTED_BACKUP_BYTES) {
    throw new BackupValidationError("Backup payload exceeds the 20 MB safety limit.");
  }

  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return JSON.stringify({
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    algorithm: "aes-256-gcm+scrypt",
    created_at: new Date().toISOString(),
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    auth_tag: authTag.toString("base64"),
    ciphertext: ciphertext.toString("base64")
  });
}

function decodeBase64Field(container, field, expectedLength = null) {
  const value = String(container?.[field] || "");
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new BackupValidationError(`Backup ${field} is invalid.`);
  }
  const decoded = Buffer.from(value, "base64");
  if (!decoded.length || (expectedLength && decoded.length !== expectedLength)) {
    throw new BackupValidationError(`Backup ${field} has an invalid length.`);
  }
  return decoded;
}

function decryptBackup(serializedBackup, passphrase) {
  const serialized = String(serializedBackup || "");
  if (!serialized || Buffer.byteLength(serialized, "utf8") > MAX_ENCRYPTED_BACKUP_BYTES * 2) {
    throw new BackupValidationError("Encrypted backup is empty or exceeds the safety limit.");
  }

  let container;
  try {
    container = JSON.parse(serialized);
  } catch (_error) {
    throw new BackupValidationError("Encrypted backup is not valid JSON.");
  }
  if (container?.format !== BACKUP_FORMAT || Number(container?.version) !== BACKUP_VERSION) {
    throw new BackupValidationError("Encrypted backup format or version is not supported.");
  }

  const salt = decodeBase64Field(container, "salt", 16);
  const iv = decodeBase64Field(container, "iv", 12);
  const authTag = decodeBase64Field(container, "auth_tag", 16);
  const ciphertext = decodeBase64Field(container, "ciphertext");
  const key = deriveKey(passphrase, salt);

  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    const payload = JSON.parse(plaintext.toString("utf8"));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new Error("Invalid payload.");
    return payload;
  } catch (_error) {
    throw new BackupValidationError("Backup could not be decrypted. Check the passphrase and file integrity.");
  }
}

function summarizeBackupPayload(payload) {
  const datasets = payload?.datasets && typeof payload.datasets === "object" ? payload.datasets : {};
  return Object.fromEntries(
    Object.entries(datasets).map(([key, value]) => [key, Array.isArray(value?.rows) ? value.rows.length : 0])
  );
}

module.exports = {
  BACKUP_FORMAT,
  BACKUP_VERSION,
  BackupValidationError,
  decryptBackup,
  encryptBackup,
  summarizeBackupPayload,
  validateBackupPassphrase
};
