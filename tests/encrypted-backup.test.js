const test = require("node:test");
const assert = require("node:assert/strict");
const {
  BackupValidationError,
  decryptBackup,
  encryptBackup,
  summarizeBackupPayload
} = require("../lib/encrypted-backup");

test("encrypted backups round-trip without exposing their contents", () => {
  const source = {
    created_at: "2026-09-08T00:00:00.000Z",
    datasets: {
      students: { columns: ["student_number"], rows: [{ student_number: "2026-001" }] },
      vehicles: { columns: ["plate_number"], rows: [] }
    }
  };
  const encrypted = encryptBackup(source, "correct horse battery staple");
  assert.doesNotMatch(encrypted, /2026-001/);
  assert.deepEqual(decryptBackup(encrypted, "correct horse battery staple"), source);
  assert.deepEqual(summarizeBackupPayload(source), { students: 1, vehicles: 0 });
});

test("encrypted backups reject wrong passwords, tampering, and weak passphrases", () => {
  const encrypted = encryptBackup({ datasets: {} }, "correct horse battery staple");
  assert.throws(() => decryptBackup(encrypted, "incorrect password"), BackupValidationError);
  assert.throws(() => encryptBackup({ datasets: {} }, "too-short"), BackupValidationError);
  assert.throws(() => decryptBackup("not-json", "correct horse battery staple"), BackupValidationError);
});
