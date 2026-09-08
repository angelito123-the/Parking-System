const { pool } = require("../db");

const expectedTables = [
  "backup_archives",
  "backup_restore_previews",
  "email_delivery_attempts",
  "email_delivery_jobs",
  "parking_zone_settings",
  "sticker_qr_history"
];
const expectedUserColumns = ["disabled_at", "disabled_reason", "is_active", "must_change_password"];
const expectedSlotColumns = ["disabled_reason", "reserved_for", "slot_type"];

async function listSchemaValues(sql, params, key) {
  const [rows] = await pool.query(sql, params);
  return rows.map((row) => row[key]).sort();
}

async function main() {
  const [tables, userColumns, slotColumns] = await Promise.all([
    listSchemaValues(
      "SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?)",
      [expectedTables],
      "TABLE_NAME"
    ),
    listSchemaValues(
      "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users' AND COLUMN_NAME IN (?)",
      [expectedUserColumns],
      "COLUMN_NAME"
    ),
    listSchemaValues(
      "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'parking_slots' AND COLUMN_NAME IN (?)",
      [expectedSlotColumns],
      "COLUMN_NAME"
    )
  ]);

  const checks = [
    ["tables", tables, expectedTables],
    ["user columns", userColumns, expectedUserColumns],
    ["parking-slot columns", slotColumns, expectedSlotColumns]
  ];
  for (const [label, actual, expected] of checks) {
    if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) {
      throw new Error(`Operational schema check failed for ${label}.`);
    }
  }
  console.log("Operational database schema verified.");
}

main()
  .catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
