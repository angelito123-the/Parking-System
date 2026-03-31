const mysql = require("mysql2/promise");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const host = process.env.DB_HOST || process.env.MYSQLHOST || "localhost";
const port = Number(process.env.DB_PORT || process.env.MYSQLPORT || 3306);
const user = process.env.DB_USER || process.env.MYSQLUSER || "root";
const password = process.env.DB_PASSWORD || process.env.MYSQLPASSWORD || "";
const database = process.env.DB_NAME || process.env.MYSQLDATABASE || "naap_parking";

const pool = mysql.createPool({
  host,
  port,
  user,
  password,
  database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  multipleStatements: true,
  timezone: 'Z'
});

async function ensureDatabaseSchema() {
  const schemaPath = path.join(__dirname, "sql", "schema.sql");
  const schemaSql = fs.readFileSync(schemaPath, "utf8");

  // Force schema creation in the currently configured DB (Railway uses "railway" by default).
  const sql = schemaSql
    .replace(/CREATE DATABASE IF NOT EXISTS .*?;\s*/i, "")
    .replace(/USE .*?;\s*/i, "");

  await pool.query(sql);
  await ensureParkingSlotMigrations();
}

async function columnExists(tableName, columnName) {
  const [rows] = await pool.query(
    `SELECT 1
     FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA = ?
       AND TABLE_NAME = ?
       AND COLUMN_NAME = ?
     LIMIT 1`,
    [database, tableName, columnName]
  );
  return rows.length > 0;
}

async function ensureParkingSlotMigrations() {
  // Disable FK checks so we can create tables regardless of reference order
  await pool.query("SET FOREIGN_KEY_CHECKS = 0");

  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS parking_slots (
        id INT PRIMARY KEY AUTO_INCREMENT,
        slot_code VARCHAR(30) NOT NULL UNIQUE,
        zone VARCHAR(50) NOT NULL DEFAULT 'General',
        status ENUM('available', 'disabled') NOT NULL DEFAULT 'available',
        current_sticker_id INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Add FK separately — safe to ignore if it already exists
    try {
      await pool.query(`
        ALTER TABLE parking_slots
        ADD CONSTRAINT fk_parking_slot_sticker
        FOREIGN KEY (current_sticker_id) REFERENCES stickers(id) ON DELETE SET NULL
      `);
    } catch (e) {
      if (!e.message.includes("Duplicate") && !e.message.includes("already exists") && e.errno !== 1826 && e.errno !== 1060) {
        console.warn("parking_slots FK warning (non-fatal):", e.message);
      }
    }

    if (!(await columnExists("scan_logs", "slot_id"))) {
      try {
        await pool.query("ALTER TABLE scan_logs ADD COLUMN slot_id INT NULL AFTER gate");
      } catch (e) {
        if (e.errno !== 1060) console.warn("scan_logs slot_id warning:", e.message);
      }
      try {
        await pool.query(
          "ALTER TABLE scan_logs ADD CONSTRAINT fk_scan_slot FOREIGN KEY (slot_id) REFERENCES parking_slots(id) ON DELETE SET NULL"
        );
      } catch (e) {
        if (!e.message.includes("Duplicate") && e.errno !== 1826) {
          console.warn("scan_logs FK warning (non-fatal):", e.message);
        }
      }
    }

    await pool.query(`
      INSERT IGNORE INTO parking_slots (slot_code, zone) VALUES
        ('A-01', 'Zone A'),
        ('A-02', 'Zone A'),
        ('A-03', 'Zone A'),
        ('A-04', 'Zone A'),
        ('A-05', 'Zone A'),
        ('A-06', 'Zone A'),
        ('A-07', 'Zone A'),
        ('A-08', 'Zone A'),
        ('A-09', 'Zone A'),
        ('A-10', 'Zone A'),
        ('B-01', 'Zone B'),
        ('B-02', 'Zone B'),
        ('B-03', 'Zone B'),
        ('B-04', 'Zone B'),
        ('B-05', 'Zone B'),
        ('B-06', 'Zone B'),
        ('B-07', 'Zone B'),
        ('B-08', 'Zone B'),
        ('B-09', 'Zone B'),
        ('B-10', 'Zone B')
    `);
  } finally {
    await pool.query("SET FOREIGN_KEY_CHECKS = 1");
  }
}

module.exports = {
  pool,
  ensureDatabaseSchema
};
