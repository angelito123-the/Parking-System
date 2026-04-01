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
  await ensureScanLogMigrations();
  await ensureAutoScanQueueMigrations();
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

async function constraintExists(tableName, constraintName) {
  const [rows] = await pool.query(
    `SELECT 1
     FROM information_schema.TABLE_CONSTRAINTS
     WHERE TABLE_SCHEMA = ?
       AND TABLE_NAME = ?
       AND CONSTRAINT_NAME = ?
     LIMIT 1`,
    [database, tableName, constraintName]
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

async function ensureScanLogMigrations() {
  async function addColumnIfMissing(tableName, columnName, columnDefinition) {
    if (await columnExists(tableName, columnName)) return;
    await pool.query(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDefinition}`);
  }

  try {
    await addColumnIfMissing("scan_logs", "gate_id", "VARCHAR(80) NULL AFTER gate");
    await addColumnIfMissing("scan_logs", "qr_value", "VARCHAR(120) NULL AFTER slot_id");
    await addColumnIfMissing("scan_logs", "student_id", "INT NULL AFTER qr_value");
    await addColumnIfMissing("scan_logs", "vehicle_id", "INT NULL AFTER student_id");
    await addColumnIfMissing("scan_logs", "assigned_area", "VARCHAR(80) NULL AFTER vehicle_id");
    await addColumnIfMissing("scan_logs", "assigned_by_guard", "VARCHAR(120) NULL AFTER assigned_area");
    await addColumnIfMissing("scan_logs", "scan_source", "VARCHAR(40) NOT NULL DEFAULT 'manual' AFTER assigned_by_guard");
    await addColumnIfMissing("scan_logs", "snapshot_path", "VARCHAR(255) NULL AFTER scan_source");
    await addColumnIfMissing("scan_logs", "status", "VARCHAR(40) NULL AFTER snapshot_path");
  } catch (error) {
    if (error.errno !== 1060) {
      throw error;
    }
  }

  try {
    await pool.query(`
      UPDATE scan_logs sl
      LEFT JOIN stickers s ON s.id = sl.sticker_id
      LEFT JOIN vehicles v ON v.id = s.vehicle_id
      LEFT JOIN students st ON st.id = v.student_id
      LEFT JOIN parking_slots ps ON ps.id = sl.slot_id
      SET
        sl.gate_id = COALESCE(sl.gate_id, sl.gate),
        sl.qr_value = COALESCE(sl.qr_value, s.qr_token),
        sl.student_id = COALESCE(sl.student_id, st.id),
        sl.vehicle_id = COALESCE(sl.vehicle_id, v.id),
        sl.assigned_area = COALESCE(sl.assigned_area, ps.zone),
        sl.scan_source = COALESCE(sl.scan_source, 'manual'),
        sl.status = COALESCE(
          sl.status,
          CASE
            WHEN sl.result = 'VALID' THEN 'AUTHORIZED'
            ELSE sl.result
          END
        )
    `);
  } catch (error) {
    console.warn("scan_logs backfill warning (non-fatal):", error.message);
  }

  if (!(await constraintExists("scan_logs", "fk_scan_student"))) {
    try {
      await pool.query(
        "ALTER TABLE scan_logs ADD CONSTRAINT fk_scan_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL"
      );
    } catch (error) {
      if (error.errno !== 1826 && error.errno !== 1061) {
        console.warn("scan_logs fk_scan_student warning (non-fatal):", error.message);
      }
    }
  }

  if (!(await constraintExists("scan_logs", "fk_scan_vehicle"))) {
    try {
      await pool.query(
        "ALTER TABLE scan_logs ADD CONSTRAINT fk_scan_vehicle FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE SET NULL"
      );
    } catch (error) {
      if (error.errno !== 1826 && error.errno !== 1061) {
        console.warn("scan_logs fk_scan_vehicle warning (non-fatal):", error.message);
      }
    }
  }
}

async function ensureAutoScanQueueMigrations() {
  await pool.query("SET FOREIGN_KEY_CHECKS = 0");
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS auto_scan_queue (
        id INT PRIMARY KEY AUTO_INCREMENT,
        sticker_id INT NULL,
        student_id INT NULL,
        vehicle_id INT NULL,
        qr_value VARCHAR(120) NOT NULL,
        gate_id VARCHAR(80) NULL,
        snapshot_path VARCHAR(255) NULL,
        scan_source VARCHAR(40) NOT NULL DEFAULT 'camera_phone',
        status ENUM('PENDING', 'CONFIRMED', 'CANCELLED', 'REJECTED', 'EXPIRED') NOT NULL DEFAULT 'PENDING',
        requested_by_guard VARCHAR(120) NULL,
        confirmed_by_guard VARCHAR(120) NULL,
        assigned_slot_id INT NULL,
        linked_scan_log_id INT NULL,
        confirm_note VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        confirmed_at TIMESTAMP NULL DEFAULT NULL,
        INDEX idx_auto_queue_status_created (status, created_at),
        INDEX idx_auto_queue_sticker_status (sticker_id, status),
        CONSTRAINT fk_auto_queue_sticker FOREIGN KEY (sticker_id) REFERENCES stickers(id) ON DELETE SET NULL,
        CONSTRAINT fk_auto_queue_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL,
        CONSTRAINT fk_auto_queue_vehicle FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE SET NULL,
        CONSTRAINT fk_auto_queue_slot FOREIGN KEY (assigned_slot_id) REFERENCES parking_slots(id) ON DELETE SET NULL,
        CONSTRAINT fk_auto_queue_log FOREIGN KEY (linked_scan_log_id) REFERENCES scan_logs(id) ON DELETE SET NULL
      )
    `);
  } finally {
    await pool.query("SET FOREIGN_KEY_CHECKS = 1");
  }
}

module.exports = {
  pool,
  ensureDatabaseSchema
};
