const mysql = require("mysql2/promise");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
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
  await ensureAutoScanHeartbeatMigrations();
  await ensureVisitorPassMigrations();
  await ensureAlertMigrations();
  await ensureUserMigrations();
  await ensureAnnouncementMigrations();
}

async function tableExists(tableName) {
  const [rows] = await pool.query(
    `SELECT 1
     FROM information_schema.TABLES
     WHERE TABLE_SCHEMA = ?
       AND TABLE_NAME = ?
     LIMIT 1`,
    [database, tableName]
  );
  return rows.length > 0;
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

async function ensureUserMigrations() {
  await pool.query("SET FOREIGN_KEY_CHECKS = 0");
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(80) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin', 'guard') NOT NULL,
        student_id INT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    if (!(await columnExists("users", "username"))) {
      await pool.query("ALTER TABLE users ADD COLUMN username VARCHAR(80) NOT NULL UNIQUE");
    }
    if (!(await columnExists("users", "password"))) {
      await pool.query("ALTER TABLE users ADD COLUMN password VARCHAR(255) NOT NULL");
    }
    if (!(await columnExists("users", "role"))) {
      await pool.query(
        "ALTER TABLE users ADD COLUMN role ENUM('admin', 'guard') NOT NULL DEFAULT 'guard' AFTER password"
      );
    }
    if (!(await columnExists("users", "student_id"))) {
      await pool.query("ALTER TABLE users ADD COLUMN student_id INT NULL AFTER role");
    }
    if (!(await columnExists("users", "updated_at"))) {
      await pool.query(
        "ALTER TABLE users ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"
      );
    }
  } finally {
    await pool.query("SET FOREIGN_KEY_CHECKS = 1");
  }

  if (!(await constraintExists("users", "fk_users_student"))) {
    try {
      await pool.query(
        "ALTER TABLE users ADD CONSTRAINT fk_users_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL"
      );
    } catch (error) {
      if (error.errno !== 1826 && error.errno !== 1061) {
        console.warn("users fk_users_student warning (non-fatal):", error.message);
      }
    }
  }

  // Normalize legacy role values before tightening enum values.
  await pool.query(
    `UPDATE users
     SET
       role = CASE
         WHEN role = 'admin' THEN 'admin'
         WHEN role = 'guard' THEN 'guard'
         ELSE 'guard'
       END`
  );

  try {
    await pool.query(
      "ALTER TABLE users MODIFY COLUMN role ENUM('admin', 'guard') NOT NULL DEFAULT 'guard'"
    );
  } catch (error) {
    console.warn("users role enum migration warning (non-fatal):", error.message);
  }

  const defaultUsers = [
    {
      username: String(process.env.ADMIN_USERNAME || "admin").trim(),
      password: String(process.env.ADMIN_PASSWORD || "naap2024"),
      role: "admin",
      studentId: null
    },
    {
      username: String(process.env.GUARD_USERNAME || "guard").trim(),
      password: String(process.env.GUARD_PASSWORD || "guard123"),
      role: "guard",
      studentId: null
    }
  ];

  for (const seededUser of defaultUsers) {
    if (!seededUser.username || !seededUser.password) continue;

    const [existingRows] = await pool.query(
      "SELECT id, role, password FROM users WHERE username = ? LIMIT 1",
      [seededUser.username]
    );

    if (!existingRows.length) {
      const hashedPassword = await bcrypt.hash(seededUser.password, 10);
      await pool.query(
        "INSERT INTO users (username, password, role, student_id) VALUES (?, ?, ?, ?)",
        [seededUser.username, hashedPassword, seededUser.role, seededUser.studentId]
      );
      continue;
    }

    const existingUser = existingRows[0];
    const rawPassword = String(existingUser.password || "");
    if (rawPassword && !rawPassword.startsWith("$2")) {
      const migratedHash = await bcrypt.hash(rawPassword, 10);
      await pool.query("UPDATE users SET password = ? WHERE id = ?", [migratedHash, existingUser.id]);
    }
  }
}

async function ensureAnnouncementMigrations() {
  if (!(await tableExists("announcements"))) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS announcements (
        id INT PRIMARY KEY AUTO_INCREMENT,
        title VARCHAR(150) NOT NULL,
        body TEXT NOT NULL,
        published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  await pool.query(`
    INSERT IGNORE INTO announcements (id, title, body) VALUES
      (1, 'Welcome to NAAP Parking', 'Use your assigned QR and follow guard instructions when entering campus.'),
      (2, 'Gate Reminder', 'Always park only in the assigned slot to avoid violations and delayed exit processing.')
  `);
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

async function ensureAutoScanHeartbeatMigrations() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS auto_scan_heartbeats (
      id INT PRIMARY KEY AUTO_INCREMENT,
      device_id VARCHAR(120) NOT NULL UNIQUE,
      gate_id VARCHAR(80) NULL,
      last_heartbeat_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_scan_received_at TIMESTAMP NULL DEFAULT NULL,
      last_seen_user VARCHAR(120) NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      INDEX idx_auto_scan_heartbeat_last (last_heartbeat_at)
    )
  `);
}

async function ensureVisitorPassMigrations() {
  await pool.query("SET FOREIGN_KEY_CHECKS = 0");
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS visitor_passes (
        id INT PRIMARY KEY AUTO_INCREMENT,
        pass_code VARCHAR(40) NOT NULL UNIQUE,
        qr_token VARCHAR(120) NOT NULL UNIQUE,
        visitor_type ENUM('visitor', 'parent', 'supplier', 'delivery', 'service', 'temporary') NOT NULL DEFAULT 'visitor',
        visitor_name VARCHAR(150) NOT NULL,
        organization VARCHAR(150) NULL,
        contact_number VARCHAR(60) NULL,
        plate_number VARCHAR(30) NULL,
        vehicle_type VARCHAR(80) NULL,
        purpose VARCHAR(255) NULL,
        requested_by VARCHAR(120) NULL,
        approval_status ENUM('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED') NOT NULL DEFAULT 'PENDING',
        approved_by VARCHAR(120) NULL,
        approved_at TIMESTAMP NULL DEFAULT NULL,
        approval_note VARCHAR(255) NULL,
        pass_state ENUM('PENDING', 'ACTIVE', 'INSIDE', 'EXITED', 'EXPIRED', 'REVOKED') NOT NULL DEFAULT 'PENDING',
        valid_from DATETIME NOT NULL,
        valid_until DATETIME NOT NULL,
        assigned_zone VARCHAR(80) NULL,
        assigned_slot_id INT NULL,
        last_entry_at DATETIME NULL,
        last_exit_at DATETIME NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_visitor_pass_status (approval_status, pass_state),
        INDEX idx_visitor_pass_valid_until (valid_until),
        INDEX idx_visitor_pass_plate (plate_number),
        CONSTRAINT fk_visitor_pass_slot FOREIGN KEY (assigned_slot_id) REFERENCES parking_slots(id) ON DELETE SET NULL
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS visitor_scan_logs (
        id INT PRIMARY KEY AUTO_INCREMENT,
        visitor_pass_id INT NOT NULL,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        result VARCHAR(20) NOT NULL,
        action ENUM('ENTRY', 'EXIT', 'VERIFY', 'DENIED') NOT NULL DEFAULT 'VERIFY',
        gate VARCHAR(80) NULL,
        gate_id VARCHAR(80) NULL,
        slot_id INT NULL,
        qr_value VARCHAR(120) NULL,
        assigned_by_guard VARCHAR(120) NULL,
        scan_source VARCHAR(40) NOT NULL DEFAULT 'manual',
        snapshot_path VARCHAR(255) NULL,
        status VARCHAR(40) NULL,
        reason VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_visitor_scan_pass_time (visitor_pass_id, scanned_at),
        INDEX idx_visitor_scan_result_time (result, scanned_at),
        CONSTRAINT fk_visitor_scan_pass FOREIGN KEY (visitor_pass_id) REFERENCES visitor_passes(id) ON DELETE CASCADE,
        CONSTRAINT fk_visitor_scan_slot FOREIGN KEY (slot_id) REFERENCES parking_slots(id) ON DELETE SET NULL
      )
    `);

    if (!(await columnExists("parking_slots", "current_visitor_pass_id"))) {
      await pool.query("ALTER TABLE parking_slots ADD COLUMN current_visitor_pass_id INT NULL AFTER current_sticker_id");
    }

    await pool.query(`
      INSERT IGNORE INTO parking_slots (slot_code, zone) VALUES
        ('V-01', 'Visitor Zone'),
        ('V-02', 'Visitor Zone'),
        ('V-03', 'Visitor Zone'),
        ('V-04', 'Visitor Zone'),
        ('V-05', 'Visitor Zone'),
        ('V-06', 'Visitor Zone')
    `);
  } finally {
    await pool.query("SET FOREIGN_KEY_CHECKS = 1");
  }

  if (!(await constraintExists("parking_slots", "fk_parking_slot_visitor_pass"))) {
    try {
      await pool.query(
        "ALTER TABLE parking_slots ADD CONSTRAINT fk_parking_slot_visitor_pass FOREIGN KEY (current_visitor_pass_id) REFERENCES visitor_passes(id) ON DELETE SET NULL"
      );
    } catch (error) {
      if (error.errno !== 1826 && error.errno !== 1061) {
        console.warn("parking_slots fk_parking_slot_visitor_pass warning (non-fatal):", error.message);
      }
    }
  }
}

async function ensureAlertMigrations() {
  await pool.query("SET FOREIGN_KEY_CHECKS = 0");
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS alerts (
        id INT PRIMARY KEY AUTO_INCREMENT,
        type VARCHAR(80) NOT NULL,
        title VARCHAR(180) NOT NULL,
        message TEXT NOT NULL,
        severity ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
        audience_role ENUM('admin', 'guard', 'student', 'staff', 'all') NOT NULL DEFAULT 'staff',
        related_user_id INT NULL,
        related_vehicle_id INT NULL,
        related_visitor_pass_id INT NULL,
        related_qr_id VARCHAR(120) NULL,
        related_zone_id VARCHAR(80) NULL,
        related_gate_id VARCHAR(80) NULL,
        related_scan_log_id INT NULL,
        related_pending_entry_id INT NULL,
        source VARCHAR(80) NULL,
        status ENUM('active', 'resolved') NOT NULL DEFAULT 'active',
        is_read TINYINT(1) NOT NULL DEFAULT 0,
        dedupe_key VARCHAR(190) NULL,
        metadata_json JSON NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP NULL DEFAULT NULL,
        resolved_by VARCHAR(120) NULL,
        INDEX idx_alert_type_created (type, created_at),
        INDEX idx_alert_status_created (status, created_at),
        INDEX idx_alert_severity_created (severity, created_at),
        INDEX idx_alert_audience_status (audience_role, status),
        INDEX idx_alert_zone_status (related_zone_id, status),
        INDEX idx_alert_pending_status (related_pending_entry_id, status),
        INDEX idx_alert_dedupe_status (dedupe_key, status),
        CONSTRAINT fk_alert_user FOREIGN KEY (related_user_id) REFERENCES users(id) ON DELETE SET NULL,
        CONSTRAINT fk_alert_vehicle FOREIGN KEY (related_vehicle_id) REFERENCES vehicles(id) ON DELETE SET NULL,
        CONSTRAINT fk_alert_visitor_pass FOREIGN KEY (related_visitor_pass_id) REFERENCES visitor_passes(id) ON DELETE SET NULL,
        CONSTRAINT fk_alert_scan_log FOREIGN KEY (related_scan_log_id) REFERENCES scan_logs(id) ON DELETE SET NULL,
        CONSTRAINT fk_alert_pending_entry FOREIGN KEY (related_pending_entry_id) REFERENCES auto_scan_queue(id) ON DELETE SET NULL
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS alert_reads (
        id INT PRIMARY KEY AUTO_INCREMENT,
        alert_id INT NOT NULL,
        user_id INT NOT NULL,
        read_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_alert_reads (alert_id, user_id),
        INDEX idx_alert_reads_user_read (user_id, read_at),
        CONSTRAINT fk_alert_reads_alert FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
        CONSTRAINT fk_alert_reads_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
  } finally {
    await pool.query("SET FOREIGN_KEY_CHECKS = 1");
  }

  // Backward compatible column additions for deployments that may already have alerts table.
  async function addAlertColumnIfMissing(columnName, columnDefinition) {
    if (await columnExists("alerts", columnName)) return;
    await pool.query(`ALTER TABLE alerts ADD COLUMN ${columnName} ${columnDefinition}`);
  }

  try {
    await addAlertColumnIfMissing("is_read", "TINYINT(1) NOT NULL DEFAULT 0 AFTER status");
    await addAlertColumnIfMissing("dedupe_key", "VARCHAR(190) NULL AFTER is_read");
    await addAlertColumnIfMissing("metadata_json", "JSON NULL AFTER dedupe_key");
    await addAlertColumnIfMissing("related_scan_log_id", "INT NULL AFTER related_gate_id");
    await addAlertColumnIfMissing("related_pending_entry_id", "INT NULL AFTER related_scan_log_id");
    await addAlertColumnIfMissing("related_visitor_pass_id", "INT NULL AFTER related_vehicle_id");
  } catch (error) {
    if (error.errno !== 1060) {
      throw error;
    }
  }

  if (!(await constraintExists("alerts", "fk_alert_visitor_pass"))) {
    try {
      await pool.query(
        "ALTER TABLE alerts ADD CONSTRAINT fk_alert_visitor_pass FOREIGN KEY (related_visitor_pass_id) REFERENCES visitor_passes(id) ON DELETE SET NULL"
      );
    } catch (error) {
      if (error.errno !== 1826 && error.errno !== 1061) {
        console.warn("alerts fk_alert_visitor_pass warning (non-fatal):", error.message);
      }
    }
  }
}

module.exports = {
  pool,
  ensureDatabaseSchema
};
