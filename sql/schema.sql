CREATE DATABASE IF NOT EXISTS naap_parking;
USE naap_parking;

CREATE TABLE IF NOT EXISTS students (
  id INT PRIMARY KEY AUTO_INCREMENT,
  student_number VARCHAR(50) NOT NULL UNIQUE,
  full_name VARCHAR(150) NOT NULL,
  program VARCHAR(120),
  year_level VARCHAR(20),
  email VARCHAR(120),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_students_name (full_name),
  INDEX idx_students_program_year (program, year_level)
);

CREATE TABLE IF NOT EXISTS users (
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(80) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('admin', 'guard') NOT NULL,
  student_id INT NULL,
  totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
  totp_secret_encrypted TEXT NULL,
  password_changed_at TIMESTAMP NULL DEFAULT NULL,
  last_login_at TIMESTAMP NULL DEFAULT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_users_role_updated (role, updated_at),
  CONSTRAINT fk_users_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS announcements (
  id INT PRIMARY KEY AUTO_INCREMENT,
  title VARCHAR(150) NOT NULL,
  body TEXT NOT NULL,
  published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT IGNORE INTO announcements (id, title, body) VALUES
  (1, 'Welcome to NAAP Parking', 'Use your assigned QR and follow guard instructions when entering campus.'),
  (2, 'Gate Reminder', 'Always park only in the assigned slot to avoid violations and delayed exit processing.');

CREATE TABLE IF NOT EXISTS vehicles (
  id INT PRIMARY KEY AUTO_INCREMENT,
  student_id INT NOT NULL,
  plate_number VARCHAR(30) NOT NULL UNIQUE,
  model VARCHAR(120),
  color VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_vehicles_student (student_id),
  CONSTRAINT fk_vehicle_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS stickers (
  id INT PRIMARY KEY AUTO_INCREMENT,
  vehicle_id INT NOT NULL,
  sticker_code VARCHAR(60) NOT NULL UNIQUE,
  qr_token VARCHAR(80) NOT NULL UNIQUE,
  status ENUM('active', 'revoked') NOT NULL DEFAULT 'active',
  issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  expires_at DATE NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_stickers_status_expiry (status, expires_at),
  INDEX idx_stickers_vehicle_status (vehicle_id, status),
  CONSTRAINT fk_sticker_vehicle FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS parking_slots (
  id INT PRIMARY KEY AUTO_INCREMENT,
  slot_code VARCHAR(30) NOT NULL UNIQUE,
  zone VARCHAR(50) NOT NULL DEFAULT 'General',
  status ENUM('available', 'disabled') NOT NULL DEFAULT 'available',
  current_sticker_id INT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_slots_status_zone (status, zone),
  INDEX idx_slots_current_sticker (current_sticker_id),
  CONSTRAINT fk_parking_slot_sticker FOREIGN KEY (current_sticker_id) REFERENCES stickers(id) ON DELETE SET NULL
);

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
  ('B-10', 'Zone B');

CREATE TABLE IF NOT EXISTS scan_logs (
  id INT PRIMARY KEY AUTO_INCREMENT,
  sticker_id INT NULL,
  scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  result ENUM('VALID', 'INVALID', 'REVOKED', 'EXPIRED') NOT NULL,
  action ENUM('ENTRY', 'EXIT', 'VERIFY') NOT NULL DEFAULT 'VERIFY',
  gate VARCHAR(80),
  gate_id VARCHAR(80) NULL,
  slot_id INT NULL,
  qr_value VARCHAR(120) NULL,
  student_id INT NULL,
  vehicle_id INT NULL,
  assigned_area VARCHAR(80) NULL,
  assigned_by_guard VARCHAR(120) NULL,
  scan_source VARCHAR(40) NOT NULL DEFAULT 'manual',
  snapshot_path VARCHAR(255) NULL,
  status VARCHAR(40) NULL,
  notes VARCHAR(255),
  INDEX idx_scan_result_time_action (result, scanned_at, action),
  INDEX idx_scan_sticker_movement (sticker_id, result, action, scanned_at),
  INDEX idx_scan_time_id (scanned_at, id),
  INDEX idx_scan_gate_time (gate_id, scanned_at),
  INDEX idx_scan_vehicle_time (vehicle_id, scanned_at),
  INDEX idx_scan_student_time (student_id, scanned_at),
  INDEX idx_scan_source_time (scan_source, scanned_at),
  CONSTRAINT fk_scan_sticker FOREIGN KEY (sticker_id) REFERENCES stickers(id) ON DELETE SET NULL,
  CONSTRAINT fk_scan_slot FOREIGN KEY (slot_id) REFERENCES parking_slots(id) ON DELETE SET NULL,
  CONSTRAINT fk_scan_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL,
  CONSTRAINT fk_scan_vehicle FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE SET NULL
);

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
  INDEX idx_auto_queue_gate_status (gate_id, status, created_at),
  CONSTRAINT fk_auto_queue_sticker FOREIGN KEY (sticker_id) REFERENCES stickers(id) ON DELETE SET NULL,
  CONSTRAINT fk_auto_queue_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL,
  CONSTRAINT fk_auto_queue_vehicle FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE SET NULL,
  CONSTRAINT fk_auto_queue_slot FOREIGN KEY (assigned_slot_id) REFERENCES parking_slots(id) ON DELETE SET NULL,
  CONSTRAINT fk_auto_queue_log FOREIGN KEY (linked_scan_log_id) REFERENCES scan_logs(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS auto_scan_heartbeats (
  id INT PRIMARY KEY AUTO_INCREMENT,
  device_id VARCHAR(120) NOT NULL UNIQUE,
  gate_id VARCHAR(80) NULL,
  last_heartbeat_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_scan_received_at TIMESTAMP NULL DEFAULT NULL,
  last_seen_user VARCHAR(120) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_auto_scan_heartbeat_last (last_heartbeat_at),
  INDEX idx_auto_heartbeat_gate_last (gate_id, last_heartbeat_at)
);

CREATE TABLE IF NOT EXISTS scan_snapshots (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  storage_key VARCHAR(120) NOT NULL UNIQUE,
  mime_type VARCHAR(40) NOT NULL,
  image_data LONGBLOB NOT NULL,
  byte_size INT UNSIGNED NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_scan_snapshots_created (created_at)
);

CREATE TABLE IF NOT EXISTS scanner_metrics (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  event_id VARCHAR(80) NOT NULL UNIQUE,
  device_id VARCHAR(120) NULL,
  gate_id VARCHAR(80) NULL,
  outcome VARCHAR(32) NOT NULL,
  movement_action VARCHAR(20) NULL,
  detection_model VARCHAR(80) NULL,
  detection_confidence DECIMAL(6,5) NULL,
  readiness_score DECIMAL(6,5) NULL,
  process_ms INT UNSIGNED NULL,
  time_to_read_ms INT UNSIGNED NULL,
  unreadable_frames INT UNSIGNED NOT NULL DEFAULT 0,
  guidance_key VARCHAR(40) NULL,
  failure_reason VARCHAR(120) NULL,
  network_mode VARCHAR(20) NOT NULL DEFAULT 'online',
  device_class VARCHAR(30) NULL,
  browser_family VARCHAR(40) NULL,
  learning_samples INT UNSIGNED NOT NULL DEFAULT 0,
  user_id INT NULL,
  occurred_at DATETIME NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_scanner_metrics_created_outcome (created_at, outcome),
  INDEX idx_scanner_metrics_gate_created (gate_id, created_at),
  INDEX idx_scanner_metrics_device_created (device_id, created_at),
  CONSTRAINT fk_scanner_metrics_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS offline_sync_receipts (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  event_id VARCHAR(80) NOT NULL UNIQUE,
  sticker_id INT NULL,
  action VARCHAR(20) NULL,
  scan_log_id INT NULL,
  synced_by_user_id INT NULL,
  occurred_at DATETIME NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_offline_receipts_created (created_at),
  CONSTRAINT fk_offline_receipt_sticker FOREIGN KEY (sticker_id) REFERENCES stickers(id) ON DELETE SET NULL,
  CONSTRAINT fk_offline_receipt_scan_log FOREIGN KEY (scan_log_id) REFERENCES scan_logs(id) ON DELETE SET NULL,
  CONSTRAINT fk_offline_receipt_user FOREIGN KEY (synced_by_user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS security_audit_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  event_type VARCHAR(80) NOT NULL,
  actor_user_id INT NULL,
  actor_username VARCHAR(120) NULL,
  actor_role VARCHAR(30) NULL,
  target_type VARCHAR(80) NULL,
  target_id VARCHAR(120) NULL,
  outcome VARCHAR(30) NOT NULL DEFAULT 'success',
  ip_hash VARCHAR(32) NULL,
  user_agent VARCHAR(255) NULL,
  metadata_json JSON NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_security_audit_created (created_at),
  INDEX idx_security_audit_actor_created (actor_user_id, created_at),
  INDEX idx_security_audit_event_created (event_type, created_at),
  CONSTRAINT fk_security_audit_user FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
);
