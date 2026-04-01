CREATE DATABASE IF NOT EXISTS naap_parking;
USE naap_parking;

CREATE TABLE IF NOT EXISTS students (
  id INT PRIMARY KEY AUTO_INCREMENT,
  student_number VARCHAR(50) NOT NULL UNIQUE,
  full_name VARCHAR(150) NOT NULL,
  program VARCHAR(120),
  email VARCHAR(120),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vehicles (
  id INT PRIMARY KEY AUTO_INCREMENT,
  student_id INT NOT NULL,
  plate_number VARCHAR(30) NOT NULL UNIQUE,
  model VARCHAR(120),
  color VARCHAR(50),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
  CONSTRAINT fk_sticker_vehicle FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS parking_slots (
  id INT PRIMARY KEY AUTO_INCREMENT,
  slot_code VARCHAR(30) NOT NULL UNIQUE,
  zone VARCHAR(50) NOT NULL DEFAULT 'General',
  status ENUM('available', 'disabled') NOT NULL DEFAULT 'available',
  current_sticker_id INT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
  CONSTRAINT fk_auto_queue_sticker FOREIGN KEY (sticker_id) REFERENCES stickers(id) ON DELETE SET NULL,
  CONSTRAINT fk_auto_queue_student FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE SET NULL,
  CONSTRAINT fk_auto_queue_vehicle FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE SET NULL,
  CONSTRAINT fk_auto_queue_slot FOREIGN KEY (assigned_slot_id) REFERENCES parking_slots(id) ON DELETE SET NULL,
  CONSTRAINT fk_auto_queue_log FOREIGN KEY (linked_scan_log_id) REFERENCES scan_logs(id) ON DELETE SET NULL
);
