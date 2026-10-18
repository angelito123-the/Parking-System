-- Additive migration: existing scan records, gate text, and assignments are retained.
CREATE TABLE IF NOT EXISTS gates (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(80) NOT NULL UNIQUE,
  type ENUM('entry', 'exit', 'both') NOT NULL DEFAULT 'both'
);

-- Gate 5 is retained for installations already using the fifth gate.
-- INSERT IGNORE preserves administrator changes on subsequent deployments.
INSERT IGNORE INTO gates (name, type) VALUES
  ('Gate 1', 'both'), ('Gate 2', 'both'), ('Gate 3', 'both'),
  ('Gate 4', 'exit'), ('Gate 5', 'both');

CREATE TABLE IF NOT EXISTS vehicle_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  vehicle_id INT NULL,
  guard_id INT NULL,
  gate_id INT NULL,
  scan_log_id INT NULL UNIQUE,
  scan_type ENUM('entry', 'exit') NOT NULL,
  scanned_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  vehicle_plate VARCHAR(30) NULL,
  guard_name VARCHAR(120) NULL,
  gate_name VARCHAR(80) NULL,
  INDEX idx_vehicle_logs_vehicle_time (vehicle_id, scanned_at, id),
  INDEX idx_vehicle_logs_gate_time (gate_id, scanned_at, id),
  INDEX idx_vehicle_logs_time (scanned_at, id),
  INDEX idx_vehicle_logs_type_time (scan_type, scanned_at, id),
  CONSTRAINT fk_vehicle_logs_vehicle FOREIGN KEY (vehicle_id) REFERENCES vehicles(id) ON DELETE SET NULL,
  CONSTRAINT fk_vehicle_logs_guard FOREIGN KEY (guard_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_vehicle_logs_gate FOREIGN KEY (gate_id) REFERENCES gates(id) ON DELETE SET NULL,
  CONSTRAINT fk_vehicle_logs_scan FOREIGN KEY (scan_log_id) REFERENCES scan_logs(id) ON DELETE SET NULL
);

-- Keep unknown historical actors/gates nullable instead of inventing identities.
INSERT INTO vehicle_logs
  (vehicle_id, guard_id, gate_id, scan_log_id, scan_type, scanned_at, vehicle_plate, guard_name, gate_name)
SELECT v.id, u.id, g.id, sl.id, LOWER(sl.action), sl.scanned_at,
       v.plate_number, sl.assigned_by_guard, COALESCE(sl.gate_id, sl.gate)
FROM scan_logs sl
LEFT JOIN stickers s ON s.id = sl.sticker_id
LEFT JOIN vehicles v ON v.id = COALESCE(sl.vehicle_id, s.vehicle_id)
LEFT JOIN users u ON u.username = sl.assigned_by_guard
LEFT JOIN gates g ON g.name = CASE COALESCE(sl.gate_id, sl.gate)
  WHEN 'Main Gate' THEN 'Gate 1' WHEN 'Side Gate' THEN 'Gate 2'
  WHEN 'North Gate' THEN 'Gate 3' WHEN 'South Gate' THEN 'Gate 4'
  ELSE COALESCE(sl.gate_id, sl.gate) END
LEFT JOIN vehicle_logs existing ON existing.scan_log_id = sl.id
WHERE sl.result = 'VALID' AND sl.action IN ('ENTRY', 'EXIT') AND existing.id IS NULL
ON DUPLICATE KEY UPDATE scan_log_id = VALUES(scan_log_id);
