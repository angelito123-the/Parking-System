const fs = require('node:fs');

class GateLoggingError extends Error {
  constructor(message, code = 'INVALID_GATE', status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const aliases = new Map([
  ['Main Gate', 'Gate 1'], ['Side Gate', 'Gate 2'],
  ['North Gate', 'Gate 3'], ['South Gate', 'Gate 4']
]);

// The checked-in migration is additive and safe to repeat after a deployment.
async function migrate(db, filename) {
  const sql = fs.readFileSync(filename, 'utf8').replace(/^--.*$/gm, '');
  for (const statement of sql.split(';').map(value => value.trim()).filter(Boolean)) {
    await db.query(statement);
  }
}

async function listGates(db) {
  const [rows] = await db.query('SELECT id, name, type FROM gates ORDER BY id');
  return rows;
}

async function resolveGate(db, value) {
  if (!['string', 'number'].includes(typeof value)) throw new GateLoggingError('Select a valid gate.');
  const input = String(value).trim();
  if (!input || input.length > 80) throw new GateLoggingError('Select a valid gate.');
  const numeric = /^\d+$/.test(input);
  if (numeric) integer(input, 'gate', null);
  const [rows] = await db.query(
    numeric ? 'SELECT id, name, type FROM gates WHERE id = ?' : 'SELECT id, name, type FROM gates WHERE name = ?',
    [numeric ? Number(input) : aliases.get(input) || input]
  );
  if (!rows.length) throw new GateLoggingError('The selected gate is not configured. Choose a gate from the list.');
  return rows[0];
}

function assertGateDirection(gate, action) {
  const direction = String(action).toLowerCase();
  if (!['entry', 'exit'].includes(direction)) throw new GateLoggingError('Invalid movement type.');
  if (gate.type !== 'both' && gate.type !== direction) {
    throw new GateLoggingError(`${gate.name} is ${gate.type}-only. This vehicle requires ${direction}. Use a gate that allows ${direction}.`, 'GATE_DIRECTION_MISMATCH', 409);
  }
}

// Lock by vehicle, so two stickers/devices cannot record conflicting movements.
async function vehicleForSticker(db, stickerId, lock = false) {
  const [rows] = await db.query(
    `SELECT v.id, v.plate_number FROM vehicles v JOIN stickers s ON s.vehicle_id = v.id WHERE s.id = ?${lock ? ' FOR UPDATE' : ''}`,
    [stickerId]
  );
  if (!rows.length) throw new GateLoggingError('Vehicle registration was not found.', 'INVALID_VEHICLE', 404);
  return rows[0];
}

async function lastMovement(db, stickerId, lock = false) {
  const vehicle = await vehicleForSticker(db, stickerId, lock);
  const [rows] = await db.query(
    `SELECT vl.scan_log_id AS id, UPPER(vl.scan_type) AS action, vl.scanned_at, sl.slot_id
     FROM vehicle_logs vl LEFT JOIN scan_logs sl ON sl.id = vl.scan_log_id
     WHERE vl.vehicle_id = ? ORDER BY vl.scanned_at DESC, vl.id DESC LIMIT 1`,
    [vehicle.id]
  );
  return rows[0] || null;
}

async function validateMovement(db, { stickerId, action, gate, cooldownSeconds, scannedAt, administrativeOverride }) {
  const vehicle = await vehicleForSticker(db, stickerId, true);
  if (administrativeOverride) return { vehicle, gate: null };
  const selectedGate = await resolveGate(db, gate);
  assertGateDirection(selectedGate, action);
  const [rows] = await db.query('SELECT scan_type, scanned_at FROM vehicle_logs WHERE vehicle_id = ? ORDER BY scanned_at DESC, id DESC LIMIT 1', [vehicle.id]);
  const previous = rows[0];
  const elapsed = previous ? (new Date(scannedAt || Date.now()) - new Date(previous.scanned_at)) / 1000 : Infinity;
  if (previous && elapsed < Math.max(0, cooldownSeconds)) {
    throw new GateLoggingError(`Duplicate or older scan ignored. Wait ${cooldownSeconds} seconds before scanning this vehicle again.`, 'DUPLICATE_SCAN', 409);
  }
  const expected = previous?.scan_type === 'entry' ? 'exit' : 'entry';
  if (String(action).toLowerCase() !== expected) {
    throw new GateLoggingError(`This vehicle requires ${expected}; its movement state has changed. Scan again.`, 'MOVEMENT_CONFLICT', 409);
  }
  return { vehicle, gate: selectedGate };
}

// Called on the same connection/transaction as the original log and slot update.
async function recordMovement(db, { movement, scanLog, action, guardName, gateName, scannedAt }) {
  const [guards] = guardName ? await db.query('SELECT id FROM users WHERE username = ? LIMIT 1', [guardName]) : [[]];
  const [result] = await db.query(
    `INSERT INTO vehicle_logs (vehicle_id, guard_id, gate_id, scan_log_id, scan_type, scanned_at, vehicle_plate, guard_name, gate_name)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [movement.vehicle.id, guards[0]?.id || null, movement.gate?.id || null, scanLog.id,
      action.toLowerCase(), scannedAt || scanLog.scanned_at, movement.vehicle.plate_number,
      guardName || null, movement.gate?.name || gateName || null]
  );
  return { id: result.insertId, gate_id: movement.gate?.id || null, gate_name: movement.gate?.name || gateName || null, scan_type: action.toLowerCase() };
}

function integer(value, name, fallback, max = Number.MAX_SAFE_INTEGER) {
  if (value === undefined || value === '') return fallback;
  if (!['string', 'number'].includes(typeof value) || !/^\d+$/.test(String(value)) || !Number.isSafeInteger(Number(value)) || Number(value) < 1 || Number(value) > max) {
    throw new GateLoggingError(`Enter a valid ${name}.`, 'INVALID_FILTER');
  }
  return Number(value);
}

function dateBoundary(value, name, end = false) {
  if (value === undefined || value === '') return null;
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) throw new GateLoggingError(`Use YYYY-MM-DD for ${name}.`, 'INVALID_FILTER');
  const date = new Date(`${value}T00:00:00+08:00`);
  if (!Number.isFinite(date.getTime()) || new Date(date.getTime() + 8 * 3600000).toISOString().slice(0, 10) !== value) {
    throw new GateLoggingError(`Enter a valid ${name}.`, 'INVALID_FILTER');
  }
  if (end) date.setTime(date.getTime() + 86400000);
  return date;
}

function filters(query, sessions = false) {
  const page = integer(query.page, 'page', 1, 10000);
  const limit = integer(query.limit, 'page size', 25, 100);
  const gateId = integer(query.gate_id, 'gate', null);
  const vehicleId = integer(query.vehicle_id, 'vehicle', null);
  const from = dateBoundary(query.date_from, 'start date');
  const to = dateBoundary(query.date_to, 'end date', true);
  if (from && to && from >= to) throw new GateLoggingError('Start date must be on or before end date.', 'INVALID_FILTER');
  if (query.scan_type && !['entry', 'exit'].includes(query.scan_type)) throw new GateLoggingError('Choose entry or exit.', 'INVALID_FILTER');
  if (query.vehicle !== undefined && (typeof query.vehicle !== 'string' || query.vehicle.length > 30)) throw new GateLoggingError('Enter a vehicle plate of 30 characters or fewer.', 'INVALID_FILTER');
  const alias = sessions ? 'e' : 'vl';
  const conditions = sessions ? ["e.scan_type = 'entry'"] : [];
  const params = [];
  if (gateId) {
    conditions.push(sessions ? '(e.gate_id = ? OR x.gate_id = ?)' : 'vl.gate_id = ?');
    params.push(gateId);
    if (sessions) params.push(gateId);
  }
  if (vehicleId) { conditions.push(`${alias}.vehicle_id = ?`); params.push(vehicleId); }
  if (query.vehicle?.trim()) { conditions.push(`${alias}.vehicle_plate LIKE ?`); params.push(query.vehicle.trim().replace(/[\\%_]/g, '\\$&') + '%'); }
  if (from) { conditions.push(`${alias}.scanned_at >= ?`); params.push(from); }
  if (to) { conditions.push(`${alias}.scanned_at < ?`); params.push(to); }
  if (!sessions && query.scan_type) { conditions.push('vl.scan_type = ?'); params.push(query.scan_type); }
  return { page, limit, offset: (page - 1) * limit, where: conditions.length ? conditions.join(' AND ') : '1=1', params };
}

async function listLogs(db, query) {
  const f = filters(query);
  const [[count]] = await db.query(`SELECT COUNT(*) AS total FROM vehicle_logs vl WHERE ${f.where}`, f.params);
  const [rows] = await db.query(
    `SELECT vl.id, vl.vehicle_id, vl.vehicle_plate, vl.guard_id, vl.guard_name,
            vl.gate_id, vl.gate_name, vl.scan_type, vl.scanned_at
     FROM vehicle_logs vl WHERE ${f.where} ORDER BY vl.scanned_at DESC, vl.id DESC LIMIT ? OFFSET ?`,
    [...f.params, f.limit, f.offset]
  );
  return { rows, page: f.page, limit: f.limit, total: Number(count.total) };
}

// Pair with the immediately following movement, never with a later unrelated exit.
// LEAD works in MySQL 8 and TiDB; TiDB rejects scalar subqueries in JOIN ON.
const sessionJoin = `FROM (
  SELECT vl.*, LEAD(id) OVER (PARTITION BY vehicle_id ORDER BY scanned_at, id) AS next_log_id
  FROM vehicle_logs vl
) e LEFT JOIN vehicle_logs x ON x.id = e.next_log_id
  AND x.vehicle_id = e.vehicle_id AND x.scan_type = 'exit'`;

async function listSessions(db, query) {
  const f = filters(query, true);
  const [[count]] = await db.query(`SELECT COUNT(*) AS total ${sessionJoin} WHERE ${f.where}`, f.params);
  const [rows] = await db.query(
    `SELECT e.id, e.vehicle_id, e.vehicle_plate, e.gate_id AS entry_gate_id,
            e.gate_name AS entry_gate, e.scanned_at AS entry_time, e.guard_id AS entry_guard_id, e.guard_name AS entry_guard,
            x.gate_id AS exit_gate_id, x.gate_name AS exit_gate, x.scanned_at AS exit_time,
            x.guard_id AS exit_guard_id, x.guard_name AS exit_guard
     ${sessionJoin} WHERE ${f.where} ORDER BY e.scanned_at DESC, e.id DESC LIMIT ? OFFSET ?`,
    [...f.params, f.limit, f.offset]
  );
  return { rows, page: f.page, limit: f.limit, total: Number(count.total) };
}

module.exports = { GateLoggingError, migrate, listGates, resolveGate, assertGateDirection, vehicleForSticker, lastMovement, validateMovement, recordMovement, integer, filters, listLogs, listSessions };
