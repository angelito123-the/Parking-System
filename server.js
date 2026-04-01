process.env.TZ = "Asia/Manila";
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const QRCode = require("qrcode");
const session = require("express-session");
const { pool, ensureDatabaseSchema } = require("./db");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const SCAN_COOLDOWN_SECONDS = Number(process.env.SCAN_COOLDOWN_SECONDS || 10);
const rawOverstayLimitHours = Number(process.env.OVERSTAY_LIMIT_HOURS);
const OVERSTAY_LIMIT_HOURS = Number.isFinite(rawOverstayLimitHours)
  ? Math.max(0.5, rawOverstayLimitHours)
  : 4;
const OVERSTAY_LIMIT_MINUTES = Math.max(1, Math.round(OVERSTAY_LIMIT_HOURS * 60));
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "naap2024";
const SESSION_SECRET = process.env.SESSION_SECRET || "naap-parking-secret";
const SNAPSHOT_DIR = path.join(__dirname, "public", "snapshots");
const SNAPSHOT_MAX_BYTES = Number(process.env.SCAN_SNAPSHOT_MAX_BYTES || 3 * 1024 * 1024);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.set("trust proxy", true);
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 8 * 60 * 60 * 1000  // 8 hours
  }
}));
app.use((req, res, next) => {
  res.locals.currentPath = req.path;
  res.locals.requestBaseUrl = `${req.protocol}://${req.get("host")}`;
  res.locals.adminUser = req.session.adminUser || null;
  next();
});

// Auth middleware — protects all admin routes
function requireAuth(req, res, next) {
  if (req.session && req.session.adminUser) return next();
  res.redirect("/login");
}

// Login routes
app.get("/login", (req, res) => {
  if (req.session.adminUser) return res.redirect("/");
  res.render("login", { error: null, usernameVal: "" });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.adminUser = username;
    return res.redirect("/");
  }
  res.render("login", { error: "Invalid username or password.", usernameVal: username });
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/login");
});

function createStickerCode() {
  const year = new Date().getFullYear();
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `NAAP-${year}-${random}`;
}

function createQrToken() {
  return crypto.randomBytes(24).toString("hex");
}

function isExpired(expiresAt) {
  if (!expiresAt) return false;
  return new Date(expiresAt).getTime() < Date.now();
}

function toDateOnly(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().slice(0, 10);
}

function escapeCsv(value) {
  const text = value == null ? "" : String(value);
  return `"${text.replace(/"/g, '""')}"`;
}

function formatDurationMinutes(totalMinutes) {
  const safeMinutes = Math.max(0, Math.floor(Number(totalMinutes) || 0));
  const days = Math.floor(safeMinutes / 1440);
  const hours = Math.floor((safeMinutes % 1440) / 60);
  const minutes = safeMinutes % 60;
  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0 || days > 0) parts.push(`${hours}h`);
  parts.push(`${minutes}m`);
  return parts.join(" ");
}

function formatHoursLabel(hours) {
  const rounded = Math.round(Number(hours) * 10) / 10;
  if (Number.isInteger(rounded)) return `${rounded}`;
  return rounded.toFixed(1).replace(/\.0$/, "");
}

function normalizeScanStatus(result) {
  if (result === "VALID") return "AUTHORIZED";
  if (result === "INVALID") return "INVALID";
  if (result === "REVOKED") return "REVOKED";
  if (result === "EXPIRED") return "EXPIRED";
  return "UNKNOWN";
}

function normalizeQrTokenInput(rawInput) {
  const raw = String(rawInput || "").trim();
  if (!raw) return "";

  try {
    const parsed = new URL(raw);
    const parts = parsed.pathname.split("/").filter(Boolean);
    if (parts.length >= 2 && parts[0] === "verify") {
      return parts[1];
    }
  } catch (_error) {
    return raw;
  }

  return raw;
}

function getDuplicateScanInfo(lastMovement) {
  if (!lastMovement || SCAN_COOLDOWN_SECONDS <= 0) {
    return { duplicate: false, secondsSinceLastScan: null };
  }

  const lastScannedAtMs = new Date(lastMovement.scanned_at).getTime();
  if (!Number.isFinite(lastScannedAtMs)) {
    return { duplicate: false, secondsSinceLastScan: null };
  }

  const secondsSinceLastScan = Math.floor((Date.now() - lastScannedAtMs) / 1000);
  const duplicate = secondsSinceLastScan >= 0 && secondsSinceLastScan < SCAN_COOLDOWN_SECONDS;
  return { duplicate, secondsSinceLastScan };
}

function getAutoStickerPayload(sticker) {
  if (!sticker) return null;
  return {
    sticker_id: sticker.id,
    sticker_code: sticker.sticker_code,
    student_id: sticker.student_id_ref || null,
    student_number: sticker.student_number || null,
    full_name: sticker.full_name || null,
    vehicle_id: sticker.vehicle_id_ref || sticker.vehicle_id || null,
    plate_number: sticker.plate_number || null,
    vehicle_type: sticker.model || "Unspecified",
    vehicle_model: sticker.model || null,
    vehicle_color: sticker.color || null
  };
}

async function saveSnapshotDataUrl(snapshotDataUrl, prefix = "scan") {
  if (!snapshotDataUrl || typeof snapshotDataUrl !== "string") return null;
  const trimmed = snapshotDataUrl.trim();
  if (!trimmed) return null;

  const match = trimmed.match(/^data:image\/(png|jpeg|jpg);base64,([A-Za-z0-9+/=]+)$/i);
  if (!match) return null;

  const ext = match[1].toLowerCase() === "jpg" ? "jpeg" : match[1].toLowerCase();
  const imageBuffer = Buffer.from(match[2], "base64");
  if (!imageBuffer.length || imageBuffer.length > SNAPSHOT_MAX_BYTES) {
    throw new Error("Snapshot image is too large. Please keep it under 3MB.");
  }

  await fs.promises.mkdir(SNAPSHOT_DIR, { recursive: true });
  const filename = `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}.${ext}`;
  const absolutePath = path.join(SNAPSHOT_DIR, filename);
  await fs.promises.writeFile(absolutePath, imageBuffer);
  return `/snapshots/${filename}`;
}

function buildReportFilters(query) {
  const today = new Date();
  const defaultTo = toDateOnly(today);
  const sevenDaysAgo = new Date(today);
  sevenDaysAgo.setDate(today.getDate() - 6);
  const defaultFrom = toDateOnly(sevenDaysAgo);

  const from = toDateOnly(query.from) || defaultFrom;
  const to = toDateOnly(query.to) || defaultTo;
  const gate = query.gate && query.gate !== "ALL" ? String(query.gate) : "ALL";

  return { from, to, gate };
}

function buildWhereClause(filters) {
  const where = ["DATE(sl.scanned_at) BETWEEN ? AND ?"];
  const params = [filters.from, filters.to];
  if (filters.gate !== "ALL") {
    where.push("sl.gate = ?");
    params.push(filters.gate);
  }
  return {
    whereSql: where.join(" AND "),
    params
  };
}

async function findStickerByToken(token) {
  const [rows] = await pool.query(
    `SELECT
       s.*,
       v.id AS vehicle_id_ref,
       v.plate_number,
       v.model,
       v.color,
       st.id AS student_id_ref,
       st.full_name,
       st.student_number
     FROM stickers s
     JOIN vehicles v ON v.id = s.vehicle_id
     JOIN students st ON st.id = v.student_id
     WHERE s.qr_token = ?`,
    [token]
  );
  return rows.length > 0 ? rows[0] : null;
}

async function getVerificationState(token) {
  const sticker = await findStickerByToken(token);

  if (!sticker) {
    return {
      ok: false,
      result: "INVALID",
      message: "Sticker not found."
    };
  }

  if (sticker.status !== "active") {
    return {
      ok: false,
      result: "REVOKED",
      message: "Sticker is revoked.",
      sticker
    };
  }

  if (isExpired(sticker.expires_at)) {
    return {
      ok: false,
      result: "EXPIRED",
      message: "Sticker has expired.",
      sticker
    };
  }

  return {
    ok: true,
    result: "VALID",
    message: "Verification successful.",
    sticker
  };
}

async function getInsideVehiclesWithOverstay(db = pool, limit = 20) {
  const [rows] = await db.query(
    `SELECT
       s.id AS sticker_id,
       latest.scanned_at AS entered_at,
       latest.gate AS entry_gate,
       latest.slot_id,
       ps.slot_code AS parking_slot,
       TIMESTAMPDIFF(MINUTE, latest.scanned_at, NOW()) AS minutes_inside,
       s.sticker_code,
       st.student_number,
       st.full_name,
       v.plate_number
     FROM (
       SELECT sl.sticker_id, sl.action, sl.gate, sl.scanned_at, sl.slot_id
       FROM scan_logs sl
       JOIN (
         SELECT sticker_id, MAX(scanned_at) AS max_scanned_at
         FROM scan_logs
         WHERE result = 'VALID'
           AND action IN ('ENTRY', 'EXIT')
           AND sticker_id IS NOT NULL
         GROUP BY sticker_id
       ) latest
         ON latest.sticker_id = sl.sticker_id
        AND latest.max_scanned_at = sl.scanned_at
       WHERE sl.result = 'VALID'
         AND sl.action IN ('ENTRY', 'EXIT')
     ) latest
     JOIN stickers s ON s.id = latest.sticker_id
     JOIN vehicles v ON v.id = s.vehicle_id
     JOIN students st ON st.id = v.student_id
     LEFT JOIN parking_slots ps ON ps.id = latest.slot_id
     WHERE latest.action = 'ENTRY'
     ORDER BY latest.scanned_at ASC
     LIMIT ?`,
    [Number(limit) || 20]
  );

  return rows.map((row) => {
    const minutesInside = Math.max(0, Number(row.minutes_inside) || 0);
    const overstayMinutes = Math.max(0, minutesInside - OVERSTAY_LIMIT_MINUTES);
    const isOverstay = overstayMinutes > 0;
    return {
      ...row,
      minutes_inside: minutesInside,
      duration_label: formatDurationMinutes(minutesInside),
      is_overstay: isOverstay,
      overstay_minutes: overstayMinutes,
      overstay_label: isOverstay ? `+${formatDurationMinutes(overstayMinutes)} over limit` : null
    };
  });
}

async function getOverstayAlertCount(db = pool) {
  const [[countRow]] = await db.query(
    `SELECT COUNT(*) AS total
     FROM (
       SELECT sl.sticker_id, sl.action, sl.scanned_at
       FROM scan_logs sl
       JOIN (
         SELECT sticker_id, MAX(scanned_at) AS max_scanned_at
         FROM scan_logs
         WHERE result = 'VALID'
           AND action IN ('ENTRY', 'EXIT')
           AND sticker_id IS NOT NULL
         GROUP BY sticker_id
       ) latest
         ON latest.sticker_id = sl.sticker_id
        AND latest.max_scanned_at = sl.scanned_at
       WHERE sl.result = 'VALID'
         AND sl.action IN ('ENTRY', 'EXIT')
     ) movement
     WHERE movement.action = 'ENTRY'
       AND TIMESTAMPDIFF(MINUTE, movement.scanned_at, NOW()) > ?`,
    [OVERSTAY_LIMIT_MINUTES]
  );
  return Number(countRow?.total || 0);
}

async function getDashboardData() {
  const [[studentsCount]] = await pool.query("SELECT COUNT(*) AS total FROM students");
  const [[vehiclesCount]] = await pool.query("SELECT COUNT(*) AS total FROM vehicles");
  const [[stickersCount]] = await pool.query(
    "SELECT COUNT(*) AS total FROM stickers WHERE status = 'active'"
  );
  const [[todayEntries]] = await pool.query(
    `SELECT COUNT(*) AS total
     FROM scan_logs
     WHERE result = 'VALID'
       AND action = 'ENTRY'
       AND DATE(scanned_at) = CURDATE()`
  );
  const [[todayExits]] = await pool.query(
    `SELECT COUNT(*) AS total
     FROM scan_logs
     WHERE result = 'VALID'
       AND action = 'EXIT'
       AND DATE(scanned_at) = CURDATE()`
  );
  const [[currentlyInside]] = await pool.query(
    `SELECT COUNT(*) AS total
     FROM (
       SELECT latest.sticker_id, sl.action
       FROM (
         SELECT sticker_id, MAX(scanned_at) AS max_scanned_at
         FROM scan_logs
         WHERE result = 'VALID' AND sticker_id IS NOT NULL
         GROUP BY sticker_id
       ) latest
       JOIN scan_logs sl
         ON sl.sticker_id = latest.sticker_id
        AND sl.scanned_at = latest.max_scanned_at
       WHERE sl.result = 'VALID'
     ) movement
     WHERE movement.action = 'ENTRY'`
  );
  const [movementLogs] = await pool.query(
    `SELECT
       sl.scanned_at,
       sl.result,
       sl.action,
       sl.gate,
       ps.slot_code AS parking_slot,
       s.sticker_code,
       st.full_name,
       st.student_number,
       v.plate_number
     FROM scan_logs sl
     LEFT JOIN stickers s ON s.id = sl.sticker_id
     LEFT JOIN vehicles v ON v.id = s.vehicle_id
     LEFT JOIN students st ON st.id = v.student_id
     LEFT JOIN parking_slots ps ON ps.id = sl.slot_id
     ORDER BY sl.scanned_at DESC
     LIMIT 50`
  );
  const insideVehicles = await getInsideVehiclesWithOverstay(pool, 20);
  const overstayAlerts = insideVehicles.filter((item) => item.is_overstay);
  const overstayAlertCount = await getOverstayAlertCount(pool);
  const parkingSlotOverview = await getParkingSlotOverview();
  const parkingSlots = parkingSlotOverview.slots;
  const availableSlots = parkingSlots.filter((slot) => slot.is_selectable);
  return {
    metrics: {
      students: studentsCount.total,
      vehicles: vehiclesCount.total,
      activeStickers: stickersCount.total,
      todayEntries: todayEntries.total,
      todayExits: todayExits.total,
      currentlyInside: currentlyInside.total,
      overstayAlerts: overstayAlertCount,
      overstayLimitHours: OVERSTAY_LIMIT_HOURS
    },
    movementLogs,
    insideVehicles,
    overstayAlerts,
    overstayLimitHours: OVERSTAY_LIMIT_HOURS,
    overstayLimitLabel: formatHoursLabel(OVERSTAY_LIMIT_HOURS),
    parkingSlots,
    availableSlots,
    parkingSlotSummary: parkingSlotOverview.summary
  };
}

async function getReportsData(filters) {
  const { whereSql, params } = buildWhereClause(filters);

  const [rows] = await pool.query(
    `SELECT
      sl.id,
      sl.scanned_at,
      sl.result,
      sl.action,
      sl.gate,
      ps.slot_code AS parking_slot,
      sl.notes,
      s.sticker_code,
      st.student_number,
      st.full_name,
      v.plate_number
     FROM scan_logs sl
     LEFT JOIN stickers s ON s.id = sl.sticker_id
     LEFT JOIN vehicles v ON v.id = s.vehicle_id
     LEFT JOIN students st ON st.id = v.student_id
     LEFT JOIN parking_slots ps ON ps.id = sl.slot_id
     WHERE ${whereSql}
     ORDER BY sl.scanned_at DESC`,
    params
  );

  const [gateStats] = await pool.query(
    `SELECT
      IFNULL(sl.gate, 'Unspecified') AS gate,
      COUNT(*) AS total
     FROM scan_logs sl
     WHERE ${whereSql}
     GROUP BY sl.gate
     ORDER BY total DESC`,
    params
  );

  const [studentStats] = await pool.query(
    `SELECT
      IFNULL(st.student_number, 'Unknown') AS student_number,
      IFNULL(st.full_name, 'Unknown Student') AS full_name,
      COUNT(*) AS total_scans
     FROM scan_logs sl
     LEFT JOIN stickers s ON s.id = sl.sticker_id
     LEFT JOIN vehicles v ON v.id = s.vehicle_id
     LEFT JOIN students st ON st.id = v.student_id
     WHERE ${whereSql}
     GROUP BY st.student_number, st.full_name
     ORDER BY total_scans DESC
     LIMIT 10`,
    params
  );

  const [hourStats] = await pool.query(
    `SELECT
      DATE_FORMAT(sl.scanned_at, '%H:00') AS hour_slot,
      COUNT(*) AS total
     FROM scan_logs sl
     WHERE ${whereSql}
     GROUP BY hour_slot
     ORDER BY hour_slot`,
    params
  );

  const summary = {
    totalScans: rows.length,
    validScans: rows.filter((r) => r.result === "VALID").length,
    totalEntries: rows.filter((r) => r.action === "ENTRY").length,
    totalExits: rows.filter((r) => r.action === "EXIT").length,
    uniqueStudents: new Set(rows.filter((r) => r.student_number).map((r) => r.student_number)).size
  };

  return {
    filters,
    summary,
    rows,
    gateStats,
    studentStats,
    hourStats
  };
}

async function getAvailableParkingSlots(db = pool) {
  const [rows] = await db.query(
    `SELECT id, slot_code, zone
     FROM parking_slots
     WHERE status = 'available'
       AND current_sticker_id IS NULL
     ORDER BY zone ASC, slot_code ASC`
  );
  return rows;
}

async function getParkingSlotOverview(db = pool) {
  const [rows] = await db.query(
    `SELECT
       ps.id,
       ps.slot_code,
       ps.zone,
       ps.status,
       ps.current_sticker_id,
       st.full_name AS occupied_by_name,
       v.plate_number AS occupied_by_plate
     FROM parking_slots ps
     LEFT JOIN stickers s ON s.id = ps.current_sticker_id
     LEFT JOIN vehicles v ON v.id = s.vehicle_id
     LEFT JOIN students st ON st.id = v.student_id
     ORDER BY ps.zone ASC, ps.slot_code ASC`
  );

  const slots = rows.map((row) => {
    const occupancy = row.status !== "available"
      ? "disabled"
      : row.current_sticker_id
      ? "occupied"
      : "available";
    return {
      id: row.id,
      slot_code: row.slot_code,
      zone: row.zone,
      status: row.status,
      occupancy,
      is_selectable: occupancy === "available",
      occupied_by_name: row.occupied_by_name || null,
      occupied_by_plate: row.occupied_by_plate || null
    };
  });

  const summary = slots.reduce(
    (acc, slot) => {
      acc.total += 1;
      if (slot.occupancy === "available") acc.available += 1;
      else if (slot.occupancy === "occupied") acc.occupied += 1;
      else acc.disabled += 1;
      return acc;
    },
    { total: 0, available: 0, occupied: 0, disabled: 0 }
  );

  return { slots, summary };
}

async function getCurrentParkingSlotBySticker(stickerId, db = pool) {
  const [rows] = await db.query(
    `SELECT id, slot_code, zone
     FROM parking_slots
     WHERE current_sticker_id = ?
     LIMIT 1`,
    [stickerId]
  );
  return rows.length > 0 ? rows[0] : null;
}

async function assignParkingSlot(db, stickerId, slotId) {
  const [slotRows] = await db.query(
    `SELECT id, slot_code, zone, status, current_sticker_id
     FROM parking_slots
     WHERE id = ?
     FOR UPDATE`,
    [slotId]
  );

  if (slotRows.length === 0) {
    throw new Error("Selected parking slot does not exist.");
  }

  const slot = slotRows[0];
  if (slot.status !== "available") {
    throw new Error("Selected parking slot is not available.");
  }
  if (slot.current_sticker_id) {
    throw new Error("Selected parking slot is already occupied.");
  }

  await db.query(
    `UPDATE parking_slots
     SET current_sticker_id = NULL
     WHERE current_sticker_id = ?`,
    [stickerId]
  );
  await db.query(
    `UPDATE parking_slots
     SET current_sticker_id = ?
     WHERE id = ?`,
    [stickerId, slotId]
  );

  return { id: slot.id, slot_code: slot.slot_code, zone: slot.zone };
}

async function releaseParkingSlot(db, stickerId) {
  const [rows] = await db.query(
    `SELECT id, slot_code, zone
     FROM parking_slots
     WHERE current_sticker_id = ?
     FOR UPDATE`,
    [stickerId]
  );

  const slot = rows.length > 0 ? rows[0] : null;
  if (slot) {
    await db.query(
      `UPDATE parking_slots
       SET current_sticker_id = NULL
       WHERE id = ?`,
      [slot.id]
    );
  }

  return slot;
}

async function insertScanLog(stickerId, result, action, gate, notes, options = {}) {
  return insertScanLogWithDb(pool, stickerId, result, action, gate, notes, options);
}

async function insertScanLogWithDb(db, stickerId, result, action, gate, notes, options = {}) {
  const slotId = options.slotId || null;
  const gateId = options.gateId || gate || null;
  const qrValue = options.qrValue || null;
  const studentId = options.studentId || null;
  const vehicleId = options.vehicleId || null;
  const assignedArea = options.assignedArea || null;
  const assignedByGuard = options.assignedByGuard || null;
  const scanSource = options.scanSource || "manual";
  const snapshotPath = options.snapshotPath || null;
  const status = options.status || normalizeScanStatus(result);
  const [insertResult] = await db.query(
    `INSERT INTO scan_logs (
       sticker_id,
       result,
       action,
       gate,
       gate_id,
       slot_id,
       qr_value,
       student_id,
       vehicle_id,
       assigned_area,
       assigned_by_guard,
       scan_source,
       snapshot_path,
       status,
       notes
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      stickerId,
      result,
      action,
      gate,
      gateId,
      slotId,
      qrValue,
      studentId,
      vehicleId,
      assignedArea,
      assignedByGuard,
      scanSource,
      snapshotPath,
      status,
      notes
    ]
  );
  const [logRows] = await db.query(
    "SELECT id, scanned_at, slot_id, snapshot_path FROM scan_logs WHERE id = ? LIMIT 1",
    [insertResult.insertId]
  );

  return logRows.length > 0 ? logRows[0] : null;
}

async function getLastValidMovement(stickerId, db = pool) {
  const [rows] = await db.query(
    `SELECT id, action, scanned_at, slot_id
     FROM scan_logs
     WHERE sticker_id = ?
       AND result = 'VALID'
       AND action IN ('ENTRY', 'EXIT')
     ORDER BY scanned_at DESC, id DESC
     LIMIT 1`,
    [stickerId]
  );

  return rows.length > 0 ? rows[0] : null;
}

async function resolveScan(token, gate = "Main Gate") {
  const verification = await getVerificationState(token);
  if (!verification.ok && verification.result === "INVALID") {
    const scanLog = await insertScanLog(null, "INVALID", "VERIFY", gate, "Token not found", {
      gateId: gate,
      qrValue: token,
      scanSource: "scanner",
      status: normalizeScanStatus("INVALID")
    });
    return {
      ...verification,
      scan_log_id: scanLog?.id || null,
      scanned_at: scanLog?.scanned_at || null
    };
  }

  if (!verification.ok && verification.result === "REVOKED") {
    const scanLog = await insertScanLog(
      verification.sticker.id,
      "REVOKED",
      "VERIFY",
      gate,
      "Sticker is not active",
      {
        gateId: gate,
        qrValue: token,
        studentId: verification.sticker?.student_id_ref || null,
        vehicleId: verification.sticker?.vehicle_id_ref || verification.sticker?.vehicle_id || null,
        scanSource: "scanner",
        status: normalizeScanStatus("REVOKED")
      }
    );
    return {
      ...verification,
      scan_log_id: scanLog?.id || null,
      scanned_at: scanLog?.scanned_at || null
    };
  }

  if (!verification.ok && verification.result === "EXPIRED") {
    const scanLog = await insertScanLog(
      verification.sticker.id,
      "EXPIRED",
      "VERIFY",
      gate,
      "Sticker expired",
      {
        gateId: gate,
        qrValue: token,
        studentId: verification.sticker?.student_id_ref || null,
        vehicleId: verification.sticker?.vehicle_id_ref || verification.sticker?.vehicle_id || null,
        scanSource: "scanner",
        status: normalizeScanStatus("EXPIRED")
      }
    );
    return {
      ...verification,
      scan_log_id: scanLog?.id || null,
      scanned_at: scanLog?.scanned_at || null
    };
  }

  const sticker = verification.sticker;
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();
    await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [sticker.id]);
    const lastMovement = await getLastValidMovement(sticker.id, connection);

    const duplicateInfo = getDuplicateScanInfo(lastMovement);
    if (duplicateInfo.duplicate) {
      await connection.rollback();
      return {
        ...verification,
        action: lastMovement.action,
        duplicate_scan: true,
        cooldown_seconds: SCAN_COOLDOWN_SECONDS,
        seconds_since_last_scan: duplicateInfo.secondsSinceLastScan,
        message: `Scan ignored to prevent duplicate. Please wait ${SCAN_COOLDOWN_SECONDS} seconds before rescanning.`,
        scan_log_id: null,
        scanned_at: lastMovement.scanned_at
      };
    }

    const action = lastMovement && lastMovement.action === "ENTRY" ? "EXIT" : "ENTRY";
    const slot = action === "EXIT"
      ? await getCurrentParkingSlotBySticker(sticker.id, connection)
      : null;
    const scanLog = await insertScanLogWithDb(
      connection,
      sticker.id,
      "VALID",
      action,
      gate,
      "Verified",
      {
        gateId: gate,
        slotId: slot?.id || null,
        qrValue: token,
        studentId: sticker.student_id_ref || null,
        vehicleId: sticker.vehicle_id_ref || sticker.vehicle_id || null,
        assignedArea: slot?.zone || null,
        scanSource: "scanner",
        status: "AUTHORIZED"
      }
    );
    if (action === "EXIT") {
      await releaseParkingSlot(connection, sticker.id);
    }
    await connection.commit();

    return {
      ...verification,
      action,
      scan_log_id: scanLog?.id || null,
      scanned_at: scanLog?.scanned_at || null
    };
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}

async function verifyAndLog(token, gate = "Manual Verification") {
  const verification = await getVerificationState(token);
  const stickerId = verification.sticker ? verification.sticker.id : null;
  const noteByResult = {
    VALID: "Manual verification viewed",
    INVALID: "Token not found",
    REVOKED: "Sticker is not active",
    EXPIRED: "Sticker expired"
  };

  const scanLog = await insertScanLog(
    stickerId,
    verification.result,
    "VERIFY",
    gate,
    noteByResult[verification.result] || "Manual verification",
    {
      gateId: gate,
      qrValue: token,
      studentId: verification.sticker?.student_id_ref || null,
      vehicleId: verification.sticker?.vehicle_id_ref || verification.sticker?.vehicle_id || null,
      scanSource: "manual",
      status: normalizeScanStatus(verification.result)
    }
  );

  return {
    ...verification,
    scan_log_id: scanLog?.id || null,
    scanned_at: scanLog?.scanned_at || null
  };
}

// ─── Routes ─────────────────────────────────────────────────────────────────

app.get("/", requireAuth, async (req, res) => {
  try {
    const data = await getDashboardData();
    res.render("dashboard", data);
  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(500).send("An error occurred loading the dashboard.");
  }
});

// API: inside vehicles (for dashboard auto-refresh)
app.get("/api/inside-vehicles", requireAuth, async (req, res) => {
  try {
    const insideVehicles = await getInsideVehiclesWithOverstay(pool, 20);
    const overstayAlerts = insideVehicles.filter((item) => item.is_overstay);
    const overstayAlertCount = await getOverstayAlertCount(pool);
    res.json({
      ok: true,
      insideVehicles,
      overstayAlerts,
      overstayAlertCount,
      overstayLimitHours: OVERSTAY_LIMIT_HOURS,
      overstayLimitLabel: formatHoursLabel(OVERSTAY_LIMIT_HOURS)
    });
  } catch (error) {
    console.error("Inside vehicles API error:", error);
    res.status(500).json({ ok: false, message: "Failed to fetch vehicles." });
  }
});

// API: full dashboard stats refresh (metrics + movement log)
app.get("/api/dashboard-stats", requireAuth, async (req, res) => {
  try {
    const data = await getDashboardData();
    res.json({ ok: true, ...data });
  } catch (error) {
    console.error("Dashboard stats API error:", error);
    res.status(500).json({ ok: false, message: "Failed to fetch dashboard stats." });
  }
});

// API: parking history filtered by day and time window
app.get("/api/parking-history", requireAuth, async (req, res) => {
  try {
    const date = toDateOnly(req.query.date) || toDateOnly(new Date());
    const rawFrom = String(req.query.from_time || "").trim();
    const rawTo = String(req.query.to_time || "").trim();
    const timePattern = /^([01]\d|2[0-3]):([0-5]\d)$/;
    const fromTime = timePattern.test(rawFrom) ? rawFrom : "00:00";
    const toTime = timePattern.test(rawTo) ? rawTo : "23:59";

    if (fromTime > toTime) {
      return res.status(400).json({
        ok: false,
        message: "Invalid time range. 'From' time must be earlier than 'To' time.",
        rows: []
      });
    }

    const [rows] = await pool.query(
      `SELECT
         sl.scanned_at,
         sl.gate,
         ps.slot_code AS parking_slot,
         st.student_number,
         st.full_name,
         v.plate_number,
         s.sticker_code
       FROM scan_logs sl
       LEFT JOIN stickers s ON s.id = sl.sticker_id
       LEFT JOIN vehicles v ON v.id = s.vehicle_id
       LEFT JOIN students st ON st.id = v.student_id
       LEFT JOIN parking_slots ps ON ps.id = sl.slot_id
       WHERE sl.result = 'VALID'
         AND sl.action = 'ENTRY'
         AND DATE(sl.scanned_at) = ?
         AND TIME(sl.scanned_at) BETWEEN ? AND ?
       ORDER BY sl.scanned_at DESC
       LIMIT 300`,
      [date, `${fromTime}:00`, `${toTime}:59`]
    );

    res.json({
      ok: true,
      filters: {
        date,
        from_time: fromTime,
        to_time: toTime
      },
      rows
    });
  } catch (error) {
    console.error("Parking history API error:", error);
    res.status(500).json({ ok: false, message: "Failed to fetch parking history.", rows: [] });
  }
});

// API: parking history for a specific slot (latest ENTRY records)
app.get("/api/parking-slot-history", requireAuth, async (req, res) => {
  try {
    const slotCode = String(req.query.slot_code || "").trim().toUpperCase();
    if (!slotCode) {
      return res.status(400).json({ ok: false, message: "Missing slot_code.", rows: [] });
    }

    const [rows] = await pool.query(
      `SELECT
         entry_log.scanned_at AS parked_at,
         entry_log.gate AS entry_gate,
         ps.slot_code AS parking_slot,
         st.student_number,
         st.full_name,
         v.plate_number,
         s.sticker_code,
         (
           SELECT MIN(exit_log.scanned_at)
           FROM scan_logs exit_log
           WHERE exit_log.result = 'VALID'
             AND exit_log.action = 'EXIT'
             AND exit_log.sticker_id = entry_log.sticker_id
             AND exit_log.slot_id = entry_log.slot_id
             AND exit_log.scanned_at > entry_log.scanned_at
         ) AS exited_at
       FROM scan_logs entry_log
       JOIN parking_slots ps ON ps.id = entry_log.slot_id
       LEFT JOIN stickers s ON s.id = entry_log.sticker_id
       LEFT JOIN vehicles v ON v.id = s.vehicle_id
       LEFT JOIN students st ON st.id = v.student_id
       WHERE entry_log.result = 'VALID'
         AND entry_log.action = 'ENTRY'
         AND ps.slot_code = ?
       ORDER BY entry_log.scanned_at DESC
       LIMIT 120`,
      [slotCode]
    );

    const nowMs = Date.now();
    const durationRows = rows.map((row) => {
      const startMs = new Date(row.parked_at).getTime();
      const fallbackStartMs = Number.isFinite(startMs) ? startMs : nowMs;
      const endMs = row.exited_at
        ? new Date(row.exited_at).getTime()
        : nowMs;
      const safeEndMs = Number.isFinite(endMs) ? endMs : nowMs;
      const durationMinutes = Math.max(0, Math.floor((safeEndMs - fallbackStartMs) / 60000));
      const durationHours = Math.floor(durationMinutes / 60);
      const remainingMinutes = durationMinutes % 60;
      const durationLabel = durationHours > 0
        ? `${durationHours}h ${remainingMinutes}m`
        : `${remainingMinutes}m`;

      return {
        ...row,
        duration_minutes: durationMinutes,
        duration_label: durationLabel,
        is_ongoing: !row.exited_at
      };
    });

    res.json({
      ok: true,
      slot_code: slotCode,
      rows: durationRows
    });
  } catch (error) {
    console.error("Parking slot history API error:", error);
    res.status(500).json({ ok: false, message: "Failed to fetch slot history.", rows: [] });
  }
});

app.get("/students", requireAuth, async (req, res) => {
  try {
    const [studentRows] = await pool.query(
      "SELECT * FROM students ORDER BY created_at DESC, id DESC"
    );
    const [vehicleRows] = await pool.query(
      `SELECT v.* FROM vehicles v ORDER BY v.created_at ASC, v.id ASC`
    );
    // Attach vehicles array to each student
    const students = studentRows.map(s => ({
      ...s,
      vehicles: vehicleRows.filter(v => v.student_id === s.id)
    }));
    const flash = req.query.success
      ? { type: "success", message: "Student saved successfully." }
      : req.query.vsuccess
      ? { type: "success", message: "Vehicle registered successfully." }
      : req.query.esuccess
      ? { type: "success", message: "Record updated successfully." }
      : req.query.error === "duplicate"
      ? { type: "error", message: "A student with that student number already exists." }
      : req.query.error === "vduplicate"
      ? { type: "error", message: "A vehicle with that plate number already exists." }
      : req.query.error === "delete"
      ? { type: "error", message: "Unable to delete student — they may still have linked vehicles." }
      : req.query.deleted
      ? { type: "success", message: "Student deleted successfully." }
      : req.query.vdeleted
      ? { type: "success", message: "Vehicle deleted successfully." }
      : null;
    res.render("students", { students, flash });
  } catch (error) {
    console.error("Students error:", error);
    res.status(500).send("An error occurred loading students.");
  }
});

app.post("/students", requireAuth, async (req, res) => {
  const { student_number, full_name, program, email, plate_number, model, color } = req.body;
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [result] = await connection.query(
      "INSERT INTO students (student_number, full_name, program, email) VALUES (?, ?, ?, ?)",
      [student_number, full_name, program || null, email || null]
    );
    // If plate_number provided, also register a vehicle
    if (plate_number && plate_number.trim()) {
      await connection.query(
        "INSERT INTO vehicles (student_id, plate_number, model, color) VALUES (?, ?, ?, ?)",
        [result.insertId, plate_number.trim(), model || null, color || null]
      );
    }
    await connection.commit();
    res.redirect("/students?success=1");
  } catch (error) {
    await connection.rollback();
    if (error.code === "ER_DUP_ENTRY") {
      return res.redirect("/students?error=duplicate");
    }
    console.error("Create student error:", error);
    res.redirect("/students?error=1");
  } finally {
    connection.release();
  }
});

app.post("/students/:id/edit", requireAuth, async (req, res) => {
  const { student_number, full_name, program, email } = req.body;
  try {
    await pool.query(
      "UPDATE students SET student_number = ?, full_name = ?, program = ?, email = ? WHERE id = ?",
      [student_number, full_name, program || null, email || null, req.params.id]
    );
    res.redirect("/students?esuccess=1");
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.redirect("/students?error=duplicate");
    }
    console.error("Edit student error:", error);
    res.redirect("/students?error=1");
  }
});

app.post("/students/:id/delete", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM students WHERE id = ?", [req.params.id]);
    res.redirect("/students?deleted=1");
  } catch (error) {
    console.error("Delete student error:", error);
    res.redirect("/students?error=delete");
  }
});

// /vehicles → redirect to unified page
app.get("/vehicles", requireAuth, (req, res) => {
  res.redirect("/students");
});

app.post("/vehicles", requireAuth, async (req, res) => {
  const { student_id, plate_number, model, color } = req.body;
  try {
    await pool.query(
      "INSERT INTO vehicles (student_id, plate_number, model, color) VALUES (?, ?, ?, ?)",
      [student_id, plate_number, model || null, color || null]
    );
    res.redirect("/students?vsuccess=1");
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.redirect("/students?error=vduplicate");
    }
    console.error("Create vehicle error:", error);
    res.redirect("/students?error=1");
  }
});

app.post("/vehicles/:id/edit", requireAuth, async (req, res) => {
  const { plate_number, model, color } = req.body;
  try {
    await pool.query(
      "UPDATE vehicles SET plate_number = ?, model = ?, color = ? WHERE id = ?",
      [plate_number, model || null, color || null, req.params.id]
    );
    res.redirect("/students?esuccess=1");
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.redirect("/students?error=vduplicate");
    }
    console.error("Edit vehicle error:", error);
    res.redirect("/students?error=1");
  }
});

app.post("/vehicles/:id/delete", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM vehicles WHERE id = ?", [req.params.id]);
    res.redirect("/students?vdeleted=1");
  } catch (error) {
    console.error("Delete vehicle error:", error);
    res.redirect("/students?error=delete");
  }
});

app.get("/stickers", requireAuth, async (req, res) => {
  try {
    const [vehicles] = await pool.query(
      `SELECT v.id, v.plate_number, v.model, s.full_name, s.student_number
       FROM vehicles v
       JOIN students s ON s.id = v.student_id
       ORDER BY v.id DESC`
    );
    const [stickers] = await pool.query(
      `SELECT st.*, v.plate_number, v.model, s.full_name, s.student_number
       FROM stickers st
       JOIN vehicles v ON v.id = st.vehicle_id
       JOIN students s ON s.id = v.student_id
       ORDER BY st.created_at DESC, st.id DESC`
    );
    const flash = req.query.success
      ? { type: "success", message: "Sticker issued successfully." }
      : req.query.revoked
      ? { type: "success", message: "Sticker has been revoked." }
      : null;
    res.render("stickers", { stickers, vehicles, APP_BASE_URL, flash });
  } catch (error) {
    console.error("Stickers error:", error);
    res.status(500).send("An error occurred loading stickers.");
  }
});

app.post("/stickers", requireAuth, async (req, res) => {
  const { vehicle_id, expires_at } = req.body;
  const sticker_code = createStickerCode();
  const qr_token = createQrToken();

  try {
    await pool.query(
      "INSERT INTO stickers (vehicle_id, sticker_code, qr_token, expires_at) VALUES (?, ?, ?, ?)",
      [vehicle_id, sticker_code, qr_token, expires_at || null]
    );
    res.redirect("/stickers?success=1");
  } catch (error) {
    console.error("Issue sticker error:", error);
    res.status(400).send("Unable to issue sticker. Please try again.");
  }
});

app.post("/stickers/:id/revoke", requireAuth, async (req, res) => {
  try {
    await pool.query("UPDATE stickers SET status = 'revoked' WHERE id = ?", [req.params.id]);
    res.redirect("/stickers?revoked=1");
  } catch (error) {
    console.error("Revoke sticker error:", error);
    res.status(400).send("Unable to revoke sticker.");
  }
});

app.get("/stickers/:id/qr", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT qr_token FROM stickers WHERE id = ?", [req.params.id]);
    if (rows.length === 0) return res.status(404).send("Sticker not found");

    const requestBaseUrl = `${req.protocol}://${req.get("host")}`;
    const verifyUrl = `${requestBaseUrl}/verify/${rows[0].qr_token}`;
    const png = await QRCode.toBuffer(verifyUrl, { type: "png", width: 600 });
    res.type("png");
    res.send(png);
  } catch (error) {
    console.error("QR generation error:", error);
    res.status(500).send("Unable to generate QR code.");
  }
});

app.get("/verify/:token", async (req, res) => {
  try {
    // Get sticker info without logging automatically
    const verification = await getVerificationState(req.params.token);
    let lastAction = null;
    let currentSlot = null;
    let parkingSlotOverview = { slots: [], summary: { total: 0, available: 0, occupied: 0, disabled: 0 } };
    if (verification.ok && verification.sticker) {
       const lastMovement = await getLastValidMovement(verification.sticker.id);
       if (lastMovement) lastAction = lastMovement.action;
       currentSlot = await getCurrentParkingSlotBySticker(verification.sticker.id);
       parkingSlotOverview = await getParkingSlotOverview();
    }
    const result = { ...verification, last_action: lastAction, current_slot: currentSlot };
    res.render("verify", { result, parkingSlotOverview });
  } catch (error) {
    console.error("Verify GET error:", error);
    res.status(500).send("An error occurred during verification.");
  }
});

app.post("/verify/:token/movement", async (req, res) => {
  const selectedAction = String(req.body.action || "").toUpperCase();
  const gate = req.body.gate || "Manual Verification";
  const slotId = req.body.slot_id ? Number(req.body.slot_id) : null;

  if (!["ENTRY", "EXIT"].includes(selectedAction)) {
    return res.status(400).send("Invalid action. Please choose ENTRY or EXIT.");
  }

  try {
    const verification = await getVerificationState(req.params.token);
    if (!verification.ok) {
      return res.render("verify", {
        result: verification,
        parkingSlotOverview: { slots: [], summary: { total: 0, available: 0, occupied: 0, disabled: 0 } }
      });
    }

    const sticker = verification.sticker;
    const connection = await pool.getConnection();
    let movement_saved = false;
    let duplicate_movement = false;
    let savedAction = selectedAction;
    let scanLog = null;
    let currentSlot = null;

    try {
      await connection.beginTransaction();
      // Lock the sticker row to prevent concurrent duplicate submissions
      await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [sticker.id]);

      const lastMovement = await getLastValidMovement(sticker.id, connection);
      if (lastMovement && lastMovement.action === selectedAction) {
        await connection.rollback();
        duplicate_movement = true;
      } else {
        if (selectedAction === "ENTRY") {
          if (!slotId) {
            throw new Error("Please choose a parking slot before recording entry.");
          }
          currentSlot = await assignParkingSlot(connection, sticker.id, slotId);
        } else {
          currentSlot = await getCurrentParkingSlotBySticker(sticker.id, connection);
        }
        scanLog = await insertScanLogWithDb(
          connection,
          sticker.id,
          "VALID",
          selectedAction,
          gate,
          "Movement selected manually",
          {
            gateId: gate,
            slotId: currentSlot?.id || null,
            qrValue: req.params.token,
            studentId: sticker.student_id_ref || null,
            vehicleId: sticker.vehicle_id_ref || sticker.vehicle_id || null,
            assignedArea: currentSlot?.zone || null,
            assignedByGuard: req.session?.adminUser || null,
            scanSource: "manual",
            status: "AUTHORIZED"
          }
        );
        if (selectedAction === "EXIT") {
          await releaseParkingSlot(connection, sticker.id);
        }
        await connection.commit();
        movement_saved = true;
      }
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }

    const result = {
      ...verification,
      action: savedAction,
      current_slot: currentSlot,
      movement_saved,
      duplicate_movement,
      message: duplicate_movement
        ? `Movement ignored — last recorded movement is already ${selectedAction}.`
        : verification.message,
      scan_log_id: scanLog?.id || null,
      scanned_at: scanLog?.scanned_at || null
    };
    const parkingSlotOverview = await getParkingSlotOverview();
    res.render("verify", { result, parkingSlotOverview });
  } catch (error) {
    console.error("Movement error:", error);
    const verification = await getVerificationState(req.params.token).catch(() => null);
    const currentSlot = verification?.ok && verification?.sticker
      ? await getCurrentParkingSlotBySticker(verification.sticker.id).catch(() => null)
      : null;
    const parkingSlotOverview = await getParkingSlotOverview().catch(
      () => ({ slots: [], summary: { total: 0, available: 0, occupied: 0, disabled: 0 } })
    );
    res.status(400).render("verify", {
      result: {
        ...(verification || { ok: false, result: "INVALID", message: "An error occurred recording movement." }),
        current_slot: currentSlot,
        movement_saved: false,
        duplicate_movement: false,
        message: error.message || "An error occurred recording movement."
      },
      parkingSlotOverview
    });
  }
});

app.get("/scanner", requireAuth, (req, res) => {
  res.render("scanner");
});

app.get("/scanner/auto", requireAuth, (req, res) => {
  res.render("scanner_auto", {
    scanCooldownSeconds: SCAN_COOLDOWN_SECONDS
  });
});

// API: phone camera auto-detection (ENTRY requires guard confirmation, EXIT is auto-recorded)
app.post("/api/auto-scan/detect", requireAuth, async (req, res) => {
  const token = normalizeQrTokenInput(req.body.token);
  const gate = String(req.body.gate || "Main Gate").trim() || "Main Gate";
  const snapshotDataUrl = typeof req.body.snapshot_data_url === "string"
    ? req.body.snapshot_data_url
    : "";
  const guardName = req.session?.adminUser || "guard";

  if (!token) {
    return res.status(400).json({ ok: false, message: "Missing QR token." });
  }

  try {
    const verification = await getVerificationState(token);

    if (!verification.ok) {
      let snapshotPath = null;
      if (snapshotDataUrl) {
        try {
          snapshotPath = await saveSnapshotDataUrl(snapshotDataUrl, "auto-verify");
        } catch (_error) {
          snapshotPath = null;
        }
      }

      const scanLog = await insertScanLog(
        verification.sticker?.id || null,
        verification.result || "INVALID",
        "VERIFY",
        gate,
        "Auto camera verification failed",
        {
          gateId: gate,
          qrValue: token,
          studentId: verification.sticker?.student_id_ref || null,
          vehicleId: verification.sticker?.vehicle_id_ref || verification.sticker?.vehicle_id || null,
          assignedByGuard: guardName,
          scanSource: "camera_phone",
          snapshotPath,
          status: normalizeScanStatus(verification.result || "INVALID")
        }
      );

      return res.json({
        ...verification,
        sticker: getAutoStickerPayload(verification.sticker),
        action: "VERIFY",
        movement_saved: false,
        requires_confirmation: false,
        snapshot_path: scanLog?.snapshot_path || snapshotPath || null,
        scan_log_id: scanLog?.id || null,
        scanned_at: scanLog?.scanned_at || null
      });
    }

    const sticker = verification.sticker;
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [sticker.id]);

      const lastMovement = await getLastValidMovement(sticker.id, connection);
      const duplicateInfo = getDuplicateScanInfo(lastMovement);
      if (duplicateInfo.duplicate) {
        await connection.rollback();
        return res.json({
          ok: false,
          result: "VALID",
          message: `Scan ignored to prevent duplicate. Please wait ${SCAN_COOLDOWN_SECONDS} seconds before rescanning.`,
          duplicate_scan: true,
          cooldown_seconds: SCAN_COOLDOWN_SECONDS,
          seconds_since_last_scan: duplicateInfo.secondsSinceLastScan,
          action: lastMovement?.action || null,
          sticker: getAutoStickerPayload(sticker),
          scanned_at: lastMovement?.scanned_at || null
        });
      }

      const action = lastMovement && lastMovement.action === "ENTRY" ? "EXIT" : "ENTRY";

      if (action === "ENTRY") {
        await connection.rollback();
        const parkingSlotOverview = await getParkingSlotOverview();
        return res.json({
          ok: true,
          result: "VALID",
          action: "ENTRY",
          movement_saved: false,
          requires_confirmation: true,
          message: "Valid sticker detected. Select a parking slot and confirm ENTRY.",
          sticker: getAutoStickerPayload(sticker),
          parkingSlotOverview
        });
      }

      const currentSlot = await getCurrentParkingSlotBySticker(sticker.id, connection);
      if (!snapshotDataUrl) {
        throw new Error("Snapshot capture failed. Keep the camera active and scan again.");
      }
      const snapshotPath = await saveSnapshotDataUrl(snapshotDataUrl, "auto-exit");
      if (!snapshotPath) {
        throw new Error("Snapshot capture failed. Keep the camera active and scan again.");
      }

      const scanLog = await insertScanLogWithDb(
        connection,
        sticker.id,
        "VALID",
        "EXIT",
        gate,
        "Auto camera exit",
        {
          gateId: gate,
          slotId: currentSlot?.id || null,
          qrValue: token,
          studentId: sticker.student_id_ref || null,
          vehicleId: sticker.vehicle_id_ref || sticker.vehicle_id || null,
          assignedArea: currentSlot?.zone || null,
          assignedByGuard: guardName,
          scanSource: "camera_phone",
          snapshotPath,
          status: "AUTHORIZED"
        }
      );

      await releaseParkingSlot(connection, sticker.id);
      await connection.commit();

      return res.json({
        ok: true,
        result: "VALID",
        action: "EXIT",
        movement_saved: true,
        requires_confirmation: false,
        message: currentSlot
          ? `EXIT recorded. Released slot ${currentSlot.slot_code}.`
          : "EXIT recorded successfully.",
        released_slot: currentSlot?.slot_code || null,
        sticker: getAutoStickerPayload(sticker),
        snapshot_path: scanLog?.snapshot_path || snapshotPath || null,
        scan_log_id: scanLog?.id || null,
        scanned_at: scanLog?.scanned_at || null
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Auto detect scan error:", error);
    res.status(500).json({
      ok: false,
      message: error.message || "Failed to process automatic scan."
    });
  }
});

// API: guard confirms ENTRY after auto-detection and slot selection
app.post("/api/auto-scan/confirm-entry", requireAuth, async (req, res) => {
  const token = normalizeQrTokenInput(req.body.token);
  const gate = String(req.body.gate || "Main Gate").trim() || "Main Gate";
  const slotId = Number(req.body.slot_id);
  const snapshotDataUrl = typeof req.body.snapshot_data_url === "string"
    ? req.body.snapshot_data_url
    : "";
  const guardName = req.session?.adminUser || "guard";

  if (!token) {
    return res.status(400).json({ ok: false, message: "Missing QR token." });
  }
  if (!Number.isInteger(slotId) || slotId <= 0) {
    return res.status(400).json({ ok: false, message: "Please choose a parking slot before recording entry." });
  }

  try {
    const verification = await getVerificationState(token);
    if (!verification.ok) {
      return res.status(400).json({ ok: false, message: verification.message });
    }

    const sticker = verification.sticker;
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [sticker.id]);

      const lastMovement = await getLastValidMovement(sticker.id, connection);
      const duplicateInfo = getDuplicateScanInfo(lastMovement);
      if (duplicateInfo.duplicate) {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          duplicate_scan: true,
          message: `Scan ignored to prevent duplicate. Please wait ${SCAN_COOLDOWN_SECONDS} seconds before rescanning.`,
          cooldown_seconds: SCAN_COOLDOWN_SECONDS,
          seconds_since_last_scan: duplicateInfo.secondsSinceLastScan
        });
      }

      if (lastMovement && lastMovement.action === "ENTRY") {
        await connection.rollback();
        return res.status(400).json({
          ok: false,
          duplicate_movement: true,
          message: "Vehicle is already marked as inside. Record EXIT first."
        });
      }

      const assignedSlot = await assignParkingSlot(connection, sticker.id, slotId);
      if (!snapshotDataUrl) {
        throw new Error("Snapshot capture failed. Keep the camera active and confirm again.");
      }
      const snapshotPath = await saveSnapshotDataUrl(snapshotDataUrl, "auto-entry");
      if (!snapshotPath) {
        throw new Error("Snapshot capture failed. Keep the camera active and confirm again.");
      }
      const scanLog = await insertScanLogWithDb(
        connection,
        sticker.id,
        "VALID",
        "ENTRY",
        gate,
        "Auto camera entry confirmed by guard",
        {
          gateId: gate,
          slotId: assignedSlot.id,
          qrValue: token,
          studentId: sticker.student_id_ref || null,
          vehicleId: sticker.vehicle_id_ref || sticker.vehicle_id || null,
          assignedArea: assignedSlot.zone || null,
          assignedByGuard: guardName,
          scanSource: "camera_phone",
          snapshotPath,
          status: "AUTHORIZED"
        }
      );
      await connection.commit();

      return res.json({
        ok: true,
        movement_saved: true,
        result: "VALID",
        action: "ENTRY",
        message: `ENTRY recorded. Assigned slot ${assignedSlot.slot_code}.`,
        sticker: getAutoStickerPayload(sticker),
        parking_slot: assignedSlot.slot_code,
        assigned_area: assignedSlot.zone,
        assigned_by_guard: guardName,
        scan_source: "camera_phone",
        snapshot_path: scanLog?.snapshot_path || snapshotPath || null,
        scan_log_id: scanLog?.id || null,
        scanned_at: scanLog?.scanned_at || null
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Auto confirm entry error:", error);
    res.status(400).json({ ok: false, message: error.message || "Failed to record entry." });
  }
});

// API: search students/vehicles by plate, name, or student number
app.get("/api/gate-lookup", requireAuth, async (req, res) => {
  const q = String(req.query.q || "").trim();
  if (!q) return res.json({ ok: false, message: "No query provided.", results: [] });

  try {
    const like = `%${q}%`;
    const [results] = await pool.query(
      `SELECT
         v.id AS vehicle_id,
         v.plate_number,
         v.model,
         v.color,
         st.full_name,
         st.student_number,
         s.status AS sticker_status,
         s.sticker_code,
         s.qr_token,
         s.expires_at,
         (
           SELECT sl2.action
           FROM scan_logs sl2
           WHERE sl2.sticker_id = s.id
             AND sl2.result = 'VALID'
             AND sl2.action IN ('ENTRY', 'EXIT')
           ORDER BY sl2.scanned_at DESC, sl2.id DESC
           LIMIT 1
         ) AS last_action,
         (
           SELECT ps.slot_code
           FROM parking_slots ps
           WHERE ps.current_sticker_id = s.id
           LIMIT 1
         ) AS current_slot
       FROM vehicles v
       JOIN students st ON st.id = v.student_id
       LEFT JOIN stickers s ON s.id = (
         SELECT id FROM stickers
         WHERE vehicle_id = v.id
           AND status = 'active'
         ORDER BY created_at DESC
         LIMIT 1
       )
       WHERE v.plate_number LIKE ?
          OR st.student_number LIKE ?
          OR st.full_name LIKE ?
       ORDER BY st.full_name ASC
       LIMIT 10`,
      [like, like, like]
    );
    res.json({ ok: true, results });
  } catch (error) {
    console.error("Gate lookup error:", error);
    res.status(500).json({ ok: false, message: "Search failed.", results: [] });
  }
});

app.get("/api/parking-slots", requireAuth, async (req, res) => {
  try {
    const slots = await getAvailableParkingSlots();
    res.json({ ok: true, slots });
  } catch (error) {
    console.error("Parking slots API error:", error);
    res.status(500).json({ ok: false, message: "Failed to load parking slots.", slots: [] });
  }
});

app.get("/api/parking-slot-overview", requireAuth, async (req, res) => {
  try {
    const overview = await getParkingSlotOverview();
    res.json({ ok: true, ...overview });
  } catch (error) {
    console.error("Parking slot overview API error:", error);
    res.status(500).json({
      ok: false,
      message: "Failed to load parking slot overview.",
      slots: [],
      summary: { total: 0, available: 0, occupied: 0, disabled: 0 }
    });
  }
});

// API: manually record ENTRY or EXIT for a sticker (by qr_token)
app.post("/api/manual-movement", requireAuth, async (req, res) => {
  const token = normalizeQrTokenInput(req.body.token);
  const { action, gate, slot_id } = req.body;
  const selectedAction = String(action || "").toUpperCase();
  const slotId = slot_id ? Number(slot_id) : null;

  if (!token) return res.status(400).json({ ok: false, message: "Missing sticker token." });
  if (!["ENTRY", "EXIT"].includes(selectedAction)) {
    return res.status(400).json({ ok: false, message: "Invalid action." });
  }

  try {
    const verification = await getVerificationState(token);
    if (!verification.ok) {
      return res.json({ ok: false, message: verification.message, movement_saved: false });
    }

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [verification.sticker.id]);

      const lastMovement = await getLastValidMovement(verification.sticker.id, connection);
      if (lastMovement && lastMovement.action === selectedAction) {
        await connection.rollback();
        return res.json({
          ok: false,
          movement_saved: false,
          duplicate_movement: true,
          message: `Vehicle's last recorded movement is already ${selectedAction}.`
        });
      }

      let currentSlot = null;
      if (selectedAction === "ENTRY") {
        if (!slotId) {
          await connection.rollback();
          return res.status(400).json({ ok: false, message: "Please select a parking slot before recording entry." });
        }
        currentSlot = await assignParkingSlot(connection, verification.sticker.id, slotId);
      } else {
        currentSlot = await getCurrentParkingSlotBySticker(verification.sticker.id, connection);
      }

      const scanLog = await insertScanLogWithDb(
        connection,
        verification.sticker.id,
        "VALID",
        selectedAction,
        gate || "Manual Gate",
        "Recorded via Gate Console",
        {
          gateId: gate || "Manual Gate",
          slotId: currentSlot?.id || null,
          qrValue: token,
          studentId: verification.sticker.student_id_ref || null,
          vehicleId: verification.sticker.vehicle_id_ref || verification.sticker.vehicle_id || null,
          assignedArea: currentSlot?.zone || null,
          assignedByGuard: req.session?.adminUser || null,
          scanSource: "manual",
          status: "AUTHORIZED"
        }
      );

      if (selectedAction === "EXIT") {
        await releaseParkingSlot(connection, verification.sticker.id);
      }

      await connection.commit();

      res.json({
        ok: true,
        movement_saved: true,
        action: selectedAction,
        parking_slot: currentSlot?.slot_code || null,
        scan_log_id: scanLog?.id || null,
        scanned_at: scanLog?.scanned_at || null
      });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Manual movement error:", error);
    res.status(400).json({ ok: false, message: error.message || "Failed to record movement." });
  }
});

// API: force exit for a sticker (admin only)
app.post("/api/force-exit", requireAuth, async (req, res) => {
  const { sticker_id, gate } = req.body;
  if (!sticker_id) return res.status(400).json({ ok: false, message: "Missing sticker_id" });

  try {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [sticker_id]);
      const currentSlot = await getCurrentParkingSlotBySticker(sticker_id, connection);
      const scanLog = await insertScanLogWithDb(
        connection,
        sticker_id,
        "VALID",
        "EXIT",
        gate || "Admin Console",
        "Forced Exit by Admin",
        {
          gateId: gate || "Admin Console",
          slotId: currentSlot?.id || null,
          assignedArea: currentSlot?.zone || null,
          assignedByGuard: req.session?.adminUser || null,
          scanSource: "manual",
          status: "AUTHORIZED"
        }
      );
      await releaseParkingSlot(connection, sticker_id);
      await connection.commit();

      res.json({
        ok: true,
        movement_saved: true,
        action: "EXIT",
        parking_slot: currentSlot?.slot_code || null,
        scan_log_id: scanLog?.id || null,
        scanned_at: scanLog?.scanned_at || null
      });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Force exit error:", error);
    res.status(400).json({ ok: false, message: error.message || "Failed to force exit." });
  }
});

app.get("/reports", requireAuth, async (req, res) => {
  try {
    const filters = buildReportFilters(req.query);
    const data = await getReportsData(filters);

    if (req.query.format === "csv") {
      const header = [
        "scanned_at",
        "student_number",
        "full_name",
        "plate_number",
        "sticker_code",
        "result",
        "action",
        "gate",
        "parking_slot",
        "notes"
      ];
      const lines = [header.join(",")];
      for (const row of data.rows) {
        lines.push(
          [
            escapeCsv(row.scanned_at),
            escapeCsv(row.student_number),
            escapeCsv(row.full_name),
            escapeCsv(row.plate_number),
            escapeCsv(row.sticker_code),
            escapeCsv(row.result),
            escapeCsv(row.action),
            escapeCsv(row.gate),
            escapeCsv(row.parking_slot),
            escapeCsv(row.notes)
          ].join(",")
        );
      }

      const filename = `naap-scan-report-${filters.from}-to-${filters.to}.csv`;
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      return res.send(lines.join("\n"));
    }

    res.render("reports", data);
  } catch (error) {
    console.error("Reports error:", error);
    res.status(500).send("An error occurred loading reports.");
  }
});

app.post("/api/scan", requireAuth, async (req, res) => {
  const token = normalizeQrTokenInput(req.body.token);
  const { gate } = req.body;
  if (!token) return res.status(400).json({ ok: false, message: "Missing token" });

  try {
    const result = await resolveScan(token, gate || "Main Gate");
    res.json(result);
  } catch (error) {
    console.error("Scan API error:", error);
    res.status(500).json({ ok: false, message: "Scan processing failed. Please try again." });
  }
});

// PWA Offline Sync: Download active roster to local DB
app.get("/api/sync-roster", requireAuth, async (req, res) => {
  try {
    const [roster] = await pool.query(`
      SELECT
        s.qr_token,
        s.sticker_code,
        s.expires_at,
        v.plate_number,
        v.model,
        v.color,
        st.full_name,
        st.student_number
      FROM stickers s
      JOIN vehicles v ON v.id = s.vehicle_id
      JOIN students st ON st.id = v.student_id
      WHERE s.status = 'active'
        AND (s.expires_at IS NULL OR s.expires_at >= NOW())
    `);
    res.json({ ok: true, roster });
  } catch (error) {
    console.error("Sync roster error:", error);
    res.status(500).json({ ok: false, message: "Failed to download roster." });
  }
});

// PWA Offline Sync: Upload pending outbox to main DB
app.post("/api/sync-queue", requireAuth, async (req, res) => {
  const { movements } = req.body;
  if (!Array.isArray(movements) || movements.length === 0) {
    return res.json({ ok: true });
  }

  try {
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      for (const m of movements) {
        // Find the sticker
        const [stickerRows] = await connection.query(
          "SELECT id FROM stickers WHERE qr_token = ? LIMIT 1",
          [m.token]
        );
        if (stickerRows.length > 0) {
          const stickerId = stickerRows[0].id;
          // Format the offline timestamp so MySQL accepts it
          let scannedAt = new Date().toISOString().slice(0, 19).replace('T', ' ');
          if (m.offline_timestamp) {
            const dt = new Date(m.offline_timestamp);
            if (!Number.isNaN(dt.getTime())) {
              scannedAt = dt.toISOString().slice(0, 19).replace('T', ' ');
            }
          }

          await connection.query(
            "INSERT INTO scan_logs (sticker_id, result, action, gate, notes, scanned_at) VALUES (?, ?, ?, ?, ?, ?)",
            [stickerId, "VALID", m.action, m.gate || "Offline Scan", "Synced from Offline Device", scannedAt]
          );
        }
      }
      await connection.commit();
      res.json({ ok: true, synced_count: movements.length });
    } catch (err) {
      await connection.rollback();
      throw err;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Sync queue error:", error);
    res.status(500).json({ ok: false, message: "Failed to sync offline queue." });
  }
});

async function startServer() {
  try {
    await ensureDatabaseSchema();
    app.listen(PORT, () => {
      console.log(`NAAP Parking app running at ${APP_BASE_URL}`);
    });
  } catch (error) {
    console.error("Failed to initialize database schema:", error.message);
    process.exit(1);
  }
}

startServer();
