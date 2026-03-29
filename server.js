process.env.TZ = "Asia/Manila";
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const QRCode = require("qrcode");
const session = require("express-session");
const { pool, ensureDatabaseSchema } = require("./db");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;
const SCAN_COOLDOWN_SECONDS = Number(process.env.SCAN_COOLDOWN_SECONDS || 12);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "naap2024";
const SESSION_SECRET = process.env.SESSION_SECRET || "naap-parking-secret";

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
    `SELECT s.*, v.plate_number, v.model, st.full_name, st.student_number
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
       s.sticker_code,
       st.full_name,
       st.student_number,
       v.plate_number
     FROM scan_logs sl
     LEFT JOIN stickers s ON s.id = sl.sticker_id
     LEFT JOIN vehicles v ON v.id = s.vehicle_id
     LEFT JOIN students st ON st.id = v.student_id
     ORDER BY sl.scanned_at DESC
     LIMIT 50`
  );
  const [insideVehicles] = await pool.query(
    `SELECT
       latest.scanned_at AS entered_at,
       latest.gate AS entry_gate,
       TIMESTAMPDIFF(MINUTE, latest.scanned_at, NOW()) AS minutes_inside,
       s.sticker_code,
       st.student_number,
       st.full_name,
       v.plate_number
     FROM (
       SELECT sl.sticker_id, sl.action, sl.gate, sl.scanned_at
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
     WHERE latest.action = 'ENTRY'
     ORDER BY latest.scanned_at ASC
     LIMIT 20`
  );
  return {
    metrics: {
      students: studentsCount.total,
      vehicles: vehiclesCount.total,
      activeStickers: stickersCount.total,
      todayEntries: todayEntries.total,
      todayExits: todayExits.total,
      currentlyInside: currentlyInside.total
    },
    movementLogs,
    insideVehicles
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
      sl.notes,
      s.sticker_code,
      st.student_number,
      st.full_name,
      v.plate_number
     FROM scan_logs sl
     LEFT JOIN stickers s ON s.id = sl.sticker_id
     LEFT JOIN vehicles v ON v.id = s.vehicle_id
     LEFT JOIN students st ON st.id = v.student_id
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

async function insertScanLog(stickerId, result, action, gate, notes) {
  return insertScanLogWithDb(pool, stickerId, result, action, gate, notes);
}

async function insertScanLogWithDb(db, stickerId, result, action, gate, notes) {
  const [insertResult] = await db.query(
    "INSERT INTO scan_logs (sticker_id, result, action, gate, notes) VALUES (?, ?, ?, ?, ?)",
    [stickerId, result, action, gate, notes]
  );
  const [logRows] = await db.query(
    "SELECT id, scanned_at FROM scan_logs WHERE id = ? LIMIT 1",
    [insertResult.insertId]
  );

  return logRows.length > 0 ? logRows[0] : null;
}

async function getLastValidMovement(stickerId, db = pool) {
  const [rows] = await db.query(
    `SELECT id, action, scanned_at
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
    const scanLog = await insertScanLog(null, "INVALID", "VERIFY", gate, "Token not found");
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
      "Sticker is not active"
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
      "Sticker expired"
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

    if (lastMovement && SCAN_COOLDOWN_SECONDS > 0) {
      const lastScannedAtMs = new Date(lastMovement.scanned_at).getTime();
      if (Number.isFinite(lastScannedAtMs)) {
        const secondsSinceLastScan = Math.floor((Date.now() - lastScannedAtMs) / 1000);
        if (secondsSinceLastScan >= 0 && secondsSinceLastScan < SCAN_COOLDOWN_SECONDS) {
          await connection.rollback();
          return {
            ...verification,
            action: lastMovement.action,
            duplicate_scan: true,
            cooldown_seconds: SCAN_COOLDOWN_SECONDS,
            seconds_since_last_scan: secondsSinceLastScan,
            message: `Scan ignored to prevent duplicate. Please wait ${SCAN_COOLDOWN_SECONDS} seconds before rescanning.`,
            scan_log_id: null,
            scanned_at: lastMovement.scanned_at
          };
        }
      }
    }

    const action = lastMovement && lastMovement.action === "ENTRY" ? "EXIT" : "ENTRY";
    const scanLog = await insertScanLogWithDb(connection, sticker.id, "VALID", action, gate, "Verified");
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
    noteByResult[verification.result] || "Manual verification"
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
    const [insideVehicles] = await pool.query(
      `SELECT
         latest.scanned_at AS entered_at,
         latest.gate AS entry_gate,
         TIMESTAMPDIFF(MINUTE, latest.scanned_at, NOW()) AS minutes_inside,
         s.sticker_code,
         st.student_number,
         st.full_name,
         v.plate_number
       FROM (
         SELECT sl.sticker_id, sl.action, sl.gate, sl.scanned_at
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
       WHERE latest.action = 'ENTRY'
       ORDER BY latest.scanned_at ASC
       LIMIT 20`
    );
    res.json({ ok: true, insideVehicles });
  } catch (error) {
    console.error("Inside vehicles API error:", error);
    res.status(500).json({ ok: false, message: "Failed to fetch vehicles." });
  }
});

app.get("/students", requireAuth, async (req, res) => {
  try {
    const [students] = await pool.query(
      "SELECT * FROM students ORDER BY created_at DESC, id DESC"
    );
    const flash = req.query.success
      ? { type: "success", message: "Student saved successfully." }
      : req.query.error === "duplicate"
      ? { type: "error", message: "A student with that student number already exists." }
      : req.query.error === "delete"
      ? { type: "error", message: "Unable to delete student — they may still have linked vehicles." }
      : req.query.deleted
      ? { type: "success", message: "Student deleted successfully." }
      : null;
    res.render("students", { students, flash });
  } catch (error) {
    console.error("Students error:", error);
    res.status(500).send("An error occurred loading students.");
  }
});

app.post("/students", requireAuth, async (req, res) => {
  const { student_number, full_name, program, email } = req.body;
  try {
    await pool.query(
      "INSERT INTO students (student_number, full_name, program, email) VALUES (?, ?, ?, ?)",
      [student_number, full_name, program || null, email || null]
    );
    res.redirect("/students?success=1");
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.redirect("/students?error=duplicate");
    }
    console.error("Create student error:", error);
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

app.get("/vehicles", requireAuth, async (req, res) => {
  try {
    const [students] = await pool.query(
      "SELECT id, student_number, full_name FROM students ORDER BY full_name ASC"
    );
    const [vehicles] = await pool.query(
      `SELECT v.*, s.student_number, s.full_name
       FROM vehicles v
       JOIN students s ON s.id = v.student_id
       ORDER BY v.created_at DESC, v.id DESC`
    );
    const flash = req.query.success
      ? { type: "success", message: "Vehicle saved successfully." }
      : req.query.error === "delete"
      ? { type: "error", message: "Unable to delete vehicle — it may still have linked stickers." }
      : req.query.deleted
      ? { type: "success", message: "Vehicle deleted successfully." }
      : null;
    res.render("vehicles", { vehicles, students, flash });
  } catch (error) {
    console.error("Vehicles error:", error);
    res.status(500).send("An error occurred loading vehicles.");
  }
});

app.post("/vehicles", requireAuth, async (req, res) => {
  const { student_id, plate_number, model, color } = req.body;
  try {
    await pool.query(
      "INSERT INTO vehicles (student_id, plate_number, model, color) VALUES (?, ?, ?, ?)",
      [student_id, plate_number, model || null, color || null]
    );
    res.redirect("/vehicles?success=1");
  } catch (error) {
    console.error("Create vehicle error:", error);
    res.redirect("/vehicles?error=1");
  }
});

app.post("/vehicles/:id/delete", requireAuth, async (req, res) => {
  try {
    await pool.query("DELETE FROM vehicles WHERE id = ?", [req.params.id]);
    res.redirect("/vehicles?deleted=1");
  } catch (error) {
    console.error("Delete vehicle error:", error);
    res.redirect("/vehicles?error=delete");
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
    if (verification.ok && verification.sticker) {
       const lastMovement = await getLastValidMovement(verification.sticker.id);
       if (lastMovement) lastAction = lastMovement.action;
    }
    const result = { ...verification, last_action: lastAction };
    res.render("verify", { result });
  } catch (error) {
    console.error("Verify GET error:", error);
    res.status(500).send("An error occurred during verification.");
  }
});

app.post("/verify/:token/movement", async (req, res) => {
  const selectedAction = String(req.body.action || "").toUpperCase();
  const gate = req.body.gate || "Manual Verification";

  if (!["ENTRY", "EXIT"].includes(selectedAction)) {
    return res.status(400).send("Invalid action. Please choose ENTRY or EXIT.");
  }

  try {
    const verification = await getVerificationState(req.params.token);
    if (!verification.ok) {
      return res.render("verify", { result: verification });
    }

    const sticker = verification.sticker;
    const connection = await pool.getConnection();
    let movement_saved = false;
    let duplicate_movement = false;
    let savedAction = selectedAction;
    let scanLog = null;

    try {
      await connection.beginTransaction();
      // Lock the sticker row to prevent concurrent duplicate submissions
      await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [sticker.id]);

      const lastMovement = await getLastValidMovement(sticker.id, connection);
      if (lastMovement && lastMovement.action === selectedAction) {
        await connection.rollback();
        duplicate_movement = true;
      } else {
        scanLog = await insertScanLogWithDb(connection, sticker.id, "VALID", selectedAction, gate, "Movement selected manually");
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
      movement_saved,
      duplicate_movement,
      message: duplicate_movement
        ? `Movement ignored — last recorded movement is already ${selectedAction}.`
        : verification.message,
      scan_log_id: scanLog?.id || null,
      scanned_at: scanLog?.scanned_at || null
    };
    res.render("verify", { result });
  } catch (error) {
    console.error("Movement error:", error);
    res.status(500).send("An error occurred recording movement.");
  }
});

app.get("/scanner", requireAuth, (req, res) => {
  res.render("scanner");
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
         s.expires_at
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

// API: manually record ENTRY or EXIT for a sticker (by qr_token)
app.post("/api/manual-movement", requireAuth, async (req, res) => {
  const { token, action, gate } = req.body;
  const selectedAction = String(action || "").toUpperCase();

  if (!token) return res.status(400).json({ ok: false, message: "Missing sticker token." });
  if (!["ENTRY", "EXIT"].includes(selectedAction)) {
    return res.status(400).json({ ok: false, message: "Invalid action." });
  }

  try {
    const verification = await getVerificationState(token);
    if (!verification.ok) {
      return res.json({ ok: false, message: verification.message, movement_saved: false });
    }

    const lastMovement = await getLastValidMovement(verification.sticker.id);
    if (lastMovement && lastMovement.action === selectedAction) {
      return res.json({
        ok: false,
        movement_saved: false,
        duplicate_movement: true,
        message: `Vehicle's last recorded movement is already ${selectedAction}.`
      });
    }

    const scanLog = await insertScanLog(
      verification.sticker.id,
      "VALID",
      selectedAction,
      gate || "Manual Gate",
      "Recorded via Gate Console"
    );

    res.json({
      ok: true,
      movement_saved: true,
      action: selectedAction,
      scan_log_id: scanLog?.id || null,
      scanned_at: scanLog?.scanned_at || null
    });
  } catch (error) {
    console.error("Manual movement error:", error);
    res.status(500).json({ ok: false, message: "Failed to record movement." });
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
  const { token, gate } = req.body;
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
