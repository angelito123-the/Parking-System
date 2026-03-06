const express = require("express");
const path = require("path");
const crypto = require("crypto");
const QRCode = require("qrcode");
const pool = require("./db");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.set("trust proxy", true);
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use((req, res, next) => {
  res.locals.currentPath = req.path;
  res.locals.requestBaseUrl = `${req.protocol}://${req.get("host")}`;
  next();
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

  return {
    metrics: {
      students: studentsCount.total,
      vehicles: vehiclesCount.total,
      activeStickers: stickersCount.total,
      todayEntries: todayEntries.total,
      todayExits: todayExits.total,
      currentlyInside: currentlyInside.total
    },
    movementLogs
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
  const [insertResult] = await pool.query(
    "INSERT INTO scan_logs (sticker_id, result, action, gate, notes) VALUES (?, ?, ?, ?, ?)",
    [stickerId, result, action, gate, notes]
  );
  const [logRows] = await pool.query(
    "SELECT id, scanned_at FROM scan_logs WHERE id = ? LIMIT 1",
    [insertResult.insertId]
  );

  return logRows.length > 0 ? logRows[0] : null;
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

  const [lastLogRows] = await pool.query(
    "SELECT action FROM scan_logs WHERE sticker_id = ? AND result = 'VALID' ORDER BY scanned_at DESC LIMIT 1",
    [sticker.id]
  );
  const action = lastLogRows.length > 0 && lastLogRows[0].action === "ENTRY" ? "EXIT" : "ENTRY";

  const scanLog = await insertScanLog(sticker.id, "VALID", action, gate, "Verified");

  return {
    ...verification,
    action,
    scan_log_id: scanLog?.id || null,
    scanned_at: scanLog?.scanned_at || null
  };
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

app.get("/", async (req, res) => {
  try {
    const data = await getDashboardData();
    res.render("dashboard", data);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get("/students", async (req, res) => {
  try {
    const [students] = await pool.query(
      "SELECT * FROM students ORDER BY created_at DESC, id DESC"
    );
    res.render("students", { students });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/students", async (req, res) => {
  const { student_number, full_name, program, email } = req.body;
  try {
    await pool.query(
      "INSERT INTO students (student_number, full_name, program, email) VALUES (?, ?, ?, ?)",
      [student_number, full_name, program || null, email || null]
    );
    res.redirect("/students");
  } catch (error) {
    res.status(400).send(`Unable to create student: ${error.message}`);
  }
});

app.get("/vehicles", async (req, res) => {
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
    res.render("vehicles", { vehicles, students });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/vehicles", async (req, res) => {
  const { student_id, plate_number, model, color } = req.body;
  try {
    await pool.query(
      "INSERT INTO vehicles (student_id, plate_number, model, color) VALUES (?, ?, ?, ?)",
      [student_id, plate_number, model || null, color || null]
    );
    res.redirect("/vehicles");
  } catch (error) {
    res.status(400).send(`Unable to create vehicle: ${error.message}`);
  }
});

app.get("/stickers", async (req, res) => {
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
    res.render("stickers", { stickers, vehicles, APP_BASE_URL });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/stickers", async (req, res) => {
  const { vehicle_id, expires_at } = req.body;
  const sticker_code = createStickerCode();
  const qr_token = createQrToken();

  try {
    await pool.query(
      "INSERT INTO stickers (vehicle_id, sticker_code, qr_token, expires_at) VALUES (?, ?, ?, ?)",
      [vehicle_id, sticker_code, qr_token, expires_at || null]
    );
    res.redirect("/stickers");
  } catch (error) {
    res.status(400).send(`Unable to issue sticker: ${error.message}`);
  }
});

app.post("/stickers/:id/revoke", async (req, res) => {
  try {
    await pool.query("UPDATE stickers SET status = 'revoked' WHERE id = ?", [req.params.id]);
    res.redirect("/stickers");
  } catch (error) {
    res.status(400).send(`Unable to revoke sticker: ${error.message}`);
  }
});

app.get("/stickers/:id/qr", async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT qr_token FROM stickers WHERE id = ?", [req.params.id]);
    if (rows.length === 0) return res.status(404).send("Sticker not found");

    const requestBaseUrl = `${req.protocol}://${req.get("host")}`;
    const verifyUrl = `${requestBaseUrl}/verify/${rows[0].qr_token}`;
    const png = await QRCode.toBuffer(verifyUrl, { type: "png", width: 600 });
    res.type("png");
    res.send(png);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get("/verify/:token", async (req, res) => {
  try {
    const result = await verifyAndLog(req.params.token, "Manual Verification");
    res.render("verify", { result });
  } catch (error) {
    res.status(500).send(error.message);
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

    const scanLog = await insertScanLog(
      verification.sticker.id,
      "VALID",
      selectedAction,
      gate,
      "Movement selected manually"
    );

    const result = {
      ...verification,
      action: selectedAction,
      movement_saved: true,
      scan_log_id: scanLog?.id || null,
      scanned_at: scanLog?.scanned_at || null
    };
    res.render("verify", { result });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get("/scanner", (req, res) => {
  res.render("scanner");
});

app.get("/reports", async (req, res) => {
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
      res.setHeader("Content-Disposition", `attachment; filename=\"${filename}\"`);
      return res.send(lines.join("\n"));
    }

    res.render("reports", data);
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/api/scan", async (req, res) => {
  const { token, gate } = req.body;
  if (!token) return res.status(400).json({ ok: false, message: "Missing token" });

  try {
    const result = await resolveScan(token, gate || "Main Gate");
    res.json(result);
  } catch (error) {
    res.status(500).json({ ok: false, message: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`NAAP Parking app running at ${APP_BASE_URL}`);
});
