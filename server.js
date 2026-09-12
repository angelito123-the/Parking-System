process.env.TZ = "Asia/Manila";
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const compression = require("compression");
const multer = require("multer");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const { pool, ensureDatabaseSchema } = require("./db");
const { openEventStream } = require("./lib/event-stream");
const { generateBrandedQrPng } = require("./lib/branded-qr");
const {
  MailConfigurationError,
  normalizeEmailAddress,
  sendBackupArchiveEmail,
  sendStudentQrEmail
} = require("./lib/student-qr-email");
const {
  BackupValidationError,
  decryptBackup,
  encryptBackup,
  summarizeBackupPayload
} = require("./lib/encrypted-backup");
const { serializeForScript } = require("./lib/serialize-for-script");
const { escapeCsvCell, parseCsv, parseCsvDocument, stringifyCsv } = require("./lib/csv");
const {
  STUDENT_IMPORT_COLUMNS,
  validateStudentImportDocument
} = require("./lib/student-import");
const {
  SlidingWindowRateLimiter,
  hashIdentifier,
  validatePassword
} = require("./lib/security");
const {
  ACADEMIC_PROGRAM_GROUPS,
  YEAR_LEVELS,
  findAcademicProgram,
  getYearLevelLabel,
  isValidAcademicProgram,
  isValidYearLevel
} = require("./lib/academic-programs");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const APP_BASE_URL = process.env.APP_BASE_URL
  || process.env.RENDER_EXTERNAL_URL
  || `http://localhost:${PORT}`;
let APP_ORIGIN;
try {
  const parsedBaseUrl = new URL(APP_BASE_URL);
  if (!['http:', 'https:'].includes(parsedBaseUrl.protocol)) throw new Error('Unsupported protocol.');
  if (IS_PRODUCTION && parsedBaseUrl.protocol !== 'https:') {
    throw new Error('Production URL must use HTTPS.');
  }
  APP_ORIGIN = parsedBaseUrl.origin;
} catch (error) {
  throw new Error(`APP_BASE_URL must be a valid${IS_PRODUCTION ? ' HTTPS' : ''} URL: ${error.message}`);
}
const SCAN_COOLDOWN_SECONDS = Number(process.env.SCAN_COOLDOWN_SECONDS || 10);
const AUTO_PENDING_EXPIRY_MINUTES = Math.max(
  5,
  Number.isFinite(Number(process.env.AUTO_PENDING_EXPIRY_MINUTES))
    ? Number(process.env.AUTO_PENDING_EXPIRY_MINUTES)
    : 20
);
const AUTO_SCAN_HEARTBEAT_INTERVAL_SECONDS = Math.max(
  3,
  Number.isFinite(Number(process.env.AUTO_SCAN_HEARTBEAT_INTERVAL_SECONDS))
    ? Number(process.env.AUTO_SCAN_HEARTBEAT_INTERVAL_SECONDS)
    : 6
);
const AUTO_SCAN_ONLINE_WINDOW_SECONDS = Math.max(
  AUTO_SCAN_HEARTBEAT_INTERVAL_SECONDS + 2,
  Number.isFinite(Number(process.env.AUTO_SCAN_ONLINE_WINDOW_SECONDS))
    ? Number(process.env.AUTO_SCAN_ONLINE_WINDOW_SECONDS)
    : 18
);
const AUTO_SCAN_SSE_KEEPALIVE_SECONDS = Math.max(
  10,
  Number.isFinite(Number(process.env.AUTO_SCAN_SSE_KEEPALIVE_SECONDS))
    ? Number(process.env.AUTO_SCAN_SSE_KEEPALIVE_SECONDS)
    : 20
);
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "8mb";
const rawOverstayLimitHours = Number(process.env.OVERSTAY_LIMIT_HOURS);
const OVERSTAY_LIMIT_HOURS = Number.isFinite(rawOverstayLimitHours)
  ? Math.max(0.5, rawOverstayLimitHours)
  : 4;
const OVERSTAY_LIMIT_MINUTES = Math.max(1, Math.round(OVERSTAY_LIMIT_HOURS * 60));
function readBoundedIntegerEnv(name, fallback, min, max) {
  const parsed = Number.parseInt(String(process.env[name] || ""), 10);
  const value = Number.isInteger(parsed) ? parsed : fallback;
  return Math.max(min, Math.min(max, value));
}
const GUARD_INACTIVITY_DAYS = readBoundedIntegerEnv("GUARD_INACTIVITY_DAYS", IS_PRODUCTION ? 120 : 0, 0, 3650);
const SNAPSHOT_RETENTION_DAYS = readBoundedIntegerEnv("SNAPSHOT_RETENTION_DAYS", 30, 1, 3650);
const SCAN_LOG_RETENTION_DAYS = readBoundedIntegerEnv("SCAN_LOG_RETENTION_DAYS", 365, 30, 3650);
const SECURITY_AUDIT_RETENTION_DAYS = readBoundedIntegerEnv("SECURITY_AUDIT_RETENTION_DAYS", 730, 90, 3650);
const SCANNER_METRIC_RETENTION_DAYS = readBoundedIntegerEnv("SCANNER_METRIC_RETENTION_DAYS", 90, 7, 3650);
const BACKUP_RETENTION_DAYS = readBoundedIntegerEnv("BACKUP_RETENTION_DAYS", 14, 1, 365);
const BACKUP_ENCRYPTION_KEY = String(process.env.BACKUP_ENCRYPTION_KEY || "");
const BACKUP_EMAIL_TO = normalizeEmailAddress(process.env.BACKUP_EMAIL_TO) || null;
const backupUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024, files: 1, fields: 4 }
});
const configuredSessionSecret = String(process.env.SESSION_SECRET || "").trim();
if (IS_PRODUCTION && configuredSessionSecret.length < 32) {
  throw new Error("SESSION_SECRET must contain at least 32 characters in production.");
}
const SESSION_SECRET = configuredSessionSecret || "naap-parking-local-development-secret";
const loginRateLimiter = new SlidingWindowRateLimiter({ limit: 5, windowMs: 15 * 60 * 1000 });
const loginAccountRateLimiter = new SlidingWindowRateLimiter({ limit: 15, windowMs: 15 * 60 * 1000 });
const accountSecurityRateLimiter = new SlidingWindowRateLimiter({ limit: 8, windowMs: 15 * 60 * 1000 });
const qrEmailRateLimiter = new SlidingWindowRateLimiter({ limit: 10, windowMs: 10 * 60 * 1000 });
const EMAIL_WORKER_INTERVAL_MS = Math.max(5000, Number(process.env.EMAIL_WORKER_INTERVAL_MS || 15000) || 15000);
let emailWorkerRunning = false;
const SNAPSHOT_DIR = path.join(__dirname, "storage", "snapshots");
const LEGACY_PUBLIC_SNAPSHOT_DIR = path.join(__dirname, "public", "snapshots");
const SNAPSHOT_MAX_BYTES = Number(process.env.SCAN_SNAPSHOT_MAX_BYTES || 3 * 1024 * 1024);
const USER_ROLES = Object.freeze({
  ADMIN: "admin",
  GUARD: "guard"
});
const VALID_ROLES = new Set(Object.values(USER_ROLES));
const VISITOR_TYPES = Object.freeze({
  VISITOR: "visitor",
  PARENT: "parent",
  SUPPLIER: "supplier",
  DELIVERY: "delivery",
  SERVICE: "service",
  TEMPORARY: "temporary"
});
const VALID_VISITOR_TYPES = new Set(Object.values(VISITOR_TYPES));
const VISITOR_APPROVAL_STATUS = Object.freeze({
  PENDING: "PENDING",
  APPROVED: "APPROVED",
  REJECTED: "REJECTED",
  CANCELLED: "CANCELLED"
});
const VISITOR_PASS_STATE = Object.freeze({
  PENDING: "PENDING",
  ACTIVE: "ACTIVE",
  INSIDE: "INSIDE",
  EXITED: "EXITED",
  EXPIRED: "EXPIRED",
  REVOKED: "REVOKED"
});
const ALERT_TYPES = Object.freeze({
  INVALID_QR_ATTEMPT: "INVALID_QR_ATTEMPT",
  FULL_PARKING_ZONE: "FULL_PARKING_ZONE",
  LOW_SLOT_WARNING: "LOW_SLOT_WARNING",
  PENDING_ENTRY_APPROVAL: "PENDING_ENTRY_APPROVAL",
  SUSPICIOUS_SCAN_BEHAVIOR: "SUSPICIOUS_SCAN_BEHAVIOR",
  VISITOR_OVERSTAY: "VISITOR_OVERSTAY"
});
const ALERT_SEVERITIES = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical"
});
const ALERT_STATUS = Object.freeze({
  ACTIVE: "active",
  RESOLVED: "resolved"
});
const INVALID_SCAN_RESULTS = new Set(["INVALID", "REVOKED", "EXPIRED"]);
const SUSPICIOUS_WINDOW_MINUTES = Math.max(
  1,
  Number.isFinite(Number(process.env.SUSPICIOUS_WINDOW_MINUTES))
    ? Number(process.env.SUSPICIOUS_WINDOW_MINUTES)
    : 5
);
const SUSPICIOUS_FAILED_SCAN_THRESHOLD = Math.max(
  3,
  Number.isFinite(Number(process.env.SUSPICIOUS_FAILED_SCAN_THRESHOLD))
    ? Number(process.env.SUSPICIOUS_FAILED_SCAN_THRESHOLD)
    : 4
);
const SUSPICIOUS_REPEAT_QR_THRESHOLD = Math.max(
  3,
  Number.isFinite(Number(process.env.SUSPICIOUS_REPEAT_QR_THRESHOLD))
    ? Number(process.env.SUSPICIOUS_REPEAT_QR_THRESHOLD)
    : 5
);
const VISITOR_OVERSTAY_HOURS = Math.max(
  1,
  Number.isFinite(Number(process.env.VISITOR_OVERSTAY_HOURS))
    ? Number(process.env.VISITOR_OVERSTAY_HOURS)
    : OVERSTAY_LIMIT_HOURS
);
const VISITOR_OVERSTAY_MINUTES = Math.max(1, Math.round(VISITOR_OVERSTAY_HOURS * 60));
const autoScanSseClients = new Map();
const notificationSseClients = new Map();

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
const configuredProxyHops = Number.parseInt(process.env.TRUST_PROXY_HOPS, 10);
const trustedProxyHops = Number.isInteger(configuredProxyHops)
  ? Math.max(0, Math.min(configuredProxyHops, 5))
  : 1;
app.set("trust proxy", IS_PRODUCTION ? trustedProxyHops : false);
app.set("view cache", IS_PRODUCTION);
app.disable("x-powered-by");
app.use((_req, res, next) => {
  const cspNonce = crypto.randomBytes(18).toString("base64");
  res.locals.cspNonce = cspNonce;
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Permissions-Policy", "camera=(self), microphone=(), geolocation=(), payment=(), usb=()");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    `script-src 'self' 'nonce-${cspNonce}' https://cdn.jsdelivr.net https://unpkg.com`,
    "script-src-attr 'none'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' data: https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "media-src 'self' data: blob:",
    "worker-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'"
  ].join("; "));
  if (IS_PRODUCTION) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  next();
});
app.use(compression({
  filter(req, res) {
    if (req.path === "/api/notifications/events" || req.path === "/api/auto-scan/events") {
      return false;
    }
    return compression.filter(req, res);
  }
}));
const sessionStore = new MySQLStore({
  clearExpired: true,
  checkExpirationInterval: 15 * 60 * 1000,
  expiration: 8 * 60 * 60 * 1000,
  createDatabaseTable: true,
  endConnectionOnClose: false
}, pool);
const sessionMiddleware = session({
  name: "naap.sid",
  secret: SESSION_SECRET,
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: "lax",
    maxAge: 8 * 60 * 60 * 1000
  }
});
app.get(
  "/snapshots/:storageKey",
  sessionMiddleware,
  requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD),
  async (req, res, next) => {
    const storageKey = String(req.params.storageKey || "");
    if (!/^[a-z0-9][a-z0-9._-]{0,119}$/i.test(storageKey) || path.basename(storageKey) !== storageKey) {
      return res.status(404).send("Snapshot not found.");
    }

    try {
      const [rows] = await pool.query(
        "SELECT mime_type, image_data FROM scan_snapshots WHERE storage_key = ? LIMIT 1",
        [storageKey]
      );

      res.setHeader("Cache-Control", "private, no-store");
      res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
      res.setHeader("X-Content-Type-Options", "nosniff");

      if (rows.length > 0) {
        res.type(rows[0].mime_type || "application/octet-stream");
        return res.send(rows[0].image_data);
      }

      const legacyPath = path.join(SNAPSHOT_DIR, storageKey);
      try {
        const imageBuffer = await fs.promises.readFile(legacyPath);
        res.type(path.extname(storageKey));
        return res.send(imageBuffer);
      } catch (error) {
        if (error.code === "ENOENT") return res.status(404).send("Snapshot not found.");
        throw error;
      }
    } catch (error) {
      return next(error);
    }
  }
);
app.use(express.static(path.join(__dirname, "public"), {
  etag: true,
  lastModified: true,
  maxAge: IS_PRODUCTION ? "1d" : 0,
  setHeaders(res, filePath) {
    const filename = path.basename(filePath).toLowerCase();
    if (filename === "sw.js" || filename === "manifest.json") {
      res.setHeader("Cache-Control", "no-cache");
    }
  }
}));
app.use(express.urlencoded({ extended: true, limit: JSON_BODY_LIMIT }));
app.use(express.json({ limit: JSON_BODY_LIMIT }));
app.use(sessionMiddleware);
app.use((req, res, next) => {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) return next();
  const fetchSite = String(req.get("sec-fetch-site") || "").trim().toLowerCase();
  if (fetchSite === "cross-site") {
    if (req.path.startsWith("/api/")) {
      return res.status(403).json({ ok: false, message: "Cross-site request rejected." });
    }
    return res.status(403).send("Cross-site request rejected.");
  }
  const source = String(req.get("origin") || req.get("referer") || "").trim();
  if (!source) {
    // Browsers can omit Origin on some same-origin navigations. Fetch Metadata
    // is a trustworthy fallback because scripts cannot forge this header.
    if (fetchSite === "same-origin") return next();
    if (req.path.startsWith("/api/")) {
      return res.status(403).json({ ok: false, message: "Request origin is required." });
    }
    return res.status(403).send("Request origin is required.");
  }
  try {
    const sourceUrl = new URL(source);
    const expectedOrigin = IS_PRODUCTION ? APP_ORIGIN : `${req.protocol}://${req.get("host")}`;
    if (sourceUrl.origin !== expectedOrigin) {
      if (req.path.startsWith("/api/")) {
        return res.status(403).json({ ok: false, message: "Cross-site request rejected." });
      }
      return res.status(403).send("Cross-site request rejected.");
    }
  } catch (_error) {
    return res.status(403).send("Invalid request origin.");
  }
  return next();
});
app.get("/healthz", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    return res.status(200).json({ ok: true });
  } catch (_error) {
    return res.status(503).json({ ok: false, database: "unavailable" });
  }
});
function normalizeRole(rawRole) {
  const role = String(rawRole || "").trim().toLowerCase();
  return VALID_ROLES.has(role) ? role : null;
}

function getRoleHomePath(role) {
  const safeRole = normalizeRole(role);
  if (safeRole === USER_ROLES.ADMIN) return "/admin";
  if (safeRole === USER_ROLES.GUARD) return "/guard";
  return "/login";
}

function getSessionUser(req) {
  const user = req.session?.user;
  if (!user || typeof user !== "object") return null;
  const role = normalizeRole(user.role);
  if (!role) return null;
  return {
    id: Number(user.id) || null,
    username: String(user.username || "").trim(),
    role,
    mustChangePassword: Boolean(user.mustChangePassword)
  };
}

function getAuthActorName(req) {
  const username = req.authUser?.username || getSessionUser(req)?.username || "";
  return username || "system";
}

function getBrowserFamily(userAgentValue) {
  const userAgent = String(userAgentValue || "");
  if (/Edg\//i.test(userAgent)) return "Edge";
  if (/OPR\//i.test(userAgent)) return "Opera";
  if (/Firefox\//i.test(userAgent)) return "Firefox";
  if (/CriOS|Chrome\//i.test(userAgent)) return "Chrome";
  if (/Safari\//i.test(userAgent)) return "Safari";
  return "Other";
}

function getRateLimitKey(req, suffix = "") {
  const forwarded = String(req.ip || req.socket?.remoteAddress || "unknown");
  return `${hashIdentifier(forwarded, SESSION_SECRET)}:${String(suffix || "").toLowerCase()}`;
}

async function recordSecurityAudit(req, eventType, options = {}) {
  try {
    const actor = options.actor || req.authUser || getSessionUser(req) || null;
    const metadata = options.metadata && typeof options.metadata === "object"
      ? JSON.stringify(options.metadata)
      : null;
    await pool.query(
      `INSERT INTO security_audit_logs (
         event_type, actor_user_id, actor_username, actor_role,
         target_type, target_id, outcome, ip_hash, user_agent, metadata_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        String(eventType || "ACTIVITY").slice(0, 80),
        Number(actor?.id) || null,
        String(actor?.username || options.actorUsername || "").slice(0, 120) || null,
        String(actor?.role || "").slice(0, 30) || null,
        String(options.targetType || "").slice(0, 80) || null,
        String(options.targetId || "").slice(0, 120) || null,
        String(options.outcome || "success").slice(0, 30),
        hashIdentifier(req.ip || req.socket?.remoteAddress || "unknown", SESSION_SECRET),
        String(req.get("user-agent") || "").slice(0, 255) || null,
        metadata
      ]
    );
  } catch (error) {
    console.warn("Security audit warning (non-fatal):", error.message);
  }
}

function sessionFingerprint(sessionId) {
  return hashIdentifier(sessionId, SESSION_SECRET).slice(0, 12);
}

async function listUserSessions(userId, currentSessionId) {
  const [rows] = await pool.query("SELECT session_id, expires, data FROM sessions ORDER BY expires DESC");
  const sessions = [];
  for (const row of rows) {
    try {
      const data = typeof row.data === "string" ? JSON.parse(row.data) : row.data;
      if (Number(data?.user?.id) !== Number(userId)) continue;
      sessions.push({
        fingerprint: sessionFingerprint(row.session_id),
        current: row.session_id === currentSessionId,
        expires_at: Number(row.expires) > 1e12 ? new Date(Number(row.expires)) : new Date(Number(row.expires) * 1000)
      });
    } catch (_error) {
      // Ignore malformed or unrelated session records.
    }
  }
  return sessions;
}

async function revokeUserSessions(userId, options = {}) {
  const keepSessionId = options.keepSessionId || null;
  const targetFingerprint = options.fingerprint || null;
  const [rows] = await pool.query("SELECT session_id, data FROM sessions");
  const sessionIds = [];
  for (const row of rows) {
    try {
      const data = typeof row.data === "string" ? JSON.parse(row.data) : row.data;
      if (Number(data?.user?.id) !== Number(userId)) continue;
      if (keepSessionId && row.session_id === keepSessionId) continue;
      if (targetFingerprint && sessionFingerprint(row.session_id) !== targetFingerprint) continue;
      sessionIds.push(row.session_id);
    } catch (_error) {
      // Ignore malformed session records.
    }
  }
  if (sessionIds.length) await pool.query("DELETE FROM sessions WHERE session_id IN (?)", [sessionIds]);
  // Include streams whose session row has already expired or been deleted.
  closeUserEventStreams(client => client.userId === Number(userId)
    && client.sessionId !== keepSessionId
    && (!targetFingerprint || sessionFingerprint(client.sessionId) === targetFingerprint));
  return sessionIds.length;
}

function regenerateAuthenticatedSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) return reject(error);
      req.session.user = {
        id: Number(user.id) || null,
        username: String(user.username || "").trim(),
        role: normalizeRole(user.role),
        mustChangePassword: Boolean(user.must_change_password)
      };
      req.session.save((saveError) => saveError ? reject(saveError) : resolve());
    });
  });
}

function isApiRequest(req) {
  return req.path.startsWith("/api/");
}

function renderForbiddenPage(req, res, message = "You do not have permission to view this page.") {
  if (isApiRequest(req)) {
    return res.status(403).json({ ok: false, message: "Forbidden." });
  }
  return res.status(403).render("forbidden", {
    message,
    homePath: getRoleHomePath(getSessionUser(req)?.role)
  });
}
app.use((req, res, next) => {
  res.locals.currentPath = req.path;
  res.locals.requestBaseUrl = `${req.protocol}://${req.get("host")}`;
  const user = getSessionUser(req);
  res.locals.currentUser = user;
  res.locals.currentRole = user?.role || null;
  res.locals.serializeForScript = serializeForScript;
  next();
});
app.use((req, res, next) => {
  const isMutation = ["POST", "PUT", "PATCH", "DELETE"].includes(req.method);
  const excluded = [
    "/login",
    "/api/auto-scan/heartbeat",
    "/api/scanner-metrics",
    "/api/scanner-metrics/batch",
    "/api/notifications/read-all"
  ];
  if (!isMutation || excluded.includes(req.path) || req.path.startsWith("/account/")) return next();
  res.once("finish", () => {
    const actor = getSessionUser(req);
    if (!actor) return;
    const eventType = `MUTATION_${req.path.replace(/\d+/g, ":id").replace(/[^a-z0-9]+/gi, "_").replace(/^_|_$/g, "").toUpperCase()}`.slice(0, 80);
    recordSecurityAudit(req, eventType, {
      actor,
      outcome: res.statusCode < 400 ? "success" : "failed",
      metadata: { method: req.method, status: res.statusCode }
    });
  });
  return next();
});
app.use("/verify", (_req, res, next) => {
  res.setHeader("Cache-Control", "private, no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
  next();
});
app.use((req, res, next) => {
  const user = getSessionUser(req);
  if (!user) return next();
  const accountPath = req.path === "/account/security"
    || req.path.startsWith("/account/password")
    || req.path === "/logout";

  if (user.mustChangePassword && !accountPath) {
    if (isApiRequest(req)) {
      return res.status(403).json({ ok: false, message: "Change your temporary password before continuing." });
    }
    return res.redirect("/account/security?password_required=1#password");
  }
  return next();
});

// Auth middleware for all protected routes
function requireAuth(req, res, next) {
  const user = getSessionUser(req);
  if (user) {
    req.authUser = user;
    return next();
  }
  if (isApiRequest(req)) {
    return res.status(401).json({ ok: false, message: "Unauthorized. Please log in again." });
  }
  res.redirect("/login");
}

function requireRole(...roles) {
  const allowedRoles = roles
    .map((role) => normalizeRole(role))
    .filter(Boolean);

  return (req, res, next) => {
    const user = getSessionUser(req);
    if (!user) {
      if (isApiRequest(req)) {
        return res.status(401).json({ ok: false, message: "Unauthorized. Please log in again." });
      }
      return res.redirect("/login");
    }

    if (allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
      return renderForbiddenPage(req, res);
    }

    req.authUser = user;
    return next();
  };
}

// Login routes
app.get("/login", (req, res) => {
  const user = getSessionUser(req);
  if (user) {
    return res.redirect(getRoleHomePath(user.role));
  }
  res.render("login", { error: null, usernameVal: "" });
});

app.post("/login", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const rateKey = getRateLimitKey(req, username || "blank");
  const accountRateKey = hashIdentifier(String(username || "blank").toLowerCase(), SESSION_SECRET);
  const rateState = loginRateLimiter.check(rateKey);
  const accountRateState = loginAccountRateLimiter.check(accountRateKey);

  if (!rateState.allowed || !accountRateState.allowed) {
    const retryAfterSeconds = Math.max(rateState.retryAfterSeconds, accountRateState.retryAfterSeconds);
    res.setHeader("Retry-After", String(retryAfterSeconds));
    await recordSecurityAudit(req, "LOGIN_RATE_LIMITED", { actorUsername: username, outcome: "blocked" });
    return res.status(429).render("login", {
      error: `Too many sign-in attempts. Try again in ${Math.ceil(retryAfterSeconds / 60)} minute(s).`,
      usernameVal: username
    });
  }

  if (!username || !password) {
    loginRateLimiter.recordFailure(rateKey);
    loginAccountRateLimiter.recordFailure(accountRateKey);
    return res.render("login", { error: "Please enter your username and password.", usernameVal: username });
  }

  try {
    const [rows] = await pool.query(
      `SELECT id, username, password, role,
              is_active, must_change_password
       FROM users
       WHERE username = ?
       LIMIT 1`,
      [username]
    );

    if (!rows.length) {
      loginRateLimiter.recordFailure(rateKey);
      loginAccountRateLimiter.recordFailure(accountRateKey);
      await recordSecurityAudit(req, "LOGIN_FAILED", { actorUsername: username, outcome: "failed" });
      return res.render("login", { error: "Invalid username or password.", usernameVal: username });
    }

    const user = rows[0];
    const role = normalizeRole(user.role);
    if (!role) {
      return res.render("login", {
        error: "Your account role is invalid. Please contact an administrator.",
        usernameVal: username
      });
    }

    const passwordHash = String(user.password || "");
    const passwordMatched = passwordHash.startsWith("$2")
      ? await bcrypt.compare(password, passwordHash)
      : password === passwordHash;

    if (!passwordMatched) {
      loginRateLimiter.recordFailure(rateKey);
      loginAccountRateLimiter.recordFailure(accountRateKey);
      await recordSecurityAudit(req, "LOGIN_FAILED", {
        actor: { id: user.id, username: user.username, role },
        outcome: "failed"
      });
      return res.render("login", { error: "Invalid username or password.", usernameVal: username });
    }

    if (!user.is_active) {
      await recordSecurityAudit(req, "LOGIN_DISABLED_ACCOUNT", {
        actor: { id: user.id, username: user.username, role },
        outcome: "blocked"
      });
      return res.render("login", {
        error: "This account is suspended. Contact an administrator.",
        usernameVal: username
      });
    }

    loginRateLimiter.reset(rateKey);
    loginAccountRateLimiter.reset(accountRateKey);
    await regenerateAuthenticatedSession(req, user);
    await pool.query("UPDATE users SET last_login_at = NOW() WHERE id = ?", [user.id]);
    await recordSecurityAudit(req, "LOGIN_SUCCEEDED", { actor: user });
    return res.redirect(getRoleHomePath(role));
  } catch (error) {
    console.error("Login error:", error);
    return res.render("login", { error: "Unable to sign in right now. Please try again.", usernameVal: username });
  }
});

// Send old verification pages back through password sign-in.
app.get("/login/2fa", (_req, res) => res.redirect("/login"));
app.post("/login/2fa", (_req, res) => res.redirect("/login"));

app.get("/logout", async (req, res) => {
  await recordSecurityAudit(req, "LOGOUT");
  const sessionId = req.sessionID;
  req.session.destroy(() => {
    closeUserEventStreams(client => client.sessionId === sessionId);
    res.redirect("/login");
  });
});

function createStickerCode() {
  const year = new Date().getFullYear();
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();
  return `NAAP-${year}-${random}`;
}

function createVisitorPassCode() {
  const year = new Date().getFullYear();
  const random = crypto.randomBytes(2).toString("hex").toUpperCase();
  return `VIS-${year}-${random}`;
}

function createQrToken() {
  return crypto.randomBytes(24).toString("hex");
}

async function getStickerEmailDetails(stickerId, db = pool) {
  const [rows] = await db.query(
    `SELECT st.id, st.sticker_code, st.qr_token, st.status, st.expires_at,
            v.plate_number, s.id AS student_id, s.student_number, s.full_name, s.email
     FROM stickers st
     JOIN vehicles v ON v.id = st.vehicle_id
     JOIN students s ON s.id = v.student_id
     WHERE st.id = ?
     LIMIT 1`,
    [stickerId]
  );
  return rows[0] || null;
}

function isStickerEmailEligible(sticker) {
  if (!sticker || sticker.status !== "active") return false;
  return !isExpired(sticker.expires_at);
}

async function recordBackgroundAudit(eventType, options = {}) {
  try {
    await pool.query(
      `INSERT INTO security_audit_logs (
         event_type, actor_user_id, actor_username, actor_role,
         target_type, target_id, outcome, metadata_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        String(eventType).slice(0, 80),
        Number(options.actorUserId) || null,
        options.actorUsername || "background-worker",
        options.actorRole || "system",
        options.targetType || null,
        options.targetId ? String(options.targetId).slice(0, 120) : null,
        options.outcome || "success",
        JSON.stringify(options.metadata || {})
      ]
    );
  } catch (error) {
    console.warn("Background audit warning (non-fatal):", error.message);
  }
}

async function processEmailDeliveryJobs() {
  if (emailWorkerRunning) return;
  emailWorkerRunning = true;
  try {
    await pool.query(
      `UPDATE email_delivery_jobs
       SET status = 'queued', last_error = 'Recovered after interrupted delivery.'
       WHERE status = 'sending' AND updated_at < NOW() - INTERVAL 10 MINUTE`
    );
    const [jobs] = await pool.query(
      `SELECT id, sticker_id, recipient, attempts, max_attempts, requested_by_user_id
       FROM email_delivery_jobs
       WHERE status IN ('queued', 'retrying')
         AND attempts < max_attempts
         AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
       ORDER BY created_at ASC
       LIMIT 5`
    );

    for (const job of jobs) {
      const [claim] = await pool.query(
        `UPDATE email_delivery_jobs
         SET status = 'sending', attempts = attempts + 1
         WHERE id = ? AND status IN ('queued', 'retrying')`,
        [job.id]
      );
      if (!claim.affectedRows) continue;
      const attemptNumber = Number(job.attempts || 0) + 1;
      try {
        const sticker = await getStickerEmailDetails(job.sticker_id);
        if (!isStickerEmailEligible(sticker)) throw new Error("Sticker is no longer active or has expired.");
        const currentRecipient = normalizeEmailAddress(sticker.email);
        if (!currentRecipient || currentRecipient !== normalizeEmailAddress(job.recipient)) {
          throw new Error("Student email changed or is no longer valid. Queue a new delivery.");
        }
        const verifyUrl = `${APP_BASE_URL.replace(/\/+$/, "")}/verify/${sticker.qr_token}`;
        const qrPng = await generateBrandedQrPng(verifyUrl);
        const result = await sendStudentQrEmail({
          to: currentRecipient,
          studentName: sticker.full_name,
          studentNumber: sticker.student_number,
          stickerCode: sticker.sticker_code,
          plateNumber: sticker.plate_number,
          verifyUrl,
          qrPng
        });
        const messageId = String(result?.messageId || "").slice(0, 255) || null;
        const [sentUpdate] = await pool.query(
          `UPDATE email_delivery_jobs
           SET status = 'sent', sent_at = NOW(), next_attempt_at = NULL,
               last_error = NULL, message_id = ?
           WHERE id = ? AND status = 'sending'`,
          [messageId, job.id]
        );
        if (!sentUpdate.affectedRows) continue;
        await pool.query(
          `INSERT INTO email_delivery_attempts
             (job_id, attempt_number, outcome, provider_message_id)
           VALUES (?, ?, 'sent', ?)`,
          [job.id, attemptNumber, messageId]
        );
        await recordBackgroundAudit("STICKER_QR_EMAILED", {
          actorUserId: job.requested_by_user_id,
          targetType: "sticker",
          targetId: sticker.id,
          metadata: { job_id: job.id, student_id: sticker.student_id }
        });
      } catch (error) {
        const cleanError = String(error?.message || "Email delivery failed.").replace(/[\r\n]+/g, " ").slice(0, 500);
        const terminal = attemptNumber >= Number(job.max_attempts || 3)
          || error instanceof MailConfigurationError
          || error?.code === "MAIL_NOT_CONFIGURED";
        const retryMinutes = Math.min(30, 2 ** attemptNumber);
        const nextAttemptAt = terminal ? null : new Date(Date.now() + retryMinutes * 60 * 1000);
        const [failedUpdate] = await pool.query(
          `UPDATE email_delivery_jobs
           SET status = ?, last_error = ?, next_attempt_at = ?
           WHERE id = ? AND status = 'sending'`,
          [terminal ? "failed" : "retrying", cleanError, nextAttemptAt, job.id]
        );
        if (!failedUpdate.affectedRows) continue;
        await pool.query(
          `INSERT INTO email_delivery_attempts
             (job_id, attempt_number, outcome, error_message)
           VALUES (?, ?, 'failed', ?)`,
          [job.id, attemptNumber, cleanError]
        );
        await recordBackgroundAudit("STICKER_QR_EMAIL_FAILED", {
          actorUserId: job.requested_by_user_id,
          targetType: "sticker",
          targetId: job.sticker_id,
          outcome: "failed",
          metadata: { job_id: job.id, attempt: attemptNumber, terminal }
        });
      }
    }
  } catch (error) {
    console.error("Email delivery worker error:", error.message);
  } finally {
    emailWorkerRunning = false;
  }
}

function normalizeVisitorType(rawType) {
  const type = String(rawType || "").trim().toLowerCase();
  return VALID_VISITOR_TYPES.has(type) ? type : VISITOR_TYPES.VISITOR;
}

function isVisitorZone(zoneValue) {
  const zone = String(zoneValue || "").trim();
  return /^visitor/i.test(zone) || /^v[-\s]?/i.test(zone);
}

function parseDateTimeInput(rawValue) {
  const value = String(rawValue || "").trim();
  if (!value) return null;
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return null;
  return dt;
}

function isExpired(expiresAt) {
  if (!expiresAt) return false;
  const expirationDate = normalizeDateOnlyInput(expiresAt);
  const today = toDateOnly(new Date());
  if (expirationDate && today) return expirationDate < today;
  return new Date(expiresAt).getTime() < Date.now();
}

function toDateOnly(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  const yyyy = date.getFullYear();
  const mm = String(date.getMonth() + 1).padStart(2, "0");
  const dd = String(date.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
}

function normalizeDateOnlyInput(value) {
  const text = String(value || "").trim();
  if (!text) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) return text;
  return toDateOnly(text);
}

function isSchemaCompatibilityError(error) {
  if (!error || typeof error !== "object") return false;
  const code = String(error.code || "");
  return code === "ER_BAD_FIELD_ERROR" || code === "ER_NO_SUCH_TABLE" || code === "ER_BAD_TABLE_ERROR";
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

function normalizeBehaviorRiskPayload(body = {}) {
  const rawLevel = String(body.behavior_risk_level || "").trim().toLowerCase();
  const riskLevel = rawLevel === "high" || rawLevel === "medium" || rawLevel === "low"
    ? rawLevel
    : "low";
  const riskScore = Math.max(0, Math.min(1, Number(body.behavior_risk_score) || 0));
  const riskReasons = Array.isArray(body.behavior_risk_reasons)
    ? body.behavior_risk_reasons
      .map((item) => String(item || "").trim())
      .filter(Boolean)
      .slice(0, 3)
    : [];
  const detectionConfidence = Math.max(0, Math.min(1, Number(body.detection_confidence) || 0));
  const detectionModel = String(body.detection_model || "").trim() || null;
  return {
    risk_level: riskLevel,
    risk_score: Math.round(riskScore * 1000) / 1000,
    risk_reasons: riskReasons,
    detection_confidence: Math.round(detectionConfidence * 1000) / 1000,
    detection_model: detectionModel
  };
}

function buildRiskSummaryNote(riskPayload) {
  if (!riskPayload || !riskPayload.risk_level) return "";
  const level = String(riskPayload.risk_level || "low").toUpperCase();
  const score = Math.round((Number(riskPayload.risk_score) || 0) * 100);
  const reason = Array.isArray(riskPayload.risk_reasons) && riskPayload.risk_reasons.length
    ? `; ${riskPayload.risk_reasons[0]}`
    : "";
  return `[BehaviorRisk ${level} ${score}%${reason}]`;
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

function normalizeAutoScanDeviceId(rawDeviceId) {
  const cleaned = String(rawDeviceId || "")
    .trim()
    .replace(/[^a-zA-Z0-9._:-]/g, "");
  if (!cleaned) return "phone-camera-default";
  return cleaned.slice(0, 120);
}

function normalizeGateId(rawGateId) {
  const gateId = String(rawGateId || "").trim();
  if (!gateId) return "Main Gate";
  return gateId.slice(0, 80);
}

function toIsoStringOrNull(value) {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function mapAutoScanHealthRow(row) {
  if (!row) return null;
  const heartbeatAgeSeconds = Number.isFinite(Number(row.heartbeat_age_seconds))
    ? Math.max(0, Number(row.heartbeat_age_seconds))
    : null;
  const scanAgeSeconds = Number.isFinite(Number(row.scan_age_seconds))
    ? Math.max(0, Number(row.scan_age_seconds))
    : null;

  return {
    device_id: row.device_id || null,
    gate_id: row.gate_id || null,
    last_seen_user: row.last_seen_user || null,
    last_heartbeat_at: toIsoStringOrNull(row.last_heartbeat_at),
    last_scan_received_at: toIsoStringOrNull(row.last_scan_received_at),
    updated_at: toIsoStringOrNull(row.updated_at),
    heartbeat_age_seconds: heartbeatAgeSeconds,
    scan_age_seconds: scanAgeSeconds,
    is_online: heartbeatAgeSeconds != null && heartbeatAgeSeconds <= AUTO_SCAN_ONLINE_WINDOW_SECONDS
  };
}

async function upsertAutoScanHeartbeat(
  {
    deviceId,
    gateId,
    actorName,
    markScanReceived = false
  } = {},
  db = pool
) {
  const safeDeviceId = normalizeAutoScanDeviceId(deviceId);
  const safeGateId = normalizeGateId(gateId);
  const safeActorName = String(actorName || "").trim().slice(0, 120) || null;

  await db.query(
    `INSERT INTO auto_scan_heartbeats (
       device_id,
       gate_id,
       last_heartbeat_at,
       last_scan_received_at,
       last_seen_user
     ) VALUES (?, ?, UTC_TIMESTAMP(), ${markScanReceived ? "UTC_TIMESTAMP()" : "NULL"}, ?)
     ON DUPLICATE KEY UPDATE
       gate_id = VALUES(gate_id),
       last_heartbeat_at = UTC_TIMESTAMP(),
       last_scan_received_at = ${markScanReceived ? "UTC_TIMESTAMP()" : "last_scan_received_at"},
       last_seen_user = VALUES(last_seen_user),
       updated_at = UTC_TIMESTAMP()`,
    [safeDeviceId, safeGateId, safeActorName]
  );

  const [rows] = await db.query(
    `SELECT
       device_id,
       gate_id,
       last_seen_user,
       last_heartbeat_at,
       last_scan_received_at,
       updated_at,
       TIMESTAMPDIFF(SECOND, last_heartbeat_at, UTC_TIMESTAMP()) AS heartbeat_age_seconds,
       CASE
         WHEN last_scan_received_at IS NULL THEN NULL
         ELSE TIMESTAMPDIFF(SECOND, last_scan_received_at, UTC_TIMESTAMP())
       END AS scan_age_seconds
     FROM auto_scan_heartbeats
     WHERE device_id = ?
     LIMIT 1`,
    [safeDeviceId]
  );
  return rows.length ? mapAutoScanHealthRow(rows[0]) : null;
}

async function listAutoScanHealthRows(limit = 12, db = pool) {
  const safeLimit = Math.max(1, Math.min(20, Number(limit) || 12));
  const [rows] = await db.query(
    `SELECT
       device_id,
       gate_id,
       last_seen_user,
       last_heartbeat_at,
       last_scan_received_at,
       updated_at,
       TIMESTAMPDIFF(SECOND, last_heartbeat_at, UTC_TIMESTAMP()) AS heartbeat_age_seconds,
       CASE
         WHEN last_scan_received_at IS NULL THEN NULL
         ELSE TIMESTAMPDIFF(SECOND, last_scan_received_at, UTC_TIMESTAMP())
       END AS scan_age_seconds
     FROM auto_scan_heartbeats
     ORDER BY last_heartbeat_at DESC
     LIMIT ?`,
    [safeLimit]
  );
  return rows.map((row) => mapAutoScanHealthRow(row));
}

async function getAutoScanHealthSnapshot(limit = 12, db = pool) {
  const rows = await listAutoScanHealthRows(limit, db);
  const primary = rows.length > 0 ? rows[0] : null;
  const onlineDevices = rows.filter((row) => row.is_online).length;
  return {
    rows,
    primary,
    total_devices: rows.length,
    online_devices: onlineDevices,
    offline_devices: Math.max(0, rows.length - onlineDevices),
    online_window_seconds: AUTO_SCAN_ONLINE_WINDOW_SECONDS,
    heartbeat_interval_seconds: AUTO_SCAN_HEARTBEAT_INTERVAL_SECONDS,
    server_time: new Date().toISOString()
  };
}

function closeUserEventStreams(matches) {
  for (const clients of [autoScanSseClients, notificationSseClients]) {
    for (const client of clients.values()) if (matches(client)) client.close();
  }
}

function broadcastAutoScanSse(eventName, payload = {}) {
  for (const client of autoScanSseClients.values()) client.send(eventName, payload);
}

function broadcastNotificationSse(eventName, payload = {}) {
  for (const client of notificationSseClients.values()) client.send(eventName, payload);
}

function broadcastNotificationsUpdated(reason = "updated", payload = {}) {
  broadcastNotificationSse("notifications-updated", {
    reason,
    server_time: new Date().toISOString(),
    ...payload
  });
}

function broadcastExpiredPendingEntries(expiredPendingIds) {
  if (!Array.isArray(expiredPendingIds) || expiredPendingIds.length === 0) return;
  broadcastNotificationsUpdated("pending-entry-expired", {
    expired_pending_ids: expiredPendingIds
  });
}

async function broadcastAutoScanHealth(reason = "heartbeat") {
  if (!autoScanSseClients.size) return;
  try {
    const snapshot = await getAutoScanHealthSnapshot(5);
    broadcastAutoScanSse("queue-health", {
      ...snapshot,
      reason
    });
  } catch (error) {
    console.warn("SSE queue-health broadcast warning:", error.message);
  }
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

async function reportDuplicateScan({ qrValue, gate, source, actorName, deniedReason }) {
  await evaluateSuspiciousScanSignals(pool, {
    qrValue,
    gate,
    source,
    actorName,
    result: "VALID",
    duplicateScan: true,
    deniedReason
  });
  broadcastNotificationsUpdated("duplicate-scan-blocked", {
    gate_id: gate,
    qr_value: qrValue
  });
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

function normalizeAlertSeverity(value) {
  const normalized = String(value || ALERT_SEVERITIES.LOW).trim().toLowerCase();
  if (Object.values(ALERT_SEVERITIES).includes(normalized)) return normalized;
  return ALERT_SEVERITIES.LOW;
}

function normalizeAlertAudienceRole(value) {
  const normalized = String(value || "staff").trim().toLowerCase();
  if (["admin", "guard", "student", "staff", "all"].includes(normalized)) return normalized;
  return "staff";
}

function normalizeAlertStatus(value) {
  const normalized = String(value || ALERT_STATUS.ACTIVE).trim().toLowerCase();
  if (Object.values(ALERT_STATUS).includes(normalized)) return normalized;
  return ALERT_STATUS.ACTIVE;
}

function getAlertAudienceRolesForViewer(role) {
  const safeRole = normalizeRole(role);
  if (safeRole === USER_ROLES.ADMIN) {
    return ["all", "staff", "admin", "guard", "student"];
  }
  if (safeRole === USER_ROLES.GUARD) {
    return ["all", "staff", "guard"];
  }
  return ["all", "student"];
}

function safeJsonStringify(value) {
  try {
    return JSON.stringify(value == null ? null : value);
  } catch (_error) {
    return JSON.stringify({ note: "metadata-serialization-failed" });
  }
}

function mapAlertRow(row) {
  if (!row) return null;
  let metadata = null;
  if (row.metadata_json) {
    try {
      metadata = typeof row.metadata_json === "string" ? JSON.parse(row.metadata_json) : row.metadata_json;
    } catch (_error) {
      metadata = null;
    }
  }

  return {
    id: row.id,
    type: row.type,
    title: row.title,
    message: row.message,
    severity: row.severity,
    audience_role: row.audience_role,
    related_user_id: row.related_user_id,
    related_vehicle_id: row.related_vehicle_id,
    related_visitor_pass_id: row.related_visitor_pass_id || null,
    related_qr_id: row.related_qr_id,
    related_zone_id: row.related_zone_id,
    related_gate_id: row.related_gate_id,
    related_scan_log_id: row.related_scan_log_id,
    related_pending_entry_id: row.related_pending_entry_id,
    source: row.source,
    status: row.status,
    is_read: Boolean(Number(row.user_is_read || 0)),
    dedupe_key: row.dedupe_key || null,
    metadata,
    created_at: row.created_at,
    updated_at: row.updated_at,
    resolved_at: row.resolved_at,
    resolved_by: row.resolved_by
  };
}

async function createOrRefreshAlertWithDb(db, payload = {}) {
  const type = String(payload.type || "").trim().slice(0, 80);
  const title = String(payload.title || "").trim().slice(0, 180);
  const message = String(payload.message || "").trim();
  if (!type || !title || !message) {
    throw new Error("Alert payload is missing type, title, or message.");
  }

  const severity = normalizeAlertSeverity(payload.severity);
  const audienceRole = normalizeAlertAudienceRole(payload.audienceRole || "staff");
  const status = normalizeAlertStatus(payload.status || ALERT_STATUS.ACTIVE);
  const dedupeKey = payload.dedupeKey ? String(payload.dedupeKey).trim().slice(0, 190) : null;
  const metadataJson = payload.metadata === undefined ? null : safeJsonStringify(payload.metadata);
  const relatedUserId = Number(payload.relatedUserId) || null;
  const relatedVehicleId = Number(payload.relatedVehicleId) || null;
  const relatedVisitorPassId = Number(payload.relatedVisitorPassId) || null;
  const relatedScanLogId = Number(payload.relatedScanLogId) || null;
  const relatedPendingEntryId = Number(payload.relatedPendingEntryId) || null;
  const relatedQrId = payload.relatedQrId ? String(payload.relatedQrId).slice(0, 120) : null;
  const relatedZoneId = payload.relatedZoneId ? String(payload.relatedZoneId).slice(0, 80) : null;
  const relatedGateId = payload.relatedGateId ? String(payload.relatedGateId).slice(0, 80) : null;
  const source = payload.source ? String(payload.source).slice(0, 80) : null;
  const resolvedBy = payload.resolvedBy ? String(payload.resolvedBy).slice(0, 120) : null;

  if (dedupeKey) {
    const [existingRows] = await db.query(
      `SELECT id
       FROM alerts
       WHERE dedupe_key = ?
         AND status = 'active'
       ORDER BY id DESC
       LIMIT 1
       FOR UPDATE`,
      [dedupeKey]
    );

    if (existingRows.length > 0) {
      const existingId = existingRows[0].id;
      await db.query(
        `UPDATE alerts
         SET
           type = ?,
           title = ?,
           message = ?,
           severity = ?,
           audience_role = ?,
           related_user_id = ?,
           related_vehicle_id = ?,
           related_visitor_pass_id = ?,
           related_qr_id = ?,
           related_zone_id = ?,
           related_gate_id = ?,
           related_scan_log_id = ?,
           related_pending_entry_id = ?,
           source = ?,
           status = ?,
           is_read = 0,
           metadata_json = ?,
           resolved_at = CASE WHEN ? = 'resolved' THEN NOW() ELSE NULL END,
           resolved_by = CASE WHEN ? = 'resolved' THEN ? ELSE NULL END
         WHERE id = ?`,
        [
          type,
          title,
          message,
          severity,
          audienceRole,
          relatedUserId,
          relatedVehicleId,
          relatedVisitorPassId,
          relatedQrId,
          relatedZoneId,
          relatedGateId,
          relatedScanLogId,
          relatedPendingEntryId,
          source,
          status,
          metadataJson,
          status,
          status,
          resolvedBy,
          existingId
        ]
      );
      const [rows] = await db.query("SELECT * FROM alerts WHERE id = ? LIMIT 1", [existingId]);
      return rows.length > 0 ? rows[0] : null;
    }
  }

  const [insertResult] = await db.query(
    `INSERT INTO alerts (
       type,
       title,
       message,
       severity,
       audience_role,
       related_user_id,
       related_vehicle_id,
       related_visitor_pass_id,
       related_qr_id,
       related_zone_id,
       related_gate_id,
       related_scan_log_id,
       related_pending_entry_id,
       source,
       status,
       is_read,
       dedupe_key,
       metadata_json,
       resolved_at,
       resolved_by
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
    [
      type,
      title,
      message,
      severity,
      audienceRole,
      relatedUserId,
      relatedVehicleId,
      relatedVisitorPassId,
      relatedQrId,
      relatedZoneId,
      relatedGateId,
      relatedScanLogId,
      relatedPendingEntryId,
      source,
      status,
      dedupeKey,
      metadataJson,
      status === ALERT_STATUS.RESOLVED ? new Date() : null,
      status === ALERT_STATUS.RESOLVED ? resolvedBy : null
    ]
  );

  const [rows] = await db.query("SELECT * FROM alerts WHERE id = ? LIMIT 1", [insertResult.insertId]);
  return rows.length > 0 ? rows[0] : null;
}

async function resolveAlertsByDedupeKey(db, dedupeKey, resolvedBy = "system") {
  if (!dedupeKey) return 0;
  const [result] = await db.query(
    `UPDATE alerts
     SET
       status = 'resolved',
       resolved_at = COALESCE(resolved_at, NOW()),
       resolved_by = COALESCE(resolved_by, ?)
     WHERE dedupe_key = ?
       AND status = 'active'`,
    [resolvedBy, dedupeKey]
  );
  return Number(result?.affectedRows || 0);
}

async function resolvePendingEntryAlert(db, pendingEntryId, resolvedBy = "system") {
  if (!Number.isInteger(Number(pendingEntryId)) || Number(pendingEntryId) <= 0) return 0;
  const [result] = await db.query(
    `UPDATE alerts
     SET
       status = 'resolved',
       resolved_at = COALESCE(resolved_at, NOW()),
       resolved_by = COALESCE(resolved_by, ?)
     WHERE related_pending_entry_id = ?
       AND type = ?
       AND status = 'active'`,
    [resolvedBy, Number(pendingEntryId), ALERT_TYPES.PENDING_ENTRY_APPROVAL]
  );
  return Number(result?.affectedRows || 0);
}

async function markAlertReadForUser(db, alertId, userId) {
  const safeAlertId = Number(alertId);
  const safeUserId = Number(userId);
  if (!Number.isInteger(safeAlertId) || safeAlertId <= 0) return false;
  if (!Number.isInteger(safeUserId) || safeUserId <= 0) return false;

  await db.query(
    `INSERT INTO alert_reads (alert_id, user_id, read_at)
     VALUES (?, ?, NOW())
     ON DUPLICATE KEY UPDATE read_at = VALUES(read_at)`,
    [safeAlertId, safeUserId]
  );
  return true;
}

async function markAllAlertsReadForUser(db, user) {
  const safeUserId = Number(user?.id) || 0;
  if (!Number.isInteger(safeUserId) || safeUserId <= 0) return 0;
  const audienceRoles = getAlertAudienceRolesForViewer(user?.role);
  if (!audienceRoles.length) return 0;

  const placeholders = audienceRoles.map(() => "?").join(", ");
  const [result] = await db.query(
    `INSERT INTO alert_reads (alert_id, user_id, read_at)
     SELECT a.id, ?, NOW()
     FROM alerts a
     LEFT JOIN alert_reads ar
       ON ar.alert_id = a.id
      AND ar.user_id = ?
     WHERE a.audience_role IN (${placeholders})
       AND ar.alert_id IS NULL
     ON DUPLICATE KEY UPDATE read_at = VALUES(read_at)`,
    [safeUserId, safeUserId, ...audienceRoles]
  );
  return Number(result?.affectedRows || 0);
}

function buildNotificationFilterParams(filters = {}) {
  const sanitized = {
    status: String(filters.status || "all").toLowerCase(),
    type: String(filters.type || "all").toUpperCase(),
    severity: String(filters.severity || "all").toLowerCase(),
    readState: String(filters.readState || "all").toLowerCase(),
    query: String(filters.query || "").trim(),
    from: toDateOnly(filters.from),
    to: toDateOnly(filters.to),
    limit: Math.max(1, Math.min(200, Number(filters.limit) || 25)),
    offset: Math.max(0, Number(filters.offset) || 0)
  };

  if (!["all", "active", "resolved"].includes(sanitized.status)) {
    sanitized.status = "all";
  }
  if (sanitized.type === "ALL") sanitized.type = "all";
  if (!["all", "low", "medium", "high", "critical"].includes(sanitized.severity)) {
    sanitized.severity = "all";
  }
  if (!["all", "read", "unread"].includes(sanitized.readState)) {
    sanitized.readState = "all";
  }
  return sanitized;
}

async function listAlertsForUser(user, filters = {}, db = pool) {
  const safeUserId = Number(user?.id) || 0;
  const audienceRoles = getAlertAudienceRolesForViewer(user?.role);
  const safeFilters = buildNotificationFilterParams(filters);
  const where = [];
  const params = [safeUserId, ...audienceRoles];
  where.push(`a.audience_role IN (${audienceRoles.map(() => "?").join(", ")})`);

  if (safeFilters.status !== "all") {
    where.push("a.status = ?");
    params.push(safeFilters.status);
  }
  if (safeFilters.type !== "all") {
    where.push("a.type = ?");
    params.push(safeFilters.type);
  }
  if (safeFilters.severity !== "all") {
    where.push("a.severity = ?");
    params.push(safeFilters.severity);
  }
  if (safeFilters.readState === "read") {
    where.push("ar.alert_id IS NOT NULL");
  } else if (safeFilters.readState === "unread") {
    where.push("ar.alert_id IS NULL");
  }
  if (safeFilters.from) {
    where.push("DATE(a.created_at) >= ?");
    params.push(safeFilters.from);
  }
  if (safeFilters.to) {
    where.push("DATE(a.created_at) <= ?");
    params.push(safeFilters.to);
  }
  if (safeFilters.query) {
    where.push("(a.title LIKE ? OR a.message LIKE ? OR a.related_qr_id LIKE ? OR a.related_zone_id LIKE ? OR a.related_gate_id LIKE ?)");
    const like = `%${safeFilters.query}%`;
    params.push(like, like, like, like, like);
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const baseFromSql = `
    FROM alerts a
    LEFT JOIN alert_reads ar
      ON ar.alert_id = a.id
     AND ar.user_id = ?
    ${whereSql}
  `;

  const [rows] = await db.query(
    `SELECT
       a.*,
       CASE WHEN ar.alert_id IS NULL THEN 0 ELSE 1 END AS user_is_read
     ${baseFromSql}
     ORDER BY a.status ASC, a.created_at DESC
     LIMIT ?
     OFFSET ?`,
    [...params, safeFilters.limit, safeFilters.offset]
  );

  const [[totalRow]] = await db.query(
    `SELECT COUNT(*) AS total ${baseFromSql}`,
    params
  );

  return {
    rows: rows.map(mapAlertRow),
    total: Number(totalRow?.total || 0),
    limit: safeFilters.limit,
    offset: safeFilters.offset,
    filters: safeFilters
  };
}

async function getNotificationSummaryForUser(user, db = pool) {
  const safeUserId = Number(user?.id) || 0;
  const audienceRoles = getAlertAudienceRolesForViewer(user?.role);
  const placeholders = audienceRoles.map(() => "?").join(", ");

  const [[row]] = await db.query(
    `SELECT
       COUNT(*) AS total,
       SUM(CASE WHEN a.status = 'active' THEN 1 ELSE 0 END) AS active_total,
       SUM(CASE WHEN ar.alert_id IS NULL THEN 1 ELSE 0 END) AS unread_total,
       SUM(CASE WHEN a.status = 'active' AND a.type = ? THEN 1 ELSE 0 END) AS invalid_active,
       SUM(CASE WHEN a.status = 'active' AND a.type = ? THEN 1 ELSE 0 END) AS full_zone_active,
       SUM(CASE WHEN a.status = 'active' AND a.type = ? THEN 1 ELSE 0 END) AS low_slot_active,
       SUM(CASE WHEN a.status = 'active' AND a.type = ? THEN 1 ELSE 0 END) AS pending_active,
       SUM(CASE WHEN a.status = 'active' AND a.type = ? THEN 1 ELSE 0 END) AS suspicious_active
     FROM alerts a
     LEFT JOIN alert_reads ar
       ON ar.alert_id = a.id
      AND ar.user_id = ?
     WHERE a.audience_role IN (${placeholders})`,
    [
      ALERT_TYPES.INVALID_QR_ATTEMPT,
      ALERT_TYPES.FULL_PARKING_ZONE,
      ALERT_TYPES.LOW_SLOT_WARNING,
      ALERT_TYPES.PENDING_ENTRY_APPROVAL,
      ALERT_TYPES.SUSPICIOUS_SCAN_BEHAVIOR,
      safeUserId,
      ...audienceRoles
    ]
  );

  return {
    total: Number(row?.total || 0),
    active_total: Number(row?.active_total || 0),
    unread_total: Number(row?.unread_total || 0),
    invalid_active: Number(row?.invalid_active || 0),
    full_zone_active: Number(row?.full_zone_active || 0),
    low_slot_active: Number(row?.low_slot_active || 0),
    pending_active: Number(row?.pending_active || 0),
    suspicious_active: Number(row?.suspicious_active || 0)
  };
}

async function getOperationalAlertMetrics(db = pool) {
  const [totalsResult, alertCountsResult] = await Promise.all([
    db.query(
      `SELECT
         (SELECT COUNT(*)
          FROM scan_logs
          WHERE result IN ('INVALID', 'REVOKED', 'EXPIRED')
            AND scanned_at >= (DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR) - INTERVAL 8 HOUR)
            AND scanned_at < (DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR) - INTERVAL 8 HOUR) + INTERVAL 1 DAY) AS invalid_today,
         (SELECT COUNT(*)
          FROM visitor_scan_logs
          WHERE result IN ('INVALID', 'REVOKED', 'EXPIRED', 'DENIED')
            AND scanned_at >= (DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR) - INTERVAL 8 HOUR)
            AND scanned_at < (DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR) - INTERVAL 8 HOUR) + INTERVAL 1 DAY) AS visitor_invalid_today,
         (SELECT COUNT(*)
          FROM auto_scan_queue
          WHERE status = 'PENDING') AS pending_queue,
         (SELECT COUNT(*)
          FROM visitor_passes
          WHERE approval_status = 'PENDING'
            AND pass_state <> 'EXPIRED') AS visitor_pending`
    ),
    db.query(
      `SELECT type, COUNT(*) AS total
       FROM alerts
       WHERE status = 'active'
         AND type IN (?, ?, ?, ?)
       GROUP BY type`,
      [
        ALERT_TYPES.FULL_PARKING_ZONE,
        ALERT_TYPES.LOW_SLOT_WARNING,
        ALERT_TYPES.SUSPICIOUS_SCAN_BEHAVIOR,
        ALERT_TYPES.VISITOR_OVERSTAY
      ]
    )
  ]);

  const totalsRow = totalsResult[0][0] || {};
  const alertCountByType = new Map(
    alertCountsResult[0].map((row) => [String(row.type), Number(row.total || 0)])
  );

  return {
    invalid_qr_today: Number(totalsRow.invalid_today || 0) + Number(totalsRow.visitor_invalid_today || 0),
    pending_approvals: Number(totalsRow.pending_queue || 0) + Number(totalsRow.visitor_pending || 0),
    full_parking_zones: alertCountByType.get(ALERT_TYPES.FULL_PARKING_ZONE) || 0,
    low_slot_warnings: alertCountByType.get(ALERT_TYPES.LOW_SLOT_WARNING) || 0,
    suspicious_scans: alertCountByType.get(ALERT_TYPES.SUSPICIOUS_SCAN_BEHAVIOR) || 0,
    visitor_overstay_alerts: alertCountByType.get(ALERT_TYPES.VISITOR_OVERSTAY) || 0,
    visitor_pending_approvals: Number(totalsRow.visitor_pending || 0)
  };
}

async function createInvalidQrAlert(db, payload = {}) {
  const reason = String(payload.reason || payload.message || "Invalid QR attempt.").trim();
  const typeLabelMap = {
    INVALID: "Invalid QR",
    REVOKED: "Revoked QR",
    EXPIRED: "Expired QR",
    MISMATCH: "QR Mismatch"
  };
  const resultCode = String(payload.result || "INVALID").toUpperCase();
  const title = `${typeLabelMap[resultCode] || "Invalid QR Attempt"} at ${payload.gate || "Main Gate"}`;
  return createOrRefreshAlertWithDb(db, {
    type: ALERT_TYPES.INVALID_QR_ATTEMPT,
    title,
    message: reason,
    severity: payload.severity || ALERT_SEVERITIES.MEDIUM,
    audienceRole: "staff",
    relatedVehicleId: payload.relatedVehicleId || null,
    relatedQrId: payload.qrValue || null,
    relatedZoneId: payload.relatedZoneId || null,
    relatedGateId: payload.gate || null,
    relatedScanLogId: payload.scanLogId || null,
    source: payload.source || "scanner",
    metadata: {
      result: resultCode,
      gate: payload.gate || null,
      actor: payload.actorName || null,
      scanner_source: payload.source || null,
      qr_value: payload.qrValue || null
    }
  });
}

async function createPendingApprovalAlert(db, pendingEntry, actorName = "system") {
  if (!pendingEntry?.id) return null;
  const studentName = pendingEntry.full_name || "Unknown Student";
  const plateNumber = pendingEntry.plate_number || "-";
  return createOrRefreshAlertWithDb(db, {
    type: ALERT_TYPES.PENDING_ENTRY_APPROVAL,
    title: `Pending entry approval: ${studentName}`,
    message: `${studentName} (${plateNumber}) is waiting for parking assignment confirmation.`,
    severity: ALERT_SEVERITIES.MEDIUM,
    audienceRole: "staff",
    relatedVehicleId: pendingEntry.vehicle_id || null,
    relatedQrId: pendingEntry.qr_value || null,
    relatedGateId: pendingEntry.gate_id || null,
    relatedPendingEntryId: pendingEntry.id,
    dedupeKey: `PENDING_ENTRY:${pendingEntry.id}`,
    source: "camera_phone",
    metadata: {
      pending_entry_id: pendingEntry.id,
      student_name: studentName,
      student_number: pendingEntry.student_number || null,
      plate_number: plateNumber,
      gate_id: pendingEntry.gate_id || null,
      requested_by_guard: pendingEntry.requested_by_guard || actorName || null,
      requested_at: pendingEntry.created_at || null
    }
  });
}

async function resolvePendingApprovalAlert(db, pendingEntryId, resolvedBy = "system") {
  const resolvedRows = await resolvePendingEntryAlert(db, pendingEntryId, resolvedBy);
  return resolvedRows > 0;
}

async function createVisitorPendingApprovalAlert(db, visitorPass, actorName = "system") {
  if (!visitorPass?.id) return null;
  return createOrRefreshAlertWithDb(db, {
    type: ALERT_TYPES.PENDING_ENTRY_APPROVAL,
    title: `Visitor pass pending approval: ${visitorPass.visitor_name || "Unknown Visitor"}`,
    message: `${visitorPass.visitor_name || "Visitor"} (${visitorPass.plate_number || "No plate"}) requested temporary parking access.`,
    severity: ALERT_SEVERITIES.MEDIUM,
    audienceRole: "staff",
    relatedQrId: visitorPass.pass_code || visitorPass.qr_token || null,
    relatedZoneId: visitorPass.assigned_zone || "Visitor Zone",
    relatedVisitorPassId: visitorPass.id,
    dedupeKey: `VISITOR_PENDING_APPROVAL:${visitorPass.id}`,
    source: "visitor-pass",
    metadata: {
      visitor_pass_id: visitorPass.id,
      visitor_type: visitorPass.visitor_type || "visitor",
      visitor_name: visitorPass.visitor_name || null,
      plate_number: visitorPass.plate_number || null,
      requested_by: visitorPass.requested_by || actorName
    }
  });
}

async function resolveVisitorPendingApprovalAlert(db, visitorPassId, resolvedBy = "system") {
  if (!Number.isInteger(Number(visitorPassId)) || Number(visitorPassId) <= 0) return 0;
  return resolveAlertsByDedupeKey(db, `VISITOR_PENDING_APPROVAL:${Number(visitorPassId)}`, resolvedBy);
}

async function createVisitorAccessAlert(db, payload = {}) {
  const reason = String(payload.reason || "Visitor pass access denied.").trim();
  const resultCode = String(payload.result || "INVALID").toUpperCase();
  const passCode = payload.passCode || payload.qrValue || "unknown-pass";
  return createOrRefreshAlertWithDb(db, {
    type: ALERT_TYPES.INVALID_QR_ATTEMPT,
    title: `Visitor pass ${resultCode}: ${passCode}`,
    message: reason,
    severity: payload.severity || ALERT_SEVERITIES.MEDIUM,
    audienceRole: "staff",
    relatedQrId: payload.qrValue || null,
    relatedVehicleId: null,
    relatedVisitorPassId: payload.relatedVisitorPassId || null,
    relatedGateId: payload.gate || null,
    source: payload.source || "visitor-pass",
    metadata: {
      result: resultCode,
      visitor_pass_id: payload.relatedVisitorPassId || null,
      pass_code: payload.passCode || null,
      gate: payload.gate || null,
      actor: payload.actorName || null
    }
  });
}

async function evaluateVisitorOverstayAlerts(db = pool, actorName = "system") {
  const [insideRows] = await db.query(
    `SELECT
       vp.id,
       vp.pass_code,
       vp.visitor_name,
       vp.plate_number,
       vp.assigned_zone,
       vp.last_entry_at,
       TIMESTAMPDIFF(MINUTE, vp.last_entry_at, NOW()) AS minutes_inside
     FROM visitor_passes vp
     WHERE vp.pass_state = 'INSIDE'
       AND vp.last_entry_at IS NOT NULL`
  );

  const overstayIds = [];
  for (const row of insideRows) {
    const minutesInside = Math.max(0, Number(row.minutes_inside || 0));
    if (minutesInside < VISITOR_OVERSTAY_MINUTES) {
      await resolveAlertsByDedupeKey(db, `VISITOR_OVERSTAY:${row.id}`, actorName);
      continue;
    }

    overstayIds.push(row.id);
    const overstayMinutes = Math.max(0, minutesInside - VISITOR_OVERSTAY_MINUTES);
    await createOrRefreshAlertWithDb(db, {
      type: ALERT_TYPES.VISITOR_OVERSTAY,
      title: `Visitor overstay: ${row.visitor_name || "Unknown Visitor"}`,
      message: `${row.visitor_name || "Visitor"} has stayed ${formatDurationMinutes(minutesInside)} in ${row.assigned_zone || "Visitor Zone"} (${formatDurationMinutes(overstayMinutes)} beyond limit).`,
      severity: overstayMinutes >= 120 ? ALERT_SEVERITIES.HIGH : ALERT_SEVERITIES.MEDIUM,
      audienceRole: "staff",
      relatedQrId: row.pass_code || null,
      relatedZoneId: row.assigned_zone || "Visitor Zone",
      relatedVisitorPassId: row.id,
      dedupeKey: `VISITOR_OVERSTAY:${row.id}`,
      source: "visitor-pass",
      metadata: {
        visitor_pass_id: row.id,
        visitor_name: row.visitor_name || null,
        plate_number: row.plate_number || null,
        minutes_inside: minutesInside,
        overstay_minutes: overstayMinutes,
        limit_minutes: VISITOR_OVERSTAY_MINUTES,
        actor: actorName
      }
    });
  }

  return {
    inside_count: insideRows.length,
    overstay_count: overstayIds.length
  };
}

async function evaluateZoneCapacityAlerts(db = pool, actorName = "system") {
  const [rows] = await db.query(
    `SELECT
       COALESCE(ps.zone, 'General') AS zone,
       COUNT(*) AS total_slots,
       SUM(CASE WHEN ps.status = 'available' AND ps.current_sticker_id IS NULL AND ps.current_visitor_pass_id IS NULL THEN 1 ELSE 0 END) AS available_slots,
       SUM(CASE WHEN ps.status = 'available' AND (ps.current_sticker_id IS NOT NULL OR ps.current_visitor_pass_id IS NOT NULL) THEN 1 ELSE 0 END) AS occupied_slots,
       SUM(CASE WHEN ps.status <> 'available' THEN 1 ELSE 0 END) AS disabled_slots,
       COALESCE(MAX(pzs.warning_threshold_percent), 85) AS warning_threshold_percent
     FROM parking_slots ps
     LEFT JOIN parking_zone_settings pzs ON pzs.zone = COALESCE(ps.zone, 'General')
     GROUP BY COALESCE(ps.zone, 'General')`
  );

  const zoneStates = rows.map((row) => ({
    zone: row.zone || "General",
    total_slots: Number(row.total_slots || 0),
    available_slots: Number(row.available_slots || 0),
    occupied_slots: Number(row.occupied_slots || 0),
    disabled_slots: Number(row.disabled_slots || 0),
    warning_threshold_percent: Math.max(50, Math.min(100, Number(row.warning_threshold_percent || 85)))
  }));

  zoneStates.forEach((zone) => {
    const enabledSlots = Math.max(0, zone.total_slots - zone.disabled_slots);
    zone.occupancy_percent = enabledSlots > 0 ? Math.round((zone.occupied_slots / enabledSlots) * 100) : 0;
  });

  for (const zone of zoneStates) {
    const fullDedupeKey = `ZONE_FULL:${zone.zone}`;
    const lowDedupeKey = `ZONE_LOW:${zone.zone}`;

    if (zone.total_slots > 0 && zone.available_slots <= 0) {
      await createOrRefreshAlertWithDb(db, {
        type: ALERT_TYPES.FULL_PARKING_ZONE,
        title: `Parking zone full: ${zone.zone}`,
        message: `${zone.zone} has reached full capacity. New entry assignment is blocked until a slot is released.`,
        severity: ALERT_SEVERITIES.HIGH,
        audienceRole: "staff",
        relatedZoneId: zone.zone,
        dedupeKey: fullDedupeKey,
        source: "system",
        metadata: {
          zone: zone.zone,
          available_slots: zone.available_slots,
          occupied_slots: zone.occupied_slots,
          disabled_slots: zone.disabled_slots,
          total_slots: zone.total_slots,
          threshold_percent: zone.warning_threshold_percent,
          actor: actorName
        }
      });
    } else {
      await resolveAlertsByDedupeKey(db, fullDedupeKey, actorName);
    }

    if (zone.total_slots > 0 && zone.available_slots > 0 && zone.occupancy_percent >= zone.warning_threshold_percent) {
      await createOrRefreshAlertWithDb(db, {
        type: ALERT_TYPES.LOW_SLOT_WARNING,
        title: `Low slot warning: ${zone.zone}`,
        message: `${zone.zone} is ${zone.occupancy_percent}% occupied with ${zone.available_slots} slot(s) remaining.`,
        severity: zone.available_slots === 1 ? ALERT_SEVERITIES.HIGH : ALERT_SEVERITIES.MEDIUM,
        audienceRole: "staff",
        relatedZoneId: zone.zone,
        dedupeKey: lowDedupeKey,
        source: "system",
        metadata: {
          zone: zone.zone,
          available_slots: zone.available_slots,
          occupied_slots: zone.occupied_slots,
          disabled_slots: zone.disabled_slots,
          total_slots: zone.total_slots,
          threshold_percent: zone.warning_threshold_percent,
          occupancy_percent: zone.occupancy_percent,
          actor: actorName
        }
      });
    } else {
      await resolveAlertsByDedupeKey(db, lowDedupeKey, actorName);
    }
  }

  const fullCount = zoneStates.filter((zone) => zone.total_slots > 0 && zone.available_slots <= 0).length;
  const lowCount = zoneStates.filter((zone) =>
    zone.total_slots > 0 &&
    zone.available_slots > 0 &&
    zone.occupancy_percent >= zone.warning_threshold_percent
  ).length;
  return {
    zones: zoneStates,
    full_zone_count: fullCount,
    low_slot_zone_count: lowCount
  };
}

const OPERATIONAL_STATE_REFRESH_INTERVAL_MS = 5000;
let operationalStateRefreshPromise = null;
let operationalStateRefreshedAt = 0;

async function refreshOperationalState(actorName = "system") {
  if (operationalStateRefreshPromise) return operationalStateRefreshPromise;
  if (Date.now() - operationalStateRefreshedAt < OPERATIONAL_STATE_REFRESH_INTERVAL_MS) return;

  const refreshPromise = (async () => {
    await expireStaleVisitorPasses(pool, actorName);
    await Promise.all([
      evaluateZoneCapacityAlerts(pool, actorName),
      evaluateVisitorOverstayAlerts(pool, actorName)
    ]);
    operationalStateRefreshedAt = Date.now();
  })();
  operationalStateRefreshPromise = refreshPromise;

  try {
    await refreshPromise;
  } finally {
    if (operationalStateRefreshPromise === refreshPromise) {
      operationalStateRefreshPromise = null;
    }
  }
}

async function createSuspiciousScanAlert(db, payload = {}) {
  const severity = normalizeAlertSeverity(payload.severity || ALERT_SEVERITIES.MEDIUM);
  const sourceKey = String(payload.sourceKey || payload.source || "scanner").slice(0, 120);
  const dedupeKey = payload.dedupeKey ? String(payload.dedupeKey).slice(0, 190) : null;
  return createOrRefreshAlertWithDb(db, {
    type: ALERT_TYPES.SUSPICIOUS_SCAN_BEHAVIOR,
    title: String(payload.title || "Suspicious scan behavior detected").slice(0, 180),
    message: String(payload.message || "Repeated scan anomalies were detected.").slice(0, 1000),
    severity,
    audienceRole: "staff",
    relatedVehicleId: payload.relatedVehicleId || null,
    relatedQrId: payload.qrValue || null,
    relatedGateId: payload.gate || null,
    relatedScanLogId: payload.scanLogId || null,
    dedupeKey,
    source: payload.source || "scanner",
    metadata: {
      source_key: sourceKey,
      actor: payload.actorName || null,
      gate: payload.gate || null,
      qr_value: payload.qrValue || null,
      count: payload.count || null,
      window_minutes: SUSPICIOUS_WINDOW_MINUTES,
      reason: payload.reason || null
    }
  });
}

async function evaluateSuspiciousScanSignals(db, payload = {}) {
  const qrValue = payload.qrValue ? String(payload.qrValue).trim() : "";
  const gate = payload.gate ? String(payload.gate).trim() : "";
  const source = payload.source ? String(payload.source).trim() : "scanner";
  const actorName = payload.actorName ? String(payload.actorName).trim() : "system";
  const result = String(payload.result || "").toUpperCase();
  const duplicateScan = Boolean(payload.duplicateScan);
  const deniedReason = String(payload.deniedReason || "").trim();
  const scanLogId = Number(payload.scanLogId) || null;
  const sourceKey = `${source}|${gate || "-"}|${actorName || "-"}`;
  const windowStart = new Date(Date.now() - (SUSPICIOUS_WINDOW_MINUTES * 60 * 1000));

  if (INVALID_SCAN_RESULTS.has(result)) {
    const [[sourceFailedCountRow]] = await db.query(
      `SELECT COUNT(*) AS total
       FROM scan_logs
       WHERE scanned_at >= ?
         AND scan_source = ?
         AND COALESCE(gate_id, gate, '') = ?
         AND result IN ('INVALID', 'REVOKED', 'EXPIRED')`,
      [windowStart, source, gate || ""]
    );
    const sourceFailedCount = Number(sourceFailedCountRow?.total || 0);
    if (sourceFailedCount >= SUSPICIOUS_FAILED_SCAN_THRESHOLD) {
      await createSuspiciousScanAlert(db, {
        title: "Repeated failed scans at gate",
        message: `${sourceFailedCount} invalid/revoked/expired scans were recorded within ${SUSPICIOUS_WINDOW_MINUTES} minutes at ${gate || "Unknown Gate"}.`,
        severity: sourceFailedCount >= SUSPICIOUS_FAILED_SCAN_THRESHOLD + 2 ? ALERT_SEVERITIES.HIGH : ALERT_SEVERITIES.MEDIUM,
        qrValue,
        gate,
        source,
        sourceKey,
        actorName,
        scanLogId,
        count: sourceFailedCount,
        reason: "failed-scan-burst",
        dedupeKey: `SUSP_FAILED_SOURCE:${sourceKey}`
      });
    }

    if (qrValue) {
      const [[invalidTokenCountRow]] = await db.query(
        `SELECT COUNT(*) AS total
         FROM scan_logs
         WHERE scanned_at >= ?
           AND qr_value = ?
           AND result IN ('INVALID', 'REVOKED', 'EXPIRED')`,
        [windowStart, qrValue]
      );
      const invalidTokenCount = Number(invalidTokenCountRow?.total || 0);
      if (invalidTokenCount >= SUSPICIOUS_FAILED_SCAN_THRESHOLD) {
        await createSuspiciousScanAlert(db, {
          title: "Repeated invalid attempts for same QR",
          message: `QR reference ${qrValue} has ${invalidTokenCount} failed attempts in ${SUSPICIOUS_WINDOW_MINUTES} minutes.`,
          severity: invalidTokenCount >= SUSPICIOUS_FAILED_SCAN_THRESHOLD + 2 ? ALERT_SEVERITIES.HIGH : ALERT_SEVERITIES.MEDIUM,
          qrValue,
          gate,
          source,
          sourceKey,
          actorName,
          scanLogId,
          count: invalidTokenCount,
          reason: "same-qr-invalid-burst",
          dedupeKey: `SUSP_INVALID_QR:${qrValue}`
        });
      }
    }
  }

  if (qrValue) {
    const [[repeatQrCountRow]] = await db.query(
      `SELECT COUNT(*) AS total
       FROM scan_logs
       WHERE scanned_at >= ?
         AND qr_value = ?`,
      [windowStart, qrValue]
    );
    const repeatQrCount = Number(repeatQrCountRow?.total || 0);
    if (repeatQrCount >= SUSPICIOUS_REPEAT_QR_THRESHOLD) {
      await createSuspiciousScanAlert(db, {
        title: "Repeated QR scan burst",
        message: `QR reference ${qrValue} was scanned ${repeatQrCount} times in ${SUSPICIOUS_WINDOW_MINUTES} minutes.`,
        severity: repeatQrCount >= SUSPICIOUS_REPEAT_QR_THRESHOLD + 3 ? ALERT_SEVERITIES.HIGH : ALERT_SEVERITIES.MEDIUM,
        qrValue,
        gate,
        source,
        sourceKey,
        actorName,
        scanLogId,
        count: repeatQrCount,
        reason: "repeat-qr-burst",
        dedupeKey: `SUSP_REPEAT_QR:${qrValue}`
      });
    }
  }

  if (duplicateScan && qrValue) {
    await createSuspiciousScanAlert(db, {
      title: "Duplicate scan blocked",
      message: `Duplicate scan for QR ${qrValue} was blocked by cooldown protection.`,
      severity: ALERT_SEVERITIES.LOW,
      qrValue,
      gate,
      source,
      sourceKey,
      actorName,
      scanLogId,
      reason: "duplicate-scan-blocked",
      dedupeKey: `SUSP_DUPLICATE:${qrValue}:${sourceKey}`
    });
  }

  if (deniedReason) {
    await createSuspiciousScanAlert(db, {
      title: "Entry attempt after denial",
      message: deniedReason,
      severity: ALERT_SEVERITIES.MEDIUM,
      qrValue,
      gate,
      source,
      sourceKey,
      actorName,
      scanLogId,
      reason: "denied-entry-repeat",
      dedupeKey: `SUSP_DENIED:${qrValue || sourceKey}`
    });
  }
}

function mapPendingAutoEntry(row) {
  if (!row) return null;
  return {
    id: row.id,
    sticker_id: row.sticker_id || null,
    student_id: row.student_id || null,
    vehicle_id: row.vehicle_id || null,
    qr_value: row.qr_value || null,
    gate_id: row.gate_id || null,
    snapshot_path: row.snapshot_path || null,
    status: row.status || "PENDING",
    requested_by_guard: row.requested_by_guard || null,
    confirmed_by_guard: row.confirmed_by_guard || null,
    assigned_slot_id: row.assigned_slot_id || null,
    linked_scan_log_id: row.linked_scan_log_id || null,
    confirm_note: row.confirm_note || null,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
    confirmed_at: row.confirmed_at || null,
    sticker_code: row.sticker_code || null,
    student_number: row.student_number || null,
    full_name: row.full_name || null,
    plate_number: row.plate_number || null,
    vehicle_type: row.vehicle_model || null,
    vehicle_color: row.vehicle_color || null
  };
}

async function expireStalePendingAutoEntries(db = pool) {
  const cutoff = new Date(Date.now() - (AUTO_PENDING_EXPIRY_MINUTES * 60 * 1000));
  const [rows] = await db.query(
    `SELECT id
     FROM auto_scan_queue
     WHERE status = 'PENDING'
       AND created_at < ?
     FOR UPDATE`,
    [cutoff]
  );
  const expiredIds = rows.map((row) => Number(row.id)).filter((id) => Number.isInteger(id) && id > 0);
  if (!expiredIds.length) return [];

  await db.query(
    `UPDATE auto_scan_queue
     SET
       status = 'EXPIRED',
       confirmed_at = COALESCE(confirmed_at, NOW()),
       confirm_note = COALESCE(confirm_note, 'Pending request expired before confirmation')
     WHERE status = 'PENDING'
       AND created_at < ?`,
    [cutoff]
  );

  for (const expiredId of expiredIds) {
    await resolvePendingApprovalAlert(db, expiredId, "system-expiry");
  }
  return expiredIds;
}

async function getPendingAutoEntryBySticker(stickerId, db = pool, lock = false) {
  if (!stickerId) return null;
  const sql = `
    SELECT id, sticker_id, qr_value, gate_id, snapshot_path, status, created_at
    FROM auto_scan_queue
    WHERE sticker_id = ?
      AND status = 'PENDING'
    ORDER BY created_at DESC, id DESC
    LIMIT 1
    ${lock ? "FOR UPDATE" : ""}
  `;
  const [rows] = await db.query(sql, [stickerId]);
  return rows.length > 0 ? rows[0] : null;
}

async function createPendingAutoEntryWithDb(db, payload) {
  const [insertResult] = await db.query(
    `INSERT INTO auto_scan_queue (
       sticker_id,
       student_id,
       vehicle_id,
       qr_value,
       gate_id,
       snapshot_path,
       scan_source,
       status,
       requested_by_guard
     ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)`,
    [
      payload.stickerId || null,
      payload.studentId || null,
      payload.vehicleId || null,
      payload.qrValue || null,
      payload.gateId || null,
      payload.snapshotPath || null,
      payload.scanSource || "camera_phone",
      payload.requestedByGuard || null
    ]
  );

  const [rows] = await db.query(
    `SELECT
       q.id,
       q.sticker_id,
       q.student_id,
       q.vehicle_id,
       q.qr_value,
       q.gate_id,
       q.snapshot_path,
       q.status,
       q.requested_by_guard,
       q.confirmed_by_guard,
       q.assigned_slot_id,
       q.linked_scan_log_id,
       q.confirm_note,
       q.created_at,
       q.updated_at,
       q.confirmed_at,
       s.sticker_code,
       st.student_number,
       st.full_name,
       v.plate_number,
       v.model AS vehicle_model,
       v.color AS vehicle_color
     FROM auto_scan_queue q
     LEFT JOIN stickers s ON s.id = q.sticker_id
     LEFT JOIN vehicles v ON v.id = COALESCE(q.vehicle_id, s.vehicle_id)
     LEFT JOIN students st ON st.id = COALESCE(q.student_id, v.student_id)
     WHERE q.id = ?
     LIMIT 1`,
    [insertResult.insertId]
  );

  const entry = rows.length > 0 ? mapPendingAutoEntry(rows[0]) : null;
  if (entry) {
    await createPendingApprovalAlert(db, entry, payload.requestedByGuard || "system");
  }
  return entry;
}

async function listPendingAutoEntries(limit = 25, db = pool) {
  const safeLimit = Math.max(1, Math.min(100, Number(limit) || 25));
  const [rows] = await db.query(
    `SELECT
       q.id,
       q.sticker_id,
       q.student_id,
       q.vehicle_id,
       q.qr_value,
       q.gate_id,
       q.snapshot_path,
       q.status,
       q.requested_by_guard,
       q.confirmed_by_guard,
       q.assigned_slot_id,
       q.linked_scan_log_id,
       q.confirm_note,
       q.created_at,
       q.updated_at,
       q.confirmed_at,
       s.sticker_code,
       st.student_number,
       st.full_name,
       v.plate_number,
       v.model AS vehicle_model,
       v.color AS vehicle_color
     FROM auto_scan_queue q
     LEFT JOIN stickers s ON s.id = q.sticker_id
     LEFT JOIN vehicles v ON v.id = COALESCE(q.vehicle_id, s.vehicle_id)
     LEFT JOIN students st ON st.id = COALESCE(q.student_id, v.student_id)
     WHERE q.status = 'PENDING'
     ORDER BY q.created_at DESC, q.id DESC
     LIMIT ?`,
    [safeLimit]
  );
  return rows.map(mapPendingAutoEntry);
}

async function getPendingAutoEntryByIdForUpdate(entryId, db) {
  const [rows] = await db.query(
    `SELECT
       q.id,
       q.sticker_id,
       q.student_id,
       q.vehicle_id,
       q.qr_value,
       q.gate_id,
       q.snapshot_path,
       q.status,
       q.requested_by_guard,
       q.confirmed_by_guard,
       q.assigned_slot_id,
       q.linked_scan_log_id,
       q.confirm_note,
       q.created_at,
       q.updated_at,
       q.confirmed_at,
       s.sticker_code,
       st.student_number,
       st.full_name,
       v.plate_number,
       v.model AS vehicle_model,
       v.color AS vehicle_color
     FROM auto_scan_queue q
     LEFT JOIN stickers s ON s.id = q.sticker_id
     LEFT JOIN vehicles v ON v.id = COALESCE(q.vehicle_id, s.vehicle_id)
     LEFT JOIN students st ON st.id = COALESCE(q.student_id, v.student_id)
     WHERE q.id = ?
     LIMIT 1
     FOR UPDATE`,
    [entryId]
  );
  return rows.length > 0 ? mapPendingAutoEntry(rows[0]) : null;
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

  const filename = `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString("hex")}.${ext}`;
  const mimeType = ext === "png" ? "image/png" : "image/jpeg";
  await pool.query(
    "INSERT INTO scan_snapshots (storage_key, mime_type, image_data, byte_size) VALUES (?, ?, ?, ?)",
    [filename, mimeType, imageBuffer, imageBuffer.length]
  );
  return `/snapshots/${filename}`;
}

async function preparePrivateSnapshotStorage() {
  await fs.promises.mkdir(SNAPSHOT_DIR, { recursive: true });

  let legacyEntries = [];
  try {
    legacyEntries = await fs.promises.readdir(LEGACY_PUBLIC_SNAPSHOT_DIR, { withFileTypes: true });
  } catch (error) {
    if (error.code === "ENOENT") return 0;
    throw error;
  }

  let migratedCount = 0;
  for (const entry of legacyEntries) {
    if (!entry.isFile()) continue;
    const filename = path.basename(entry.name);
    const sourcePath = path.join(LEGACY_PUBLIC_SNAPSHOT_DIR, filename);
    const destinationPath = path.join(SNAPSHOT_DIR, filename);
    try {
      await fs.promises.access(destinationPath, fs.constants.F_OK);
      console.warn(`Private snapshot migration skipped existing file: ${filename}`);
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      await fs.promises.rename(sourcePath, destinationPath);
      migratedCount += 1;
    }
  }

  try {
    await fs.promises.rmdir(LEGACY_PUBLIC_SNAPSHOT_DIR);
  } catch (error) {
    if (error.code !== "ENOENT" && error.code !== "ENOTEMPTY") throw error;
  }

  return migratedCount;
}

function buildReportFilters(query) {
  const allowedPresets = new Set(["today", "last7", "last30", "custom"]);
  const safePreset = allowedPresets.has(String(query.preset || "").toLowerCase())
    ? String(query.preset || "").toLowerCase()
    : "last7";

  const now = new Date();
  const today = new Date(now);
  today.setHours(0, 0, 0, 0);
  let fromDate = new Date(today);
  let toDate = new Date(today);

  if (safePreset === "today") {
    fromDate = new Date(today);
    toDate = new Date(today);
  } else if (safePreset === "last30") {
    fromDate = new Date(today);
    fromDate.setDate(fromDate.getDate() - 29);
  } else if (safePreset === "custom") {
    const parsedFrom = normalizeDateOnlyInput(query.from);
    const parsedTo = normalizeDateOnlyInput(query.to);
    if (parsedFrom && parsedTo) {
      fromDate = new Date(`${parsedFrom}T00:00:00`);
      toDate = new Date(`${parsedTo}T00:00:00`);
    } else {
      fromDate = new Date(today);
      fromDate.setDate(fromDate.getDate() - 6);
    }
  } else {
    fromDate = new Date(today);
    fromDate.setDate(fromDate.getDate() - 6);
  }

  if (fromDate > toDate) {
    const tmp = fromDate;
    fromDate = toDate;
    toDate = tmp;
  }

  const maxRangeDays = 180;
  const maxToDate = new Date(fromDate);
  maxToDate.setDate(maxToDate.getDate() + maxRangeDays - 1);
  if (toDate > maxToDate) {
    toDate = maxToDate;
  }

  const gate = query.gate && String(query.gate).trim() && String(query.gate).trim() !== "ALL"
    ? String(query.gate).trim()
    : "ALL";
  const zone = query.zone && String(query.zone).trim() && String(query.zone).trim() !== "ALL"
    ? String(query.zone).trim()
    : "ALL";
  const passType = ["all", "student", "visitor"].includes(String(query.pass_type || "").toLowerCase())
    ? String(query.pass_type || "").toLowerCase()
    : "all";
  const vehicleType = query.vehicle_type && String(query.vehicle_type).trim() && String(query.vehicle_type).trim() !== "ALL"
    ? String(query.vehicle_type).trim()
    : "ALL";

  const from = toDateOnly(fromDate);
  const to = toDateOnly(toDate);
  const preset = safePreset;

  return {
    preset,
    from,
    to,
    gate,
    zone,
    pass_type: passType,
    vehicle_type: vehicleType
  };
}

function getReportQueryString(filters = {}, overrides = {}) {
  const merged = {
    preset: filters.preset || "last7",
    from: filters.from || "",
    to: filters.to || "",
    gate: filters.gate || "ALL",
    zone: filters.zone || "ALL",
    pass_type: filters.pass_type || "all",
    vehicle_type: filters.vehicle_type || "ALL",
    ...overrides
  };
  const params = new URLSearchParams();
  Object.keys(merged).forEach((key) => {
    const value = merged[key];
    if (value == null || value === "") return;
    params.set(key, String(value));
  });
  return params.toString();
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

async function findVisitorPassByToken(token, db = pool) {
  const safeToken = normalizeQrTokenInput(token);
  if (!safeToken) return null;
  const [rows] = await db.query(
    `SELECT
       vp.id,
       vp.pass_code,
       vp.qr_token,
       vp.visitor_type,
       vp.visitor_name,
       vp.organization,
       vp.contact_number,
       vp.plate_number,
       vp.vehicle_type,
       vp.purpose,
       vp.requested_by,
       vp.approval_status,
       vp.approved_by,
       vp.approved_at,
       vp.approval_note,
       vp.pass_state,
       vp.valid_from,
       vp.valid_until,
       vp.assigned_zone,
       vp.assigned_slot_id,
       vp.last_entry_at,
       vp.last_exit_at,
       vp.created_at,
       vp.updated_at,
       ps.slot_code AS current_slot
     FROM visitor_passes vp
     LEFT JOIN parking_slots ps
       ON ps.current_visitor_pass_id = vp.id
     WHERE vp.qr_token = ?
        OR vp.pass_code = ?
     ORDER BY vp.id DESC
     LIMIT 1`,
    [safeToken, safeToken]
  );
  return rows.length > 0 ? rows[0] : null;
}

async function expireStaleVisitorPasses(db = pool, actorName = "system-expiry") {
  const [expiringRows] = await db.query(
    `SELECT id
     FROM visitor_passes
     WHERE pass_state IN ('PENDING', 'ACTIVE', 'INSIDE', 'EXITED')
       AND valid_until < NOW()`
  );
  const expiredIds = expiringRows.map((row) => Number(row.id)).filter((id) => Number.isInteger(id) && id > 0);
  if (!expiredIds.length) return [];

  const placeholders = expiredIds.map(() => "?").join(", ");
  await db.query(
    `UPDATE visitor_passes
     SET
       pass_state = 'EXPIRED',
       assigned_slot_id = NULL,
       updated_at = NOW()
     WHERE id IN (${placeholders})`,
    expiredIds
  );
  await db.query(
    `UPDATE parking_slots
     SET current_visitor_pass_id = NULL
     WHERE current_visitor_pass_id IN (${placeholders})`,
    expiredIds
  );

  for (const visitorPassId of expiredIds) {
    await resolveAlertsByDedupeKey(db, `VISITOR_PENDING_APPROVAL:${visitorPassId}`, actorName);
  }
  return expiredIds;
}

async function getVisitorPassVerificationState(token, db = pool) {
  const safeToken = normalizeQrTokenInput(token);
  if (!safeToken) {
    return {
      ok: false,
      result: "INVALID",
      message: "Visitor pass token is required.",
      visitor_pass: null
    };
  }

  await expireStaleVisitorPasses(db, "visitor-verification");
  const pass = await findVisitorPassByToken(safeToken, db);
  if (!pass) {
    return {
      ok: false,
      result: "INVALID",
      message: "Visitor pass not found.",
      visitor_pass: null
    };
  }

  if (pass.approval_status === VISITOR_APPROVAL_STATUS.PENDING) {
    return {
      ok: false,
      result: "INVALID",
      message: "Visitor pass is pending approval.",
      visitor_pass: pass
    };
  }

  if ([VISITOR_APPROVAL_STATUS.REJECTED, VISITOR_APPROVAL_STATUS.CANCELLED].includes(pass.approval_status)) {
    return {
      ok: false,
      result: "REVOKED",
      message: "Visitor pass access is denied.",
      visitor_pass: pass
    };
  }

  if (pass.pass_state === VISITOR_PASS_STATE.EXPIRED || (pass.valid_until && new Date(pass.valid_until).getTime() < Date.now())) {
    return {
      ok: false,
      result: "EXPIRED",
      message: "Visitor pass has expired.",
      visitor_pass: pass
    };
  }

  if (![VISITOR_PASS_STATE.ACTIVE, VISITOR_PASS_STATE.INSIDE, VISITOR_PASS_STATE.EXITED].includes(pass.pass_state)) {
    return {
      ok: false,
      result: "REVOKED",
      message: "Visitor pass is not active.",
      visitor_pass: pass
    };
  }

  return {
    ok: true,
    result: "VALID",
    message: "Visitor pass verified.",
    visitor_pass: pass
  };
}

async function getCurrentParkingSlotByVisitorPass(visitorPassId, db = pool) {
  const [rows] = await db.query(
    `SELECT id, slot_code, zone, slot_type, reserved_for
     FROM parking_slots
     WHERE current_visitor_pass_id = ?
     LIMIT 1`,
    [visitorPassId]
  );
  return rows.length > 0 ? rows[0] : null;
}

async function getLastVisitorMovement(visitorPassId, db = pool) {
  const [rows] = await db.query(
    `SELECT id, action, scanned_at, slot_id
     FROM visitor_scan_logs
     WHERE visitor_pass_id = ?
       AND result = 'VALID'
       AND action IN ('ENTRY', 'EXIT')
     ORDER BY scanned_at DESC, id DESC
     LIMIT 1`,
    [visitorPassId]
  );
  return rows.length > 0 ? rows[0] : null;
}

async function insertVisitorScanLogWithDb(db, visitorPassId, result, action, gate, reason, options = {}) {
  const [insertResult] = await db.query(
    `INSERT INTO visitor_scan_logs (
       visitor_pass_id,
       result,
       action,
       gate,
       gate_id,
       slot_id,
       qr_value,
       assigned_by_guard,
       scan_source,
       snapshot_path,
       status,
       reason
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      visitorPassId,
      String(result || "INVALID").toUpperCase(),
      String(action || "VERIFY").toUpperCase(),
      gate || null,
      options.gateId || gate || null,
      options.slotId || null,
      options.qrValue || null,
      options.assignedByGuard || null,
      options.scanSource || "manual",
      options.snapshotPath || null,
      options.status || normalizeScanStatus(result),
      reason || null
    ]
  );
  const [rows] = await db.query(
    "SELECT id, scanned_at, slot_id, status FROM visitor_scan_logs WHERE id = ? LIMIT 1",
    [insertResult.insertId]
  );
  return rows.length > 0 ? rows[0] : null;
}

async function insertVisitorScanLog(visitorPassId, result, action, gate, reason, options = {}) {
  return insertVisitorScanLogWithDb(pool, visitorPassId, result, action, gate, reason, options);
}

async function assignVisitorParkingSlot(db, visitorPassId, slotId) {
  const [slotRows] = await db.query(
    `SELECT id, slot_code, zone, status, current_sticker_id, current_visitor_pass_id
     FROM parking_slots
     WHERE id = ?
     FOR UPDATE`,
    [slotId]
  );

  if (slotRows.length === 0) {
    throw new Error("Selected parking slot does not exist.");
  }

  const slot = slotRows[0];
  if (!isVisitorZone(slot.zone)) {
    throw new Error("Visitor vehicles can only be assigned to Visitor Zone slots.");
  }
  if (slot.status !== "available") {
    throw new Error("Selected visitor parking slot is disabled.");
  }
  if (slot.current_sticker_id || slot.current_visitor_pass_id) {
    throw new Error("Selected visitor parking slot is already occupied.");
  }

  await db.query(
    `UPDATE parking_slots
     SET current_visitor_pass_id = NULL
     WHERE current_visitor_pass_id = ?`,
    [visitorPassId]
  );
  await db.query(
    `UPDATE parking_slots
     SET current_visitor_pass_id = ?
     WHERE id = ?`,
    [visitorPassId, slotId]
  );
  await db.query(
    `UPDATE visitor_passes
     SET
       assigned_slot_id = ?,
       assigned_zone = ?,
       updated_at = NOW()
     WHERE id = ?`,
    [slot.id, slot.zone || "Visitor Zone", visitorPassId]
  );
  return { id: slot.id, slot_code: slot.slot_code, zone: slot.zone };
}

async function releaseVisitorParkingSlot(db, visitorPassId) {
  const [rows] = await db.query(
    `SELECT id, slot_code, zone, slot_type, reserved_for
     FROM parking_slots
     WHERE current_visitor_pass_id = ?
     FOR UPDATE`,
    [visitorPassId]
  );
  const slot = rows.length > 0 ? rows[0] : null;
  if (slot) {
    await db.query(
      `UPDATE parking_slots
       SET current_visitor_pass_id = NULL
       WHERE id = ?`,
      [slot.id]
    );
  }
  await db.query(
    `UPDATE visitor_passes
     SET
       assigned_slot_id = NULL,
       updated_at = NOW()
     WHERE id = ?`,
    [visitorPassId]
  );
  return slot;
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

async function getInsideVehicleMetrics(db = pool) {
  const [[countRow]] = await db.query(
    `SELECT
       COUNT(*) AS total_inside,
       COALESCE(SUM(
         CASE
           WHEN TIMESTAMPDIFF(MINUTE, movement.scanned_at, NOW()) > ? THEN 1
           ELSE 0
         END
       ), 0) AS overstay_count
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
     WHERE movement.action = 'ENTRY'`,
    [OVERSTAY_LIMIT_MINUTES]
  );
  return {
    total_inside: Number(countRow?.total_inside || 0),
    overstay_count: Number(countRow?.overstay_count || 0)
  };
}

async function getRecentMovementLogs(db = pool, limit = 80) {
  const safeLimit = Math.max(10, Math.min(500, Number(limit) || 80));
  const [rows] = await db.query(
    `SELECT
       sl.scanned_at,
       sl.result,
       sl.action,
       sl.gate,
       sl.gate AS gate_name,
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
     LIMIT ?`,
    [safeLimit]
  );
  return rows;
}

function buildVisitorFilterState(query = {}) {
  return {
    q: String(query.q || "").trim(),
    approval_status: String(query.approval_status || "all").trim().toUpperCase(),
    pass_state: String(query.pass_state || "all").trim().toUpperCase(),
    type: String(query.type || "all").trim().toLowerCase(),
    from: toDateOnly(query.from),
    to: toDateOnly(query.to),
    limit: Math.max(10, Math.min(250, Number(query.limit) || 80))
  };
}

async function getVisitorSummaryMetrics(db = pool) {
  const [[row]] = await db.query(
    `SELECT
       SUM(CASE WHEN approval_status = 'APPROVED' AND pass_state IN ('ACTIVE', 'INSIDE', 'EXITED') THEN 1 ELSE 0 END) AS active_passes,
       SUM(CASE WHEN approval_status = 'PENDING' AND pass_state <> 'EXPIRED' THEN 1 ELSE 0 END) AS pending_approvals,
       SUM(CASE WHEN pass_state = 'EXPIRED' THEN 1 ELSE 0 END) AS expired_passes,
       SUM(CASE WHEN pass_state = 'INSIDE' THEN 1 ELSE 0 END) AS current_inside
     FROM visitor_passes`
  );
  return {
    active_passes: Number(row?.active_passes || 0),
    pending_approvals: Number(row?.pending_approvals || 0),
    expired_passes: Number(row?.expired_passes || 0),
    current_inside: Number(row?.current_inside || 0)
  };
}

async function getPendingVisitorPasses(db = pool, limit = 50) {
  const safeLimit = Math.max(1, Math.min(200, Number(limit) || 50));
  const [rows] = await db.query(
    `SELECT
       id,
       pass_code,
       visitor_type,
       visitor_name,
       organization,
       contact_number,
       plate_number,
       vehicle_type,
       purpose,
       requested_by,
       approval_status,
       pass_state,
       valid_from,
       valid_until,
       created_at
     FROM visitor_passes
     WHERE approval_status = 'PENDING'
       AND pass_state <> 'EXPIRED'
     ORDER BY created_at DESC
     LIMIT ?`,
    [safeLimit]
  );
  return rows;
}

async function listVisitorPasses(filters = {}, db = pool) {
  const safeFilters = buildVisitorFilterState(filters);
  const where = [];
  const params = [];
  if (safeFilters.q) {
    const like = `%${safeFilters.q}%`;
    where.push("(vp.pass_code LIKE ? OR vp.visitor_name LIKE ? OR vp.plate_number LIKE ? OR vp.organization LIKE ? OR vp.purpose LIKE ?)");
    params.push(like, like, like, like, like);
  }
  if (safeFilters.approval_status && safeFilters.approval_status !== "ALL") {
    where.push("vp.approval_status = ?");
    params.push(safeFilters.approval_status);
  }
  if (safeFilters.pass_state && safeFilters.pass_state !== "ALL") {
    where.push("vp.pass_state = ?");
    params.push(safeFilters.pass_state);
  }
  if (safeFilters.type && safeFilters.type !== "all") {
    where.push("vp.visitor_type = ?");
    params.push(safeFilters.type);
  }
  if (safeFilters.from) {
    where.push("DATE(vp.created_at) >= ?");
    params.push(safeFilters.from);
  }
  if (safeFilters.to) {
    where.push("DATE(vp.created_at) <= ?");
    params.push(safeFilters.to);
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const [rows] = await db.query(
    `SELECT
       vp.id,
       vp.pass_code,
       vp.qr_token,
       vp.visitor_type,
       vp.visitor_name,
       vp.organization,
       vp.contact_number,
       vp.plate_number,
       vp.vehicle_type,
       vp.purpose,
       vp.requested_by,
       vp.approval_status,
       vp.approved_by,
       vp.approved_at,
       vp.approval_note,
       vp.pass_state,
       vp.valid_from,
       vp.valid_until,
       vp.assigned_zone,
       vp.assigned_slot_id,
       vp.last_entry_at,
       vp.last_exit_at,
       vp.created_at,
       vp.updated_at,
       ps.slot_code AS current_slot
     FROM visitor_passes vp
     LEFT JOIN parking_slots ps ON ps.current_visitor_pass_id = vp.id
     ${whereSql}
     ORDER BY vp.created_at DESC
     LIMIT ?`,
    [...params, safeFilters.limit]
  );
  return rows;
}

async function listVisitorScanLogs(filters = {}, db = pool) {
  const safeFilters = buildVisitorFilterState(filters);
  const where = [];
  const params = [];

  if (safeFilters.q) {
    const like = `%${safeFilters.q}%`;
    where.push("(vp.pass_code LIKE ? OR vp.visitor_name LIKE ? OR vp.plate_number LIKE ? OR vsl.gate LIKE ? OR vsl.reason LIKE ?)");
    params.push(like, like, like, like, like);
  }
  if (safeFilters.from) {
    where.push("DATE(vsl.scanned_at + INTERVAL 8 HOUR) >= ?");
    params.push(safeFilters.from);
  }
  if (safeFilters.to) {
    where.push("DATE(vsl.scanned_at + INTERVAL 8 HOUR) <= ?");
    params.push(safeFilters.to);
  }
  if (safeFilters.type && safeFilters.type !== "all") {
    where.push("vp.visitor_type = ?");
    params.push(safeFilters.type);
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const [rows] = await db.query(
    `SELECT
       vsl.id,
       vsl.scanned_at,
       vsl.result,
       vsl.action,
       vsl.gate,
       vsl.gate_id,
       vsl.qr_value,
       vsl.scan_source,
       vsl.status,
       vsl.reason,
       vp.id AS visitor_pass_id,
       vp.pass_code,
       vp.visitor_name,
       vp.visitor_type,
       vp.plate_number,
       vp.approval_status,
       vp.pass_state,
       ps.slot_code AS parking_slot
     FROM visitor_scan_logs vsl
     JOIN visitor_passes vp ON vp.id = vsl.visitor_pass_id
     LEFT JOIN parking_slots ps ON ps.id = vsl.slot_id
     ${whereSql}
     ORDER BY vsl.scanned_at DESC, vsl.id DESC
     LIMIT ?`,
    [...params, safeFilters.limit]
  );
  return rows;
}

async function getCurrentVisitorInsideRows(db = pool, limit = 40) {
  const safeLimit = Math.max(1, Math.min(120, Number(limit) || 40));
  const [rows] = await db.query(
    `SELECT
       vp.id,
       vp.pass_code,
       vp.visitor_name,
       vp.visitor_type,
       vp.plate_number,
       vp.assigned_zone,
       vp.last_entry_at,
       vp.valid_until,
       ps.slot_code AS parking_slot,
       TIMESTAMPDIFF(MINUTE, vp.last_entry_at, NOW()) AS minutes_inside
     FROM visitor_passes vp
     LEFT JOIN parking_slots ps ON ps.current_visitor_pass_id = vp.id
     WHERE vp.pass_state = 'INSIDE'
     ORDER BY vp.last_entry_at DESC
     LIMIT ?`,
    [safeLimit]
  );
  return rows.map((row) => ({
    ...row,
    minutes_inside: Math.max(0, Number(row.minutes_inside || 0)),
    duration_label: formatDurationMinutes(Math.max(0, Number(row.minutes_inside || 0))),
    is_overstay: Math.max(0, Number(row.minutes_inside || 0)) > VISITOR_OVERSTAY_MINUTES
  }));
}

async function getVisitorModuleData(filters = {}, db = pool) {
  await expireStaleVisitorPasses(db, "visitor-module");
  await evaluateVisitorOverstayAlerts(db, "visitor-module");
  const [summary, pendingApprovals, passes, logs, currentInside] = await Promise.all([
    getVisitorSummaryMetrics(db),
    getPendingVisitorPasses(db, 50),
    listVisitorPasses(filters, db),
    listVisitorScanLogs(filters, db),
    getCurrentVisitorInsideRows(db, 50)
  ]);
  return {
    summary,
    pendingApprovals,
    passes,
    logs,
    currentInside,
    filters: buildVisitorFilterState(filters)
  };
}

async function getDashboardEntityCounts(db = pool) {
  const [[row]] = await db.query(
    `SELECT
       (SELECT COUNT(*) FROM students) AS students,
       (SELECT COUNT(*) FROM vehicles) AS vehicles,
       (SELECT COUNT(*) FROM stickers WHERE status = 'active') AS active_stickers`
  );
  return {
    students: Number(row?.students || 0),
    vehicles: Number(row?.vehicles || 0),
    active_stickers: Number(row?.active_stickers || 0)
  };
}

async function getTodayMovementCounts(db = pool) {
  const [[row]] = await db.query(
    `SELECT
       COALESCE(SUM(CASE WHEN action = 'ENTRY' THEN 1 ELSE 0 END), 0) AS entries,
       COALESCE(SUM(CASE WHEN action = 'EXIT' THEN 1 ELSE 0 END), 0) AS exits
     FROM scan_logs
     WHERE result = 'VALID'
       AND scanned_at >= (DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR) - INTERVAL 8 HOUR)
       AND scanned_at < (DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR) - INTERVAL 8 HOUR) + INTERVAL 1 DAY`
  );
  return {
    entries: Number(row?.entries || 0),
    exits: Number(row?.exits || 0)
  };
}

async function getDashboardData() {
  await refreshOperationalState("admin-dashboard");
  const [
    alertMetrics,
    visitorMetrics,
    entityCounts,
    todayMovement,
    insideMetrics,
    movementLogs,
    insideVehicles,
    parkingSlotOverview
  ] = await Promise.all([
    getOperationalAlertMetrics(pool),
    getVisitorSummaryMetrics(pool),
    getDashboardEntityCounts(pool),
    getTodayMovementCounts(pool),
    getInsideVehicleMetrics(pool),
    getRecentMovementLogs(pool, 80),
    getInsideVehiclesWithOverstay(pool, 20),
    getParkingSlotOverview(pool)
  ]);
  const overstayAlerts = insideVehicles.filter((item) => item.is_overstay);
  const parkingSlots = parkingSlotOverview.slots;
  const availableSlots = parkingSlots.filter((slot) => slot.is_selectable);
  return {
    metrics: {
      students: entityCounts.students,
      vehicles: entityCounts.vehicles,
      activeStickers: entityCounts.active_stickers,
      todayEntries: todayMovement.entries,
      todayExits: todayMovement.exits,
      currentlyInside: insideMetrics.total_inside,
      overstayAlerts: insideMetrics.overstay_count,
      invalidQrAttemptsToday: alertMetrics.invalid_qr_today,
      fullParkingZones: alertMetrics.full_parking_zones,
      lowSlotWarnings: alertMetrics.low_slot_warnings,
      pendingApprovals: alertMetrics.pending_approvals,
      suspiciousScans: alertMetrics.suspicious_scans,
      visitorActivePasses: visitorMetrics.active_passes,
      visitorPendingApprovals: visitorMetrics.pending_approvals,
      visitorExpiredPasses: visitorMetrics.expired_passes,
      visitorCurrentlyInside: visitorMetrics.current_inside,
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
  const safeFilters = buildReportFilters(filters);
  const todayDate = toDateOnly(new Date());
  const toTimeValue = (value) => {
    const ts = new Date(value).getTime();
    return Number.isFinite(ts) ? ts : 0;
  };
  const sortByTimeAsc = (a, b) => {
    const diff = toTimeValue(a.event_time) - toTimeValue(b.event_time);
    if (diff !== 0) return diff;
    return Number(a.id || 0) - Number(b.id || 0);
  };
  const sortByTimeDesc = (a, b) => {
    const diff = toTimeValue(b.event_time) - toTimeValue(a.event_time);
    if (diff !== 0) return diff;
    return Number(b.id || 0) - Number(a.id || 0);
  };
  const asString = (value, fallback = "Unknown") => {
    const safe = String(value == null ? "" : value).trim();
    return safe || fallback;
  };
  const computeWeekKey = (value) => {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "Unknown";
    const utc = new Date(`${toDateOnly(date)}T00:00:00.000Z`);
    const dayNum = utc.getUTCDay() || 7;
    utc.setUTCDate(utc.getUTCDate() + 4 - dayNum);
    const yearStart = new Date(Date.UTC(utc.getUTCFullYear(), 0, 1));
    const weekNo = Math.ceil((((utc - yearStart) / 86400000) + 1) / 7);
    return `${utc.getUTCFullYear()}-W${String(weekNo).padStart(2, "0")}`;
  };
  const aggregateCounts = (rows, keyPicker) => {
    const map = new Map();
    rows.forEach((row) => {
      const key = keyPicker(row);
      map.set(key, Number(map.get(key) || 0) + 1);
    });
    return map;
  };
  const mapToSeries = (map, label = "count") => {
    return Array.from(map.entries())
      .sort((a, b) => String(a[0]).localeCompare(String(b[0])))
      .map(([bucket, total]) => ({ bucket, [label]: Number(total || 0) }));
  };
  const reduceSlotSummary = (slots) => {
    return slots.reduce(
      (acc, slot) => {
        acc.total += 1;
        if (slot.occupancy === "available") acc.available += 1;
        else if (slot.occupancy === "occupied") acc.occupied += 1;
        else acc.disabled += 1;
        return acc;
      },
      { total: 0, available: 0, occupied: 0, disabled: 0 }
    );
  };
  const runQueryWithFallback = async (query, params, fallbackRows, label) => {
    try {
      const [rows] = await pool.query(query, params);
      return rows;
    } catch (error) {
      if (!isSchemaCompatibilityError(error)) throw error;
      console.warn(`[reports] ${label} fallback due to schema mismatch:`, error.message);
      return fallbackRows;
    }
  };

  const fetchMovementEvents = async (rangeFrom, rangeTo) => {
    const studentWhere = [
      "sl.result = 'VALID'",
      "sl.action IN ('ENTRY', 'EXIT')",
      "DATE(sl.scanned_at + INTERVAL 8 HOUR) BETWEEN ? AND ?"
    ];
    const studentParams = [rangeFrom, rangeTo];
    if (safeFilters.gate !== "ALL") {
      studentWhere.push("COALESCE(sl.gate, 'Unspecified') = ?");
      studentParams.push(safeFilters.gate);
    }
    if (safeFilters.zone !== "ALL") {
      studentWhere.push("COALESCE(ps.zone, sl.assigned_area, 'Unassigned') = ?");
      studentParams.push(safeFilters.zone);
    }
    if (safeFilters.vehicle_type !== "ALL") {
      studentWhere.push("COALESCE(NULLIF(TRIM(v.model), ''), 'Unknown') = ?");
      studentParams.push(safeFilters.vehicle_type);
    }

    const visitorWhere = [
      "vsl.result = 'VALID'",
      "vsl.action IN ('ENTRY', 'EXIT')",
      "DATE(vsl.scanned_at + INTERVAL 8 HOUR) BETWEEN ? AND ?"
    ];
    const visitorParams = [rangeFrom, rangeTo];
    if (safeFilters.gate !== "ALL") {
      visitorWhere.push("COALESCE(vsl.gate, 'Unspecified') = ?");
      visitorParams.push(safeFilters.gate);
    }
    if (safeFilters.zone !== "ALL") {
      visitorWhere.push("COALESCE(ps.zone, vp.assigned_zone, 'Visitor Zone') = ?");
      visitorParams.push(safeFilters.zone);
    }
    if (safeFilters.vehicle_type !== "ALL") {
      visitorWhere.push("COALESCE(NULLIF(TRIM(vp.vehicle_type), ''), 'Unknown') = ?");
      visitorParams.push(safeFilters.vehicle_type);
    }

    let studentEvents = [];
    let visitorEvents = [];

    if (safeFilters.pass_type !== "visitor") {
      try {
        const [rows] = await pool.query(
          `SELECT
             sl.id,
             sl.scanned_at AS event_time,
             sl.action,
             COALESCE(sl.gate, 'Unspecified') AS gate,
             COALESCE(ps.zone, sl.assigned_area, 'Unassigned') AS zone,
             COALESCE(NULLIF(TRIM(v.model), ''), 'Unknown') AS vehicle_type,
             'student' AS pass_type,
             COALESCE(st.student_number, 'Unknown') AS identity_number,
             COALESCE(st.full_name, 'Unknown Student') AS identity_name,
             COALESCE(v.plate_number, '-') AS plate_number,
             COALESCE(sl.sticker_id, sl.vehicle_id, sl.student_id, sl.id) AS entity_id,
             DATE_FORMAT(sl.scanned_at + INTERVAL 8 HOUR, '%Y-%m-%d') AS day_key,
             DATE_FORMAT(sl.scanned_at + INTERVAL 8 HOUR, '%H:00') AS hour_slot
           FROM scan_logs sl
           LEFT JOIN stickers s ON s.id = sl.sticker_id
           LEFT JOIN vehicles v ON v.id = COALESCE(sl.vehicle_id, s.vehicle_id)
           LEFT JOIN students st ON st.id = COALESCE(sl.student_id, v.student_id)
           LEFT JOIN parking_slots ps ON ps.id = sl.slot_id
           WHERE ${studentWhere.join(" AND ")}
           ORDER BY sl.scanned_at ASC, sl.id ASC`,
          studentParams
        );
        studentEvents = rows;
      } catch (error) {
        if (!isSchemaCompatibilityError(error)) throw error;
        console.warn("[reports] fallback to legacy student movement query:", error.message);
        const legacyWhere = [
          "sl.result = 'VALID'",
          "sl.action IN ('ENTRY', 'EXIT')",
          "DATE(sl.scanned_at + INTERVAL 8 HOUR) BETWEEN ? AND ?"
        ];
        const legacyParams = [rangeFrom, rangeTo];
        if (safeFilters.gate !== "ALL") {
          legacyWhere.push("COALESCE(sl.gate, 'Unspecified') = ?");
          legacyParams.push(safeFilters.gate);
        }
        if (safeFilters.vehicle_type !== "ALL") {
          legacyWhere.push("COALESCE(NULLIF(TRIM(v.model), ''), 'Unknown') = ?");
          legacyParams.push(safeFilters.vehicle_type);
        }
        studentEvents = await runQueryWithFallback(
          `SELECT
             sl.id,
             sl.scanned_at AS event_time,
             sl.action,
             COALESCE(sl.gate, 'Unspecified') AS gate,
             COALESCE(NULLIF(TRIM(v.model), ''), 'Unknown') AS vehicle_type,
             'student' AS pass_type,
             COALESCE(st.student_number, 'Unknown') AS identity_number,
             COALESCE(st.full_name, 'Unknown Student') AS identity_name,
             COALESCE(v.plate_number, '-') AS plate_number,
             COALESCE(sl.sticker_id, sl.id) AS entity_id,
             DATE_FORMAT(sl.scanned_at + INTERVAL 8 HOUR, '%Y-%m-%d') AS day_key,
             DATE_FORMAT(sl.scanned_at + INTERVAL 8 HOUR, '%H:00') AS hour_slot,
             'Unassigned' AS zone
           FROM scan_logs sl
           LEFT JOIN stickers s ON s.id = sl.sticker_id
           LEFT JOIN vehicles v ON v.id = s.vehicle_id
           LEFT JOIN students st ON st.id = v.student_id
           WHERE ${legacyWhere.join(" AND ")}
           ORDER BY sl.scanned_at ASC, sl.id ASC`,
          legacyParams,
          [],
          "legacy student movement"
        );
      }
    }

    if (safeFilters.pass_type !== "student") {
      visitorEvents = await runQueryWithFallback(
        `SELECT
           vsl.id,
           vsl.scanned_at AS event_time,
           vsl.action,
           COALESCE(vsl.gate, 'Unspecified') AS gate,
           COALESCE(ps.zone, vp.assigned_zone, 'Visitor Zone') AS zone,
           COALESCE(NULLIF(TRIM(vp.vehicle_type), ''), 'Unknown') AS vehicle_type,
           'visitor' AS pass_type,
           COALESCE(vp.pass_code, CONCAT('VIS-', vsl.visitor_pass_id)) AS identity_number,
           COALESCE(vp.visitor_name, 'Visitor') AS identity_name,
           COALESCE(vp.plate_number, '-') AS plate_number,
           COALESCE(vsl.visitor_pass_id, vsl.id) AS entity_id,
           DATE_FORMAT(vsl.scanned_at + INTERVAL 8 HOUR, '%Y-%m-%d') AS day_key,
           DATE_FORMAT(vsl.scanned_at + INTERVAL 8 HOUR, '%H:00') AS hour_slot
         FROM visitor_scan_logs vsl
         JOIN visitor_passes vp ON vp.id = vsl.visitor_pass_id
         LEFT JOIN parking_slots ps ON ps.id = vsl.slot_id
         WHERE ${visitorWhere.join(" AND ")}
         ORDER BY vsl.scanned_at ASC, vsl.id ASC`,
        visitorParams,
        [],
        "visitor movement"
      );
    }

    return [...studentEvents, ...visitorEvents]
      .map((row) => ({
        ...row,
        action: asString(row.action, "VERIFY").toUpperCase(),
        gate: asString(row.gate, "Unspecified"),
        zone: asString(row.zone, "Unassigned"),
        vehicle_type: asString(row.vehicle_type, "Unknown"),
        pass_type: asString(row.pass_type, "student").toLowerCase(),
        identity_number: asString(row.identity_number, "Unknown"),
        identity_name: asString(row.identity_name, "Unknown"),
        plate_number: asString(row.plate_number, "-")
      }))
      .sort(sortByTimeAsc);
  };

  const [events, optionSets, parkingSlotOverview, todayEvents] = await Promise.all([
    fetchMovementEvents(safeFilters.from, safeFilters.to),
    Promise.all([
      runQueryWithFallback(
        `SELECT gate
         FROM (
           SELECT DISTINCT COALESCE(gate, 'Unspecified') AS gate FROM scan_logs
           UNION
           SELECT DISTINCT COALESCE(gate, 'Unspecified') AS gate FROM visitor_scan_logs
         ) g
         WHERE gate IS NOT NULL AND gate <> ''
         ORDER BY gate ASC`,
        [],
        [],
        "gate options (union)"
      ),
      runQueryWithFallback(
        `SELECT DISTINCT COALESCE(zone, 'General') AS zone
         FROM parking_slots
         ORDER BY zone ASC`,
        [],
        [],
        "zone options"
      ),
      runQueryWithFallback(
        `SELECT vehicle_type
         FROM (
           SELECT DISTINCT COALESCE(NULLIF(TRIM(model), ''), 'Unknown') AS vehicle_type FROM vehicles
           UNION
           SELECT DISTINCT COALESCE(NULLIF(TRIM(vehicle_type), ''), 'Unknown') AS vehicle_type FROM visitor_passes
         ) v
         ORDER BY vehicle_type ASC`,
        [],
        [],
        "vehicle options (union)"
      )
    ]),
    getParkingSlotOverview().catch(async (error) => {
      if (!isSchemaCompatibilityError(error)) throw error;
      console.warn("[reports] parking slot overview fallback:", error.message);
      const legacySlots = await runQueryWithFallback(
        `SELECT id, slot_code, zone, status, current_sticker_id
         FROM parking_slots
         ORDER BY zone ASC, slot_code ASC`,
        [],
        [],
        "parking slot legacy overview"
      );
      const slots = legacySlots.map((row) => ({
        id: row.id,
        slot_code: row.slot_code,
        zone: row.zone,
        status: row.status,
        occupancy: row.status !== "available"
          ? "disabled"
          : row.current_sticker_id
          ? "occupied"
          : "available"
      }));
      return { slots, summary: reduceSlotSummary(slots) };
    }),
    fetchMovementEvents(todayDate, todayDate)
  ]);

  const [gateRows, zoneRows, vehicleRows] = optionSets.map((result) => (Array.isArray(result) ? result : []));
  const resolvedGateRows = gateRows.length
    ? gateRows
    : await runQueryWithFallback(
      `SELECT DISTINCT COALESCE(gate, 'Unspecified') AS gate
       FROM scan_logs
       WHERE gate IS NOT NULL AND gate <> ''
       ORDER BY gate ASC`,
      [],
      [],
      "gate options (legacy)"
    );
  const resolvedVehicleRows = vehicleRows.length
    ? vehicleRows
    : await runQueryWithFallback(
      `SELECT DISTINCT COALESCE(NULLIF(TRIM(model), ''), 'Unknown') AS vehicle_type
       FROM vehicles
       ORDER BY vehicle_type ASC`,
      [],
      [],
      "vehicle options (legacy)"
    );
  const filterOptions = {
    gates: resolvedGateRows.map((row) => asString(row.gate, "Unspecified")),
    zones: zoneRows.map((row) => asString(row.zone, "General")),
    vehicleTypes: resolvedVehicleRows.map((row) => asString(row.vehicle_type, "Unknown")),
    passTypes: [
      { value: "all", label: "All Pass Types" },
      { value: "student", label: "Students" },
      { value: "visitor", label: "Visitors / Temporary" }
    ]
  };

  const scopedSlots = parkingSlotOverview.slots.filter((slot) => {
    const zone = asString(slot.zone, "General");
    if (safeFilters.zone !== "ALL") return zone === safeFilters.zone;
    if (safeFilters.pass_type === "student") return !isVisitorZone(zone);
    if (safeFilters.pass_type === "visitor") return isVisitorZone(zone);
    return true;
  });
  const slotSummary = reduceSlotSummary(scopedSlots);

  const entryEvents = events.filter((row) => row.action === "ENTRY");
  const exitEvents = events.filter((row) => row.action === "EXIT");
  const todayEntryEvents = todayEvents.filter((row) => row.action === "ENTRY");
  const todayEventsByHour = aggregateCounts(todayEvents, (row) => row.hour_slot || "00:00");
  const busiestHourToday = Array.from(todayEventsByHour.entries())
    .sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0))[0] || null;

  const hourlyMap = aggregateCounts(events, (row) => row.hour_slot || "00:00");
  const busiestHours = mapToSeries(hourlyMap, "total");
  const busiestHourOverall = busiestHours
    .slice()
    .sort((a, b) => Number(b.total || 0) - Number(a.total || 0))[0] || null;

  const gateMap = aggregateCounts(events, (row) => row.gate || "Unspecified");
  const gateUsage = mapToSeries(gateMap, "total")
    .sort((a, b) => Number(b.total || 0) - Number(a.total || 0));

  const zoneMap = aggregateCounts(entryEvents, (row) => row.zone || "Unassigned");
  const zoneUsageRaw = mapToSeries(zoneMap, "total")
    .sort((a, b) => Number(b.total || 0) - Number(a.total || 0));
  const totalZoneEntries = zoneUsageRaw.reduce((sum, row) => sum + Number(row.total || 0), 0);
  const zoneUsage = zoneUsageRaw.map((row) => ({
    zone: row.bucket,
    total: row.total,
    percent: totalZoneEntries > 0 ? Number(((row.total / totalZoneEntries) * 100).toFixed(1)) : 0
  }));
  const mostUsedZone = zoneUsage[0] || null;
  const leastUsedZone = zoneUsage.length ? zoneUsage[zoneUsage.length - 1] : null;

  const dailyPeakMap = new Map();
  events.forEach((row) => {
    const dayKey = row.day_key || "Unknown";
    const hourSlot = row.hour_slot || "00:00";
    const dayData = dailyPeakMap.get(dayKey) || new Map();
    dayData.set(hourSlot, Number(dayData.get(hourSlot) || 0) + 1);
    dailyPeakMap.set(dayKey, dayData);
  });
  const peakHoursByDay = Array.from(dailyPeakMap.entries())
    .map(([day, hourMapLocal]) => {
      const best = Array.from(hourMapLocal.entries()).sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0))[0] || ["00:00", 0];
      return {
        day,
        hour_slot: best[0],
        total: Number(best[1] || 0)
      };
    })
    .sort((a, b) => String(a.day).localeCompare(String(b.day)))
    .slice(-31);

  const eventsByEntity = new Map();
  events.forEach((row) => {
    const key = `${row.pass_type}:${row.entity_id}:${row.identity_number}`;
    if (!eventsByEntity.has(key)) {
      eventsByEntity.set(key, []);
    }
    eventsByEntity.get(key).push(row);
  });

  const sessions = [];
  eventsByEntity.forEach((entityRows) => {
    const sorted = entityRows.slice().sort(sortByTimeAsc);
    let openEntry = null;
    sorted.forEach((row) => {
      if (row.action === "ENTRY") {
        openEntry = row;
        return;
      }
      if (row.action !== "EXIT" || !openEntry) return;
      const durationMinutes = Math.max(0, Math.floor((toTimeValue(row.event_time) - toTimeValue(openEntry.event_time)) / 60000));
      const threshold = openEntry.pass_type === "visitor" ? VISITOR_OVERSTAY_MINUTES : OVERSTAY_LIMIT_MINUTES;
      const overstayMinutes = Math.max(0, durationMinutes - threshold);
      sessions.push({
        pass_type: openEntry.pass_type,
        identity_number: openEntry.identity_number,
        identity_name: openEntry.identity_name,
        plate_number: openEntry.plate_number,
        vehicle_type: openEntry.vehicle_type,
        zone: openEntry.zone,
        gate: openEntry.gate,
        entry_at: openEntry.event_time,
        exit_at: row.event_time,
        duration_minutes: durationMinutes,
        duration_label: formatDurationMinutes(durationMinutes),
        overstay_limit_minutes: threshold,
        overstay_minutes: overstayMinutes,
        is_overstay: overstayMinutes > 0
      });
      openEntry = null;
    });
  });

  const completedSessionCount = sessions.length;
  const avgDurationMinutes = completedSessionCount
    ? Math.round(sessions.reduce((sum, row) => sum + Number(row.duration_minutes || 0), 0) / completedSessionCount)
    : 0;

  const durationByZoneMap = new Map();
  sessions.forEach((row) => {
    const zone = asString(row.zone, "Unassigned");
    const current = durationByZoneMap.get(zone) || { zone, total_minutes: 0, sessions: 0 };
    current.total_minutes += Number(row.duration_minutes || 0);
    current.sessions += 1;
    durationByZoneMap.set(zone, current);
  });
  const durationByZone = Array.from(durationByZoneMap.values())
    .map((row) => {
      const avgMinutes = row.sessions > 0 ? Math.round(row.total_minutes / row.sessions) : 0;
      return {
        zone: row.zone,
        sessions: row.sessions,
        avg_minutes: avgMinutes,
        avg_label: formatDurationMinutes(avgMinutes)
      };
    })
    .sort((a, b) => Number(b.sessions || 0) - Number(a.sessions || 0));

  const overstaySessions = sessions.filter((row) => row.is_overstay);
  const overstayByDay = mapToSeries(aggregateCounts(overstaySessions, (row) => toDateOnly(row.exit_at) || "Unknown"), "total");
  const overstayByWeek = mapToSeries(aggregateCounts(overstaySessions, (row) => computeWeekKey(row.exit_at)), "total");
  const overstayByMonth = mapToSeries(aggregateCounts(overstaySessions, (row) => {
    const dt = toDateOnly(row.exit_at);
    return dt ? dt.slice(0, 7) : "Unknown";
  }), "total");

  const repeatOverstayMap = new Map();
  overstaySessions.forEach((row) => {
    const key = `${row.pass_type}:${row.identity_number}:${row.identity_name}`;
    const current = repeatOverstayMap.get(key) || {
      pass_type: row.pass_type,
      identity_number: row.identity_number,
      identity_name: row.identity_name,
      plate_number: row.plate_number,
      overstay_count: 0,
      total_overstay_minutes: 0
    };
    current.overstay_count += 1;
    current.total_overstay_minutes += Number(row.overstay_minutes || 0);
    repeatOverstayMap.set(key, current);
  });
  const repeatOverstays = Array.from(repeatOverstayMap.values())
    .filter((row) => row.overstay_count > 1)
    .sort((a, b) => Number(b.overstay_count || 0) - Number(a.overstay_count || 0))
    .slice(0, 10)
    .map((row) => ({
      ...row,
      total_overstay_label: formatDurationMinutes(row.total_overstay_minutes)
    }));

  const fromDate = new Date(`${safeFilters.from}T00:00:00Z`);
  const toDate = new Date(`${safeFilters.to}T00:00:00Z`);
  const rangeDays = Math.max(1, Math.floor((toDate.getTime() - fromDate.getTime()) / 86400000) + 1);
  const trendGranularity = rangeDays <= 2 ? "hour" : "day";
  const bucketList = [];
  if (trendGranularity === "hour") {
    const cursor = new Date(fromDate);
    const end = new Date(toDate);
    end.setUTCHours(23, 0, 0, 0);
    while (cursor.getTime() <= end.getTime()) {
      const yyyy = cursor.getUTCFullYear();
      const mm = String(cursor.getUTCMonth() + 1).padStart(2, "0");
      const dd = String(cursor.getUTCDate()).padStart(2, "0");
      const hh = String(cursor.getUTCHours()).padStart(2, "0");
      bucketList.push(`${yyyy}-${mm}-${dd} ${hh}:00`);
      cursor.setUTCHours(cursor.getUTCHours() + 1);
    }
  } else {
    const cursor = new Date(fromDate);
    const end = new Date(toDate);
    while (cursor.getTime() <= end.getTime()) {
      const yyyy = cursor.getUTCFullYear();
      const mm = String(cursor.getUTCMonth() + 1).padStart(2, "0");
      const dd = String(cursor.getUTCDate()).padStart(2, "0");
      bucketList.push(`${yyyy}-${mm}-${dd}`);
      cursor.setUTCDate(cursor.getUTCDate() + 1);
    }
  }

  const trendBase = new Map();
  events.forEach((row) => {
    const bucket = trendGranularity === "hour"
      ? `${row.day_key || "Unknown"} ${row.hour_slot || "00:00"}`
      : (row.day_key || "Unknown");
    const current = trendBase.get(bucket) || { entries: 0, exits: 0 };
    if (row.action === "ENTRY") current.entries += 1;
    if (row.action === "EXIT") current.exits += 1;
    trendBase.set(bucket, current);
  });

  const totalSlotsNow = Number(slotSummary.total || 0);
  const occupiedNow = Number(slotSummary.occupied || 0);
  const netRangeDelta = entryEvents.length - exitEvents.length;
  let estimatedOccupied = Math.max(0, Math.min(totalSlotsNow, occupiedNow - netRangeDelta));
  const slotTrends = bucketList.map((bucket) => {
    const base = trendBase.get(bucket) || { entries: 0, exits: 0 };
    estimatedOccupied = Math.max(0, Math.min(totalSlotsNow, estimatedOccupied + base.entries - base.exits));
    const available = Math.max(0, totalSlotsNow - estimatedOccupied);
    return {
      bucket,
      entries: base.entries,
      exits: base.exits,
      occupied: estimatedOccupied,
      available
    };
  });

  const lowSlotThreshold = Math.max(1, Math.ceil(totalSlotsNow * 0.15));
  const underusedThreshold = Math.floor(totalSlotsNow * 0.35);
  const slotStateMoments = slotTrends.reduce(
    (acc, row) => {
      if (totalSlotsNow <= 0) return acc;
      if (row.available <= 0) acc.full += 1;
      else if (row.available <= lowSlotThreshold) acc.nearly_full += 1;
      if (row.occupied <= underusedThreshold) acc.underused += 1;
      return acc;
    },
    { full: 0, nearly_full: 0, underused: 0 }
  );

  const movementRows = events
    .slice()
    .sort(sortByTimeDesc)
    .slice(0, 200);

  const summary = {
    total_vehicles_today: todayEntryEvents.length,
    active_parked_vehicles: Number(slotSummary.occupied || 0),
    busiest_hour_today: busiestHourToday ? `${busiestHourToday[0]} (${busiestHourToday[1]})` : "No data",
    busiest_hour_overall: busiestHourOverall ? `${busiestHourOverall.bucket} (${busiestHourOverall.total})` : "No data",
    most_used_zone: mostUsedZone ? `${mostUsedZone.zone} (${mostUsedZone.total})` : "No data",
    least_used_zone: leastUsedZone ? `${leastUsedZone.zone} (${leastUsedZone.total})` : "No data",
    average_parking_duration_minutes: avgDurationMinutes,
    average_parking_duration_label: completedSessionCount ? formatDurationMinutes(avgDurationMinutes) : "No completed sessions",
    total_overstay_cases: overstaySessions.length,
    available_slots_now: Number(slotSummary.available || 0),
    total_slots_now: totalSlotsNow,
    completed_sessions: completedSessionCount,
    zone_full_moments: slotStateMoments.full,
    zone_nearly_full_moments: slotStateMoments.nearly_full,
    zone_underused_moments: slotStateMoments.underused,
    overstay_limit_label: formatHoursLabel(OVERSTAY_LIMIT_HOURS),
    visitor_overstay_limit_label: formatHoursLabel(VISITOR_OVERSTAY_HOURS)
  };

  const exportRows = events
    .slice()
    .sort(sortByTimeDesc)
    .map((row) => ({
    scanned_at: row.event_time,
    pass_type: row.pass_type,
    identity_number: row.identity_number,
    identity_name: row.identity_name,
    plate_number: row.plate_number,
    vehicle_type: row.vehicle_type,
    zone: row.zone,
    gate: row.gate,
    action: row.action
  }));

  return {
    filters: {
      ...safeFilters,
      query_string: getReportQueryString(safeFilters),
      range_label: `${safeFilters.from} to ${safeFilters.to}`
    },
    filterOptions,
    summary,
    charts: {
      busiestHours,
      gateUsage,
      zoneUsage,
      slotTrends,
      overstayByDay,
      overstayByWeek,
      overstayByMonth
    },
    tables: {
      peakHoursByDay,
      durationByZone,
      repeatOverstays,
      sessions: sessions
        .slice()
        .sort((a, b) => toTimeValue(b.exit_at) - toTimeValue(a.exit_at))
        .slice(0, 80),
      movementRows
    },
    exportRows,
    metadata: {
      trend_granularity: trendGranularity,
      range_days: rangeDays
    }
  };
}

async function getGuardDashboardData() {
  await refreshOperationalState("guard-dashboard");
  const visitorLogsPromise = pool.query(
    `SELECT
       vsl.scanned_at,
       vsl.action,
       vsl.result,
       vsl.gate,
       vsl.gate_id,
       ps.slot_code AS parking_slot,
       vp.pass_code,
       vp.visitor_name,
       vp.visitor_type,
       vp.plate_number
     FROM visitor_scan_logs vsl
     JOIN visitor_passes vp ON vp.id = vsl.visitor_pass_id
     LEFT JOIN parking_slots ps ON ps.id = vsl.slot_id
     ORDER BY vsl.scanned_at DESC, vsl.id DESC
     LIMIT 40`
  ).then(([rows]) => rows);
  const [
    alertMetrics,
    visitorMetrics,
    insideMetrics,
    insideVehicles,
    parkingSlotOverview,
    todayMovement,
    visitorLogs
  ] = await Promise.all([
    getOperationalAlertMetrics(pool),
    getVisitorSummaryMetrics(pool),
    getInsideVehicleMetrics(pool),
    getInsideVehiclesWithOverstay(pool, 20),
    getParkingSlotOverview(pool),
    getTodayMovementCounts(pool),
    visitorLogsPromise
  ]);
  const overstayAlerts = insideVehicles.filter((item) => item.is_overstay);

  return {
    metrics: {
      todayEntries: todayMovement.entries,
      todayExits: todayMovement.exits,
      currentlyInside: insideMetrics.total_inside,
      overstayAlerts: insideMetrics.overstay_count,
      pendingApprovals: Number(alertMetrics.pending_approvals || 0),
      invalidScans: Number(alertMetrics.invalid_qr_today || 0),
      fullParkingZones: Number(alertMetrics.full_parking_zones || 0),
      lowSlotWarnings: Number(alertMetrics.low_slot_warnings || 0),
      suspiciousScans: Number(alertMetrics.suspicious_scans || 0),
      visitorActivePasses: visitorMetrics.active_passes,
      visitorPendingApprovals: visitorMetrics.pending_approvals,
      visitorExpiredPasses: visitorMetrics.expired_passes,
      visitorCurrentlyInside: visitorMetrics.current_inside
    },
    insideVehicles,
    overstayAlerts,
    visitorLogs,
    parkingSlotSummary: parkingSlotOverview.summary,
    overstayLimitLabel: formatHoursLabel(OVERSTAY_LIMIT_HOURS)
  };
}

async function getAvailableParkingSlots(db = pool, options = {}) {
  const scope = String(options.scope || "all").toLowerCase();
  const where = [
    "status = 'available'",
    "current_sticker_id IS NULL",
    "current_visitor_pass_id IS NULL"
  ];
  const params = [];
  if (scope === "visitor") {
    where.push("zone LIKE 'Visitor%'");
  }

  const [rows] = await db.query(
    `SELECT id, slot_code, zone, slot_type, reserved_for
     FROM parking_slots
     WHERE ${where.join(" AND ")}
     ORDER BY zone ASC, slot_code ASC`,
    params
  );
  return rows;
}

async function getParkingSlotOverview(db = pool, options = {}) {
  const scope = String(options.scope || "all").toLowerCase();
  const whereSql = scope === "visitor"
    ? "WHERE ps.zone LIKE 'Visitor%'"
    : "";

  const [rows] = await db.query(
    `SELECT
       ps.id,
       ps.slot_code,
       ps.zone,
       ps.slot_type,
       ps.reserved_for,
       ps.status,
       ps.disabled_reason,
       ps.current_sticker_id,
       ps.current_visitor_pass_id,
       st.full_name AS occupied_by_name,
       v.plate_number AS occupied_by_plate,
       vp.visitor_name AS occupied_by_visitor_name,
       vp.plate_number AS occupied_by_visitor_plate,
       vp.pass_code AS occupied_by_visitor_pass_code
     FROM parking_slots ps
     LEFT JOIN stickers s ON s.id = ps.current_sticker_id
     LEFT JOIN vehicles v ON v.id = s.vehicle_id
     LEFT JOIN students st ON st.id = v.student_id
     LEFT JOIN visitor_passes vp ON vp.id = ps.current_visitor_pass_id
     ${whereSql}
     ORDER BY ps.zone ASC, ps.slot_code ASC`
  );

  const slots = rows.map((row) => {
    const occupancy = row.status !== "available"
      ? "disabled"
      : row.current_sticker_id || row.current_visitor_pass_id
      ? "occupied"
      : "available";
    return {
      id: row.id,
      slot_code: row.slot_code,
      zone: row.zone,
      slot_type: row.slot_type || "standard",
      reserved_for: row.reserved_for || null,
      status: row.status,
      disabled_reason: row.disabled_reason || null,
      occupancy,
      is_selectable: occupancy === "available",
      occupied_by_name: row.occupied_by_name || row.occupied_by_visitor_name || null,
      occupied_by_plate: row.occupied_by_plate || row.occupied_by_visitor_plate || null,
      occupied_by_type: row.current_sticker_id ? "student" : row.current_visitor_pass_id ? "visitor" : null,
      occupied_by_visitor_pass_code: row.occupied_by_visitor_pass_code || null
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
    `SELECT id, slot_code, zone, status, current_sticker_id, current_visitor_pass_id
     FROM parking_slots
     WHERE id = ?
     FOR UPDATE`,
    [slotId]
  );

  if (slotRows.length === 0) {
    throw new Error("Selected parking slot does not exist.");
  }

  const slot = slotRows[0];
  if (slot.status !== "available" || slot.current_sticker_id || slot.current_visitor_pass_id) {
    const [[zoneState]] = await db.query(
      `SELECT
         COUNT(*) AS total_slots,
         SUM(CASE WHEN status = 'available' AND current_sticker_id IS NULL AND current_visitor_pass_id IS NULL THEN 1 ELSE 0 END) AS available_slots
       FROM parking_slots
       WHERE zone = ?`,
      [slot.zone || "General"]
    );
    const availableInZone = Number(zoneState?.available_slots || 0);
    if (availableInZone <= 0) {
      throw new Error(`Zone ${slot.zone || "General"} is already full. Please choose another zone.`);
    }
    if (slot.status !== "available") {
      throw new Error("Selected parking slot is disabled.");
    }
    if (slot.current_sticker_id) {
      throw new Error("Selected parking slot is already occupied.");
    }
    if (slot.current_visitor_pass_id) {
      throw new Error("Selected parking slot is occupied by a visitor pass.");
    }
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
    await createInvalidQrAlert(pool, {
      result: "INVALID",
      reason: "QR token not found in registered stickers.",
      qrValue: token,
      gate,
      source: "scanner",
      actorName: "system",
      scanLogId: scanLog?.id || null
    });
    await evaluateSuspiciousScanSignals(pool, {
      qrValue: token,
      gate,
      source: "scanner",
      actorName: "system",
      result: "INVALID",
      scanLogId: scanLog?.id || null
    });
    broadcastNotificationsUpdated("invalid-qr", {
      gate_id: gate,
      qr_value: token,
      result: "INVALID"
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
    await createInvalidQrAlert(pool, {
      result: "REVOKED",
      reason: "Sticker is revoked and no longer allowed for entry.",
      qrValue: token,
      gate,
      source: "scanner",
      actorName: "system",
      relatedVehicleId: verification.sticker?.vehicle_id_ref || verification.sticker?.vehicle_id || null,
      scanLogId: scanLog?.id || null
    });
    await evaluateSuspiciousScanSignals(pool, {
      qrValue: token,
      gate,
      source: "scanner",
      actorName: "system",
      result: "REVOKED",
      scanLogId: scanLog?.id || null
    });
    broadcastNotificationsUpdated("invalid-qr", {
      gate_id: gate,
      qr_value: token,
      result: "REVOKED"
    });
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
    await createInvalidQrAlert(pool, {
      result: "EXPIRED",
      reason: "Sticker has expired and requires renewal.",
      qrValue: token,
      gate,
      source: "scanner",
      actorName: "system",
      relatedVehicleId: verification.sticker?.vehicle_id_ref || verification.sticker?.vehicle_id || null,
      scanLogId: scanLog?.id || null
    });
    await evaluateSuspiciousScanSignals(pool, {
      qrValue: token,
      gate,
      source: "scanner",
      actorName: "system",
      result: "EXPIRED",
      scanLogId: scanLog?.id || null
    });
    broadcastNotificationsUpdated("invalid-qr", {
      gate_id: gate,
      qr_value: token,
      result: "EXPIRED"
    });
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
      await reportDuplicateScan({
        qrValue: token,
        gate,
        source: "scanner",
        actorName: "system",
        deniedReason: `Duplicate scan blocked within ${SCAN_COOLDOWN_SECONDS} seconds cooldown.`
      });
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
    await evaluateZoneCapacityAlerts(pool, "resolve-scan");
    broadcastNotificationsUpdated("movement-recorded", {
      movement_action: action,
      gate_id: gate,
      qr_value: token
    });

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

// ─── Routes ─────────────────────────────────────────────────────────────────

const SCANNER_METRIC_OUTCOMES = new Set([
  "SUCCESS", "INVALID", "DUPLICATE", "ERROR", "CAMERA_ERROR", "OFFLINE_QUEUED", "CANCELLED"
]);

function clampMetricNumber(value, min, max, integer = false) {
  const number = Number(value);
  if (!Number.isFinite(number)) return null;
  const clamped = Math.max(min, Math.min(max, number));
  return integer ? Math.round(clamped) : Math.round(clamped * 100000) / 100000;
}

function normalizeClientEventId(value, prefix) {
  const eventId = String(value || "")
    .replace(/[^a-z0-9._:-]/gi, "")
    .slice(0, 80);
  return eventId || `${String(prefix || "event")}-${crypto.randomUUID()}`;
}

function normalizeScannerMetricPayload(payload, req) {
  const data = payload && typeof payload === "object" ? payload : {};
  const rawOutcome = String(data.outcome || "ERROR").trim().toUpperCase();
  const rawOccurredAt = new Date(data.occurred_at || Date.now());
  const action = String(data.movement_action || "").trim().toUpperCase();
  return {
    eventId: normalizeClientEventId(data.event_id, "metric"),
    deviceId: String(data.device_id || "").slice(0, 120) || null,
    gateId: normalizeGateId(data.gate_id || data.gate || "Main Gate"),
    outcome: SCANNER_METRIC_OUTCOMES.has(rawOutcome) ? rawOutcome : "ERROR",
    movementAction: ["ENTRY", "EXIT", "VERIFY"].includes(action) ? action : null,
    detectionModel: String(data.detection_model || data.model || "").slice(0, 80) || null,
    detectionConfidence: clampMetricNumber(data.detection_confidence ?? data.confidence, 0, 1),
    readinessScore: clampMetricNumber(data.readiness_score ?? data.readiness, 0, 1),
    processMs: clampMetricNumber(data.process_ms, 0, 120000, true),
    timeToReadMs: clampMetricNumber(data.time_to_read_ms, 0, 10 * 60 * 1000, true),
    unreadableFrames: clampMetricNumber(data.unreadable_frames, 0, 100000, true) || 0,
    guidanceKey: String(data.guidance_key || "").replace(/[^a-z0-9_-]/gi, "").slice(0, 40) || null,
    failureReason: String(data.failure_reason || "").replace(/[\r\n\t]+/g, " ").slice(0, 120) || null,
    networkMode: String(data.network_mode || "online").toLowerCase() === "offline" ? "offline" : "online",
    deviceClass: String(data.device_class || "unknown").replace(/[^a-z0-9_-]/gi, "").slice(0, 30),
    browserFamily: getBrowserFamily(req.get("user-agent")),
    learningSamples: clampMetricNumber(data.learning_samples, 0, 1000000, true) || 0,
    userId: Number(req.authUser?.id) || null,
    occurredAt: Number.isNaN(rawOccurredAt.getTime()) ? new Date() : rawOccurredAt
  };
}

async function insertScannerMetric(metric, db = pool) {
  const [result] = await db.query(
    `INSERT IGNORE INTO scanner_metrics (
       event_id, device_id, gate_id, outcome, movement_action, detection_model,
       detection_confidence, readiness_score, process_ms, time_to_read_ms,
       unreadable_frames, guidance_key, failure_reason, network_mode,
       device_class, browser_family, learning_samples, user_id, occurred_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      metric.eventId, metric.deviceId, metric.gateId, metric.outcome, metric.movementAction,
      metric.detectionModel, metric.detectionConfidence, metric.readinessScore,
      metric.processMs, metric.timeToReadMs, metric.unreadableFrames, metric.guidanceKey,
      metric.failureReason, metric.networkMode, metric.deviceClass, metric.browserFamily,
      metric.learningSamples, metric.userId, metric.occurredAt
    ]
  );
  return Number(result.affectedRows) > 0;
}

async function getScannerAnalytics(days = 30, gate = "") {
  const safeDays = [7, 30, 90].includes(Number(days)) ? Number(days) : 30;
  const safeGate = String(gate || "").trim().slice(0, 80);
  const conditions = ["created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)"];
  const params = [safeDays];
  if (safeGate) {
    conditions.push("gate_id = ?");
    params.push(safeGate);
  }
  const whereSql = conditions.join(" AND ");
  const [summaryRows, outcomeRows, failureRows, gateRows, dailyRows, deviceRows, recentRows, gateOptionRows] = await Promise.all([
    pool.query(
      `SELECT COUNT(*) AS total, SUM(outcome = 'SUCCESS') AS successful,
              AVG(time_to_read_ms) AS avg_time_to_read_ms,
              AVG(detection_confidence) AS avg_confidence,
              AVG(readiness_score) AS avg_readiness,
              SUM(network_mode = 'offline') AS offline_count
       FROM scanner_metrics WHERE ${whereSql}`,
      params
    ),
    pool.query(`SELECT outcome, COUNT(*) AS total FROM scanner_metrics WHERE ${whereSql} GROUP BY outcome ORDER BY total DESC`, params),
    pool.query(
      `SELECT COALESCE(failure_reason, guidance_key, 'Unspecified') AS reason, COUNT(*) AS total
       FROM scanner_metrics WHERE ${whereSql} AND outcome <> 'SUCCESS'
       GROUP BY reason ORDER BY total DESC LIMIT 8`,
      params
    ),
    pool.query(`SELECT gate_id, COUNT(*) AS total, SUM(outcome = 'SUCCESS') AS successful FROM scanner_metrics WHERE ${whereSql} GROUP BY gate_id ORDER BY total DESC`, params),
    pool.query(
      `SELECT DATE(created_at) AS day, COUNT(*) AS total, SUM(outcome = 'SUCCESS') AS successful,
              AVG(time_to_read_ms) AS avg_time_to_read_ms
       FROM scanner_metrics WHERE ${whereSql} GROUP BY DATE(created_at) ORDER BY day ASC`,
      params
    ),
    pool.query(
      `SELECT device_class, browser_family, COUNT(*) AS total, SUM(outcome = 'SUCCESS') AS successful
       FROM scanner_metrics WHERE ${whereSql}
       GROUP BY device_class, browser_family ORDER BY total DESC LIMIT 12`,
      params
    ),
    pool.query(
      `SELECT outcome, movement_action, gate_id, detection_confidence, readiness_score,
              time_to_read_ms, failure_reason, device_class, browser_family, network_mode, created_at
       FROM scanner_metrics WHERE ${whereSql} ORDER BY created_at DESC, id DESC LIMIT 40`,
      params
    ),
    pool.query("SELECT DISTINCT gate_id FROM scanner_metrics WHERE gate_id IS NOT NULL ORDER BY gate_id")
  ]);
  const summary = summaryRows[0][0] || {};
  const total = Number(summary.total) || 0;
  const successful = Number(summary.successful) || 0;
  return {
    filters: { days: safeDays, gate: safeGate },
    summary: {
      total,
      successful,
      success_rate: total ? Math.round((successful / total) * 1000) / 10 : 0,
      avg_time_to_read_ms: Math.round(Number(summary.avg_time_to_read_ms) || 0),
      avg_confidence: Number(summary.avg_confidence) || 0,
      avg_readiness: Number(summary.avg_readiness) || 0,
      offline_count: Number(summary.offline_count) || 0
    },
    outcomes: outcomeRows[0], failures: failureRows[0], gates: gateRows[0], daily: dailyRows[0],
    devices: deviceRows[0], recent: recentRows[0],
    gateOptions: gateOptionRows[0].map((row) => row.gate_id)
  };
}

const DATASET_DEFINITIONS = Object.freeze({
  students: {
    label: "Students",
    importable: true,
    columns: ["student_number", "full_name", "program", "year_level", "email"]
  },
  vehicles: {
    label: "Vehicles",
    importable: true,
    columns: ["plate_number", "student_number", "model", "color"]
  },
  parking_slots: {
    label: "Parking Slots",
    importable: true,
    columns: ["slot_code", "zone", "slot_type", "reserved_for", "status", "disabled_reason"]
  },
  stickers: {
    label: "Parking Stickers",
    importable: true,
    encryptedOnly: true,
    columns: ["sticker_code", "qr_token", "plate_number", "status", "expires_at"]
  },
  visitor_passes: {
    label: "Visitor Passes",
    importable: true,
    columns: ["pass_code", "qr_token", "visitor_type", "visitor_name", "organization", "contact_number", "plate_number", "vehicle_type", "purpose", "approval_status", "pass_state", "valid_from", "valid_until", "assigned_zone"]
  },
  scan_logs: { label: "Student Gate Records", importable: false },
  visitor_scan_logs: { label: "Visitor Gate Records", importable: false },
  scanner_metrics: { label: "Scanner Performance", importable: false },
  security_audit: { label: "Security Audit", importable: false }
});
const RECOVERY_DATASET_ORDER = Object.freeze([
  "students",
  "vehicles",
  "parking_slots",
  "stickers",
  "visitor_passes",
  "scan_logs",
  "visitor_scan_logs",
  "security_audit"
]);

const STUDENT_IMPORT_MAX_ROWS = 2000;
const STUDENT_IMPORT_MAX_BYTES = 2 * 1024 * 1024;
const STUDENT_IMPORT_PREVIEW_TTL_MS = 15 * 60 * 1000;

function parseStudentImportCsv(csvData) {
  const text = String(csvData || "");
  if (Buffer.byteLength(text, "utf8") > STUDENT_IMPORT_MAX_BYTES) {
    throw new Error("The CSV file is too large. Maximum size is 2 MB.");
  }
  const document = parseCsvDocument(text, { maxRows: STUDENT_IMPORT_MAX_ROWS });
  if (!document.records.length) throw new Error("The CSV does not contain any data rows.");
  return document;
}

async function getExistingStudentNumbers(document, db = pool) {
  const studentNumbers = Array.from(new Set(
    document.records
      .map((row) => String(row.student_number || "").trim())
      .filter(Boolean)
  ));
  if (!studentNumbers.length) return new Set();
  const placeholders = studentNumbers.map(() => "?").join(", ");
  const [rows] = await db.query(
    `SELECT student_number FROM students WHERE student_number IN (${placeholders})`,
    studentNumbers
  );
  return new Set(rows.map((row) => String(row.student_number || "").trim().toUpperCase()));
}

function getStudentImportDigest(csvData) {
  return crypto.createHash("sha256").update(String(csvData || ""), "utf8").digest("hex");
}

function createStudentImportPreviewToken(req, csvData) {
  const timestamp = Date.now();
  const message = `${req.authUser.id}|${timestamp}|${getStudentImportDigest(csvData)}`;
  const signature = crypto.createHmac("sha256", SESSION_SECRET).update(message).digest("hex");
  return `${timestamp}.${signature}`;
}

function verifyStudentImportPreviewToken(req, csvData, token) {
  const match = String(token || "").match(/^(\d{13})\.([a-f0-9]{64})$/);
  if (!match) return false;
  const timestamp = Number(match[1]);
  const age = Date.now() - timestamp;
  if (!Number.isFinite(timestamp) || age < -30000 || age > STUDENT_IMPORT_PREVIEW_TTL_MS) return false;
  const message = `${req.authUser.id}|${timestamp}|${getStudentImportDigest(csvData)}`;
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(message).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(match[2], "hex"), Buffer.from(expected, "hex"));
}

async function saveStudentImportRows(rows, db, options = {}) {
  const updateEmail = options.updateEmail !== false;
  const batchSize = 100;
  for (let start = 0; start < rows.length; start += batchSize) {
    const batch = rows.slice(start, start + batchSize);
    const placeholders = batch.map(() => "(?, ?, ?, ?, ?)").join(", ");
    const values = batch.flatMap((row) => [
      row.studentNumber,
      row.fullName,
      row.program,
      row.yearLevel,
      row.email || null
    ]);
    await db.query(
      `INSERT INTO students (student_number, full_name, program, year_level, email)
       VALUES ${placeholders}
       ON DUPLICATE KEY UPDATE full_name = VALUES(full_name), program = VALUES(program),
         year_level = VALUES(year_level), email = ${updateEmail ? "VALUES(email)" : "email"}`,
      values
    );
  }
}

async function getDatasetExport(dataset, db = pool) {
  switch (dataset) {
    case "students": {
      const [rows] = await db.query("SELECT student_number, full_name, program, year_level, email FROM students ORDER BY student_number");
      return { columns: DATASET_DEFINITIONS.students.columns, rows };
    }
    case "vehicles": {
      const [rows] = await db.query(
        `SELECT v.plate_number, s.student_number, v.model, v.color
         FROM vehicles v JOIN students s ON s.id = v.student_id ORDER BY v.plate_number`
      );
      return { columns: DATASET_DEFINITIONS.vehicles.columns, rows };
    }
    case "parking_slots": {
      const [rows] = await db.query(
        `SELECT slot_code, zone, slot_type, reserved_for, status, disabled_reason
         FROM parking_slots ORDER BY zone, slot_code`
      );
      return { columns: DATASET_DEFINITIONS.parking_slots.columns, rows };
    }
    case "stickers": {
      const [rows] = await db.query(
        `SELECT st.sticker_code, st.qr_token, v.plate_number, st.status, st.expires_at
         FROM stickers st
         JOIN vehicles v ON v.id = st.vehicle_id
         ORDER BY st.created_at DESC, st.id DESC`
      );
      return { columns: DATASET_DEFINITIONS.stickers.columns, rows };
    }
    case "visitor_passes": {
      const [rows] = await db.query(
        `SELECT pass_code, qr_token, visitor_type, visitor_name, organization, contact_number,
                plate_number, vehicle_type, purpose, approval_status, pass_state,
                valid_from, valid_until, assigned_zone
         FROM visitor_passes ORDER BY created_at DESC`
      );
      return { columns: DATASET_DEFINITIONS.visitor_passes.columns, rows };
    }
    case "scan_logs": {
      const columns = ["scanned_at", "result", "action", "gate_id", "student_number", "plate_number", "slot_code", "scan_source", "status", "notes"];
      const [rows] = await db.query(
        `SELECT sl.scanned_at, sl.result, sl.action, sl.gate_id, st.student_number,
                v.plate_number, ps.slot_code, sl.scan_source, sl.status, sl.notes
         FROM scan_logs sl
         LEFT JOIN students st ON st.id = sl.student_id
         LEFT JOIN vehicles v ON v.id = sl.vehicle_id
         LEFT JOIN parking_slots ps ON ps.id = sl.slot_id
         ORDER BY sl.scanned_at DESC, sl.id DESC`
      );
      return { columns, rows };
    }
    case "visitor_scan_logs": {
      const columns = ["scanned_at", "pass_code", "visitor_name", "plate_number", "result", "action", "gate_id", "slot_code", "scan_source", "status", "reason"];
      const [rows] = await db.query(
        `SELECT vsl.scanned_at, vp.pass_code, vp.visitor_name, vp.plate_number,
                vsl.result, vsl.action, vsl.gate_id, ps.slot_code, vsl.scan_source, vsl.status, vsl.reason
         FROM visitor_scan_logs vsl
         JOIN visitor_passes vp ON vp.id = vsl.visitor_pass_id
         LEFT JOIN parking_slots ps ON ps.id = vsl.slot_id
         ORDER BY vsl.scanned_at DESC, vsl.id DESC`
      );
      return { columns, rows };
    }
    case "scanner_metrics": {
      const columns = ["created_at", "gate_id", "outcome", "movement_action", "detection_model", "detection_confidence", "readiness_score", "process_ms", "time_to_read_ms", "unreadable_frames", "guidance_key", "failure_reason", "network_mode", "device_class", "browser_family"];
      const [rows] = await db.query(`SELECT ${columns.join(", ")} FROM scanner_metrics ORDER BY created_at DESC, id DESC`);
      return { columns, rows };
    }
    case "security_audit": {
      const columns = ["created_at", "event_type", "actor_username", "actor_role", "target_type", "target_id", "outcome", "ip_hash"];
      const [rows] = await db.query(`SELECT ${columns.join(", ")} FROM security_audit_logs ORDER BY created_at DESC, id DESC`);
      return { columns, rows };
    }
    default:
      throw new Error("Unknown backup dataset.");
  }
}

async function importDataset(dataset, records, db) {
  let imported = 0;
  const errors = [];
  const addError = (row, message) => errors.push(`Row ${row.__rowNumber || "?"}: ${message}`);

  for (const row of records) {
    try {
      if (dataset === "students") {
        if (!row.student_number || !row.full_name) throw new Error("student_number and full_name are required");
        if (row.program && !isValidAcademicProgram(row.program)) throw new Error("program is not in the official course list");
        if (row.year_level && !isValidYearLevel(row.year_level)) throw new Error("year_level is invalid");
        await db.query(
          `INSERT INTO students (student_number, full_name, program, year_level, email)
           VALUES (?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE full_name = VALUES(full_name), program = VALUES(program), year_level = VALUES(year_level), email = VALUES(email)`,
          [row.student_number.slice(0, 50), row.full_name.slice(0, 150), row.program?.slice(0, 120) || null, row.year_level?.slice(0, 20) || null, row.email?.slice(0, 120) || null]
        );
      } else if (dataset === "vehicles") {
        if (!row.plate_number || !row.student_number) throw new Error("plate_number and student_number are required");
        const [students] = await db.query("SELECT id FROM students WHERE student_number = ? LIMIT 1", [row.student_number]);
        if (!students.length) throw new Error(`student ${row.student_number} does not exist`);
        await db.query(
          `INSERT INTO vehicles (student_id, plate_number, model, color) VALUES (?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE student_id = VALUES(student_id), model = VALUES(model), color = VALUES(color)`,
          [students[0].id, row.plate_number.slice(0, 30).toUpperCase(), row.model?.slice(0, 120) || null, row.color?.slice(0, 50) || null]
        );
      } else if (dataset === "parking_slots") {
        if (!row.slot_code) throw new Error("slot_code is required");
        const status = row.status === "disabled" ? "disabled" : "available";
        const slotType = ["standard", "accessibility", "reserved"].includes(String(row.slot_type || "").toLowerCase())
          ? String(row.slot_type).toLowerCase()
          : "standard";
        await db.query(
          `INSERT INTO parking_slots (slot_code, zone, slot_type, reserved_for, status, disabled_reason)
           VALUES (?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE zone = VALUES(zone), slot_type = VALUES(slot_type),
             reserved_for = VALUES(reserved_for), status = VALUES(status), disabled_reason = VALUES(disabled_reason)`,
          [
            row.slot_code.slice(0, 30).toUpperCase(),
            row.zone?.slice(0, 50) || "General",
            slotType,
            row.reserved_for?.slice(0, 120) || null,
            status,
            row.disabled_reason?.slice(0, 255) || null
          ]
        );
      } else if (dataset === "stickers") {
        if (!row.sticker_code || !row.qr_token || !row.plate_number) {
          throw new Error("sticker_code, qr_token, and plate_number are required");
        }
        const [vehicles] = await db.query("SELECT id FROM vehicles WHERE plate_number = ? LIMIT 1", [row.plate_number]);
        if (!vehicles.length) throw new Error(`vehicle ${row.plate_number} does not exist`);
        const status = ["active", "revoked"].includes(String(row.status || "").toLowerCase())
          ? String(row.status).toLowerCase()
          : "revoked";
        const expiresAt = row.expires_at ? normalizeDateOnlyInput(row.expires_at) : null;
        if (row.expires_at && !expiresAt) throw new Error("expires_at is invalid");
        await db.query(
          `INSERT INTO stickers (vehicle_id, sticker_code, qr_token, status, expires_at)
           VALUES (?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE vehicle_id = VALUES(vehicle_id), qr_token = VALUES(qr_token),
             status = VALUES(status), expires_at = VALUES(expires_at)`,
          [vehicles[0].id, row.sticker_code.slice(0, 40), row.qr_token.slice(0, 120), status, expiresAt]
        );
      } else if (dataset === "visitor_passes") {
        if (!row.visitor_name || !row.valid_from || !row.valid_until) throw new Error("visitor_name, valid_from, and valid_until are required");
        const validFrom = parseDateTimeInput(row.valid_from);
        const validUntil = parseDateTimeInput(row.valid_until);
        if (!validFrom || !validUntil || validUntil <= validFrom) throw new Error("validity dates are invalid");
        const passCode = (row.pass_code || createVisitorPassCode()).slice(0, 40);
        const qrToken = (row.qr_token || createQrToken()).slice(0, 120);
        const visitorType = normalizeVisitorType(row.visitor_type);
        const approval = Object.values(VISITOR_APPROVAL_STATUS).includes(String(row.approval_status).toUpperCase()) ? String(row.approval_status).toUpperCase() : "PENDING";
        const state = Object.values(VISITOR_PASS_STATE).includes(String(row.pass_state).toUpperCase()) ? String(row.pass_state).toUpperCase() : "PENDING";
        await db.query(
          `INSERT INTO visitor_passes (
             pass_code, qr_token, visitor_type, visitor_name, organization, contact_number,
             plate_number, vehicle_type, purpose, approval_status, pass_state,
             valid_from, valid_until, assigned_zone, requested_by
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'csv-import')
           ON DUPLICATE KEY UPDATE visitor_type = VALUES(visitor_type), visitor_name = VALUES(visitor_name),
             organization = VALUES(organization), contact_number = VALUES(contact_number), plate_number = VALUES(plate_number),
             vehicle_type = VALUES(vehicle_type), purpose = VALUES(purpose), valid_from = VALUES(valid_from),
             valid_until = VALUES(valid_until), assigned_zone = VALUES(assigned_zone)`,
          [passCode, qrToken, visitorType, row.visitor_name.slice(0, 150), row.organization?.slice(0, 150) || null,
            row.contact_number?.slice(0, 60) || null, row.plate_number?.slice(0, 30) || null, row.vehicle_type?.slice(0, 80) || null,
            row.purpose?.slice(0, 255) || null, approval, state, validFrom, validUntil, row.assigned_zone?.slice(0, 80) || null]
        );
      } else {
        throw new Error("This dataset is export-only");
      }
      imported += 1;
    } catch (error) {
      addError(row, error.message || "invalid data");
      if (errors.length >= 20) break;
    }
  }
  return { imported, errors };
}

function validateRecoveryPayload(payload) {
  if (payload?.format !== "naap-recovery-bundle" || Number(payload?.version) !== 1) {
    throw new BackupValidationError("Recovery bundle format or version is not supported.");
  }
  if (!payload.datasets || typeof payload.datasets !== "object" || Array.isArray(payload.datasets)) {
    throw new BackupValidationError("Recovery bundle does not contain valid datasets.");
  }
  let totalRows = 0;
  for (const [dataset, exported] of Object.entries(payload.datasets)) {
    if (!RECOVERY_DATASET_ORDER.includes(dataset)) continue;
    if (!exported || !Array.isArray(exported.columns) || !Array.isArray(exported.rows)) {
      throw new BackupValidationError(`Recovery dataset ${dataset} is malformed.`);
    }
    totalRows += exported.rows.length;
  }
  if (totalRows > 100000) throw new BackupValidationError("Recovery bundle contains too many rows.");
  return payload;
}

async function buildRecoveryPayload(db = pool) {
  const datasets = {};
  for (const dataset of RECOVERY_DATASET_ORDER) {
    datasets[dataset] = await getDatasetExport(dataset, db);
  }
  return {
    format: "naap-recovery-bundle",
    version: 1,
    created_at: new Date().toISOString(),
    datasets
  };
}

function getBackupDigest(encryptedPayload) {
  return crypto.createHash("sha256").update(String(encryptedPayload || ""), "utf8").digest("hex");
}

function createRestorePreviewToken(userId, previewId, digest, expiresAt) {
  const expiry = new Date(expiresAt).getTime();
  const message = `${Number(userId)}|${Number(previewId)}|${digest}|${expiry}`;
  return crypto.createHmac("sha256", SESSION_SECRET).update(message).digest("hex");
}

function verifyRestorePreviewToken(userId, preview, token) {
  if (!preview || !/^[a-f0-9]{64}$/i.test(String(token || ""))) return false;
  if (Number(preview.requested_by_user_id) !== Number(userId)) return false;
  if (preview.consumed_at || new Date(preview.expires_at).getTime() <= Date.now()) return false;
  const expected = createRestorePreviewToken(userId, preview.id, preview.payload_digest, preview.expires_at);
  return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(String(token), "hex"));
}

async function createStoredRecoveryBackup(passphrase, options = {}) {
  let connection;
  let payload;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    payload = await buildRecoveryPayload(connection);
    await connection.commit();
  } catch (error) {
    if (connection) {
      try { await connection.rollback(); } catch (_rollbackError) {}
    }
    throw error;
  } finally {
    connection?.release();
  }
  const encryptedPayload = encryptBackup(payload, passphrase);
  const summary = summarizeBackupPayload(payload);
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const prefix = options.automated ? "automated" : "manual";
  const filename = `naap-${prefix}-backup-${timestamp}.naapbackup`;
  const expiresAt = new Date(Date.now() + BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000);
  const [result] = await pool.query(
    `INSERT INTO backup_archives (
       backup_name, encrypted_payload, payload_bytes, dataset_summary,
       status, created_by_user_id, expires_at
     ) VALUES (?, ?, ?, ?, 'ready', ?, ?)`,
    [
      filename,
      encryptedPayload,
      Buffer.byteLength(encryptedPayload, "utf8"),
      JSON.stringify(summary),
      Number(options.userId) || null,
      expiresAt
    ]
  );
  if (options.automated && BACKUP_EMAIL_TO) {
    try {
      await sendBackupArchiveEmail({
        to: BACKUP_EMAIL_TO,
        filename,
        content: Buffer.from(encryptedPayload, "utf8")
      });
      await pool.query("UPDATE backup_archives SET status = 'emailed' WHERE id = ?", [result.insertId]);
    } catch (error) {
      await pool.query("UPDATE backup_archives SET status = 'email_failed' WHERE id = ?", [result.insertId]);
      console.warn("Automated backup email warning:", error.message);
    }
  }
  return { id: result.insertId, filename, encryptedPayload, summary };
}

async function getBackupArchives(limit = 12) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || 12, 30));
  const [rows] = await pool.query(
    `SELECT id, backup_name, payload_bytes, dataset_summary, status, created_at, expires_at
     FROM backup_archives
     WHERE expires_at IS NULL OR expires_at > NOW()
     ORDER BY created_at DESC, id DESC
     LIMIT ?`,
    [safeLimit]
  );
  return rows;
}

async function suspendInactiveGuards() {
  if (!GUARD_INACTIVITY_DAYS) return 0;
  const inactiveBefore = new Date(Date.now() - GUARD_INACTIVITY_DAYS * 24 * 60 * 60 * 1000);
  const [rows] = await pool.query(
    `SELECT id, username
     FROM users
     WHERE role = 'guard' AND is_active = 1
       AND COALESCE(last_login_at, created_at) < ?`,
    [inactiveBefore]
  );
  for (const guard of rows) {
    await pool.query(
      `UPDATE users
       SET is_active = 0, disabled_at = NOW(), disabled_reason = ?
       WHERE id = ? AND is_active = 1`,
      [`Automatically suspended after ${GUARD_INACTIVITY_DAYS} days without a login`, guard.id]
    );
    await revokeUserSessions(guard.id);
    await recordBackgroundAudit("GUARD_INACTIVITY_SUSPENDED", {
      targetType: "user",
      targetId: guard.id,
      metadata: { username: guard.username, inactivity_days: GUARD_INACTIVITY_DAYS }
    });
  }
  return rows.length;
}

async function runDataRetentionCleanup() {
  const results = {};
  try {
    await pool.query(
      `UPDATE scan_logs sl
       JOIN scan_snapshots ss ON sl.snapshot_path = CONCAT('/snapshots/', ss.storage_key)
       SET sl.snapshot_path = NULL
       WHERE ss.created_at < NOW() - INTERVAL ${SNAPSHOT_RETENTION_DAYS} DAY`
    );
    await pool.query(
      `UPDATE auto_scan_queue q
       JOIN scan_snapshots ss ON q.snapshot_path = CONCAT('/snapshots/', ss.storage_key)
       SET q.snapshot_path = NULL
       WHERE ss.created_at < NOW() - INTERVAL ${SNAPSHOT_RETENTION_DAYS} DAY`
    );
    [results.snapshots] = await pool.query(
      `DELETE FROM scan_snapshots WHERE created_at < NOW() - INTERVAL ${SNAPSHOT_RETENTION_DAYS} DAY`
    );
    [results.studentLogs] = await pool.query(
      `DELETE FROM scan_logs WHERE scanned_at < NOW() - INTERVAL ${SCAN_LOG_RETENTION_DAYS} DAY`
    );
    [results.visitorLogs] = await pool.query(
      `DELETE FROM visitor_scan_logs WHERE scanned_at < NOW() - INTERVAL ${SCAN_LOG_RETENTION_DAYS} DAY`
    );
    [results.scannerMetrics] = await pool.query(
      `DELETE FROM scanner_metrics WHERE created_at < NOW() - INTERVAL ${SCANNER_METRIC_RETENTION_DAYS} DAY`
    );
    [results.emailJobs] = await pool.query(
      "DELETE FROM email_delivery_jobs WHERE created_at < NOW() - INTERVAL 180 DAY"
    );
    [results.restorePreviews] = await pool.query(
      "DELETE FROM backup_restore_previews WHERE expires_at < NOW() OR consumed_at IS NOT NULL"
    );
    [results.backups] = await pool.query(
      "DELETE FROM backup_archives WHERE expires_at IS NOT NULL AND expires_at < NOW()"
    );
    [results.securityAudit] = await pool.query(
      `DELETE FROM security_audit_logs WHERE created_at < NOW() - INTERVAL ${SECURITY_AUDIT_RETENTION_DAYS} DAY`
    );
    const deleted = Object.values(results).reduce((total, result) => total + Number(result?.affectedRows || 0), 0);
    if (deleted) await recordBackgroundAudit("DATA_RETENTION_CLEANUP", { metadata: { deleted } });
    return deleted;
  } catch (error) {
    console.error("Data retention cleanup error:", error.message);
    return 0;
  }
}

async function ensureAutomatedRecoveryBackup() {
  if (BACKUP_ENCRYPTION_KEY.length < 12) return null;
  const [[latest]] = await pool.query(
    `SELECT id FROM backup_archives
     WHERE backup_name LIKE 'naap-automated-backup-%'
       AND created_at >= NOW() - INTERVAL 20 HOUR
     ORDER BY created_at DESC LIMIT 1`
  );
  if (latest?.id) return null;
  const backup = await createStoredRecoveryBackup(BACKUP_ENCRYPTION_KEY, { automated: true });
  await recordBackgroundAudit("AUTOMATED_BACKUP_CREATED", {
    targetType: "backup",
    targetId: backup.id,
    metadata: { summary: backup.summary, emailed: Boolean(BACKUP_EMAIL_TO) }
  });
  return backup;
}

app.get("/", requireAuth, (req, res) => {
  res.redirect(getRoleHomePath(req.authUser?.role));
});

app.get("/forbidden", requireAuth, (req, res) => {
  return renderForbiddenPage(req, res);
});

app.get("/account/security", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, username, role, must_change_password,
              password_changed_at, last_login_at, created_at
       FROM users WHERE id = ? LIMIT 1`,
      [req.authUser.id]
    );
    if (!rows.length) return res.redirect("/logout");
    const [sessions, auditResult] = await Promise.all([
      listUserSessions(req.authUser.id, req.sessionID),
      pool.query(
        `SELECT event_type, outcome, created_at
         FROM security_audit_logs
         WHERE actor_user_id = ?
         ORDER BY created_at DESC, id DESC
         LIMIT 12`,
        [req.authUser.id]
      )
    ]);
    const flash = req.query.saved
      ? { type: "success", message: "Security settings updated successfully." }
      : req.query.revoked
        ? { type: "success", message: "Session access was revoked." }
        : req.query.password_required
          ? { type: "error", message: "Change your temporary password before continuing." }
        : req.query.error
          ? { type: "error", message: String(req.query.error).slice(0, 180) }
          : null;
    return res.render("account_security", {
      account: rows[0],
      sessions,
      auditRows: auditResult[0],
      flash
    });
  } catch (error) {
    console.error("Account security page error:", error);
    return res.status(500).send("Unable to load account security settings.");
  }
});

app.post("/account/password", requireAuth, async (req, res) => {
  const rateKey = getRateLimitKey(req, `account:${req.authUser.id}`);
  if (!accountSecurityRateLimiter.check(rateKey).allowed) {
    return res.redirect("/account/security?error=Too+many+security+changes.+Try+again+later.");
  }
  const currentPassword = String(req.body.current_password || "");
  const newPassword = String(req.body.new_password || "");
  const confirmation = String(req.body.confirm_password || "");
  const policy = validatePassword(newPassword);
  if (newPassword !== confirmation || !policy.valid) {
    accountSecurityRateLimiter.recordFailure(rateKey);
    const message = newPassword !== confirmation ? "New passwords do not match." : policy.issues[0];
    return res.redirect(`/account/security?error=${encodeURIComponent(message)}`);
  }
  try {
    const [rows] = await pool.query("SELECT password FROM users WHERE id = ? LIMIT 1", [req.authUser.id]);
    if (!rows.length || !(await bcrypt.compare(currentPassword, String(rows[0].password || "")))) {
      accountSecurityRateLimiter.recordFailure(rateKey);
      await recordSecurityAudit(req, "PASSWORD_CHANGE_FAILED", { outcome: "failed" });
      return res.redirect("/account/security?error=Current+password+is+incorrect.");
    }
    const passwordHash = await bcrypt.hash(newPassword, 12);
    await pool.query(
      "UPDATE users SET password = ?, password_changed_at = NOW(), must_change_password = 0 WHERE id = ?",
      [passwordHash, req.authUser.id]
    );
    if (req.session?.user) req.session.user.mustChangePassword = false;
    await revokeUserSessions(req.authUser.id, { keepSessionId: req.sessionID });
    accountSecurityRateLimiter.reset(rateKey);
    await recordSecurityAudit(req, "PASSWORD_CHANGED");
    return res.redirect("/account/security?saved=1");
  } catch (error) {
    console.error("Password change error:", error);
    return res.redirect("/account/security?error=Unable+to+change+password.");
  }
});

app.post("/account/sessions/:fingerprint/revoke", requireAuth, async (req, res, next) => {
  try {
    const fingerprint = String(req.params.fingerprint || "");
    if (!/^[a-f0-9]{12}$/.test(fingerprint)) return res.redirect("/account/security?error=Invalid+session.");
    const revoked = await revokeUserSessions(req.authUser.id, { fingerprint, keepSessionId: req.sessionID });
    await recordSecurityAudit(req, "SESSION_REVOKED", { targetType: "session", targetId: fingerprint, metadata: { revoked } });
    return res.redirect("/account/security?revoked=1#sessions");
  } catch (error) { next(error); }
});

app.post("/account/sessions/revoke-others", requireAuth, async (req, res, next) => {
  try {
    const revoked = await revokeUserSessions(req.authUser.id, { keepSessionId: req.sessionID });
    await recordSecurityAudit(req, "OTHER_SESSIONS_REVOKED", { metadata: { revoked } });
    return res.redirect("/account/security?revoked=1#sessions");
  } catch (error) { next(error); }
});

app.get("/admin", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const data = await getDashboardData();
    res.render("dashboard", data);
  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(500).send("An error occurred loading the dashboard.");
  }
});

app.get("/admin/slots", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const [overview, zoneSettingsResult] = await Promise.all([
      getParkingSlotOverview(),
      pool.query(
        `SELECT pzs.zone, pzs.warning_threshold_percent,
                COUNT(ps.id) AS total_slots
         FROM parking_zone_settings pzs
         LEFT JOIN parking_slots ps ON ps.zone = pzs.zone
         GROUP BY pzs.zone, pzs.warning_threshold_percent
         ORDER BY pzs.zone`
      )
    ]);
    const flash = req.query.saved
      ? { type: "success", message: "Parking slot settings saved." }
      : req.query.created
        ? { type: "success", message: "Parking slot created." }
        : req.query.threshold
          ? { type: "success", message: "Zone capacity warning threshold updated." }
          : req.query.error
            ? { type: "error", message: String(req.query.error).slice(0, 180) }
            : null;
    res.render("admin_slots", {
      parkingSlots: overview.slots,
      parkingSlotSummary: overview.summary,
      zoneSettings: zoneSettingsResult[0],
      flash
    });
  } catch (error) {
    console.error("Admin slots page error:", error);
    res.status(500).send("An error occurred loading available slots.");
  }
});

function normalizeParkingSlotInput(body) {
  const slotCode = String(body.slot_code || "").trim().toUpperCase().slice(0, 30);
  const zone = String(body.zone || "General").trim().slice(0, 50) || "General";
  const requestedType = String(body.slot_type || "standard").trim().toLowerCase();
  const slotType = ["standard", "accessibility", "reserved"].includes(requestedType) ? requestedType : "standard";
  const status = String(body.status || "available") === "disabled" ? "disabled" : "available";
  const reservedFor = slotType === "standard" ? null : String(body.reserved_for || "").trim().slice(0, 120) || null;
  const disabledReason = status === "disabled" ? String(body.disabled_reason || "").trim().slice(0, 255) || null : null;
  if (!/^[A-Z0-9][A-Z0-9 _-]{0,29}$/.test(slotCode)) throw new Error("Enter a valid slot code.");
  if (status === "disabled" && !disabledReason) throw new Error("Provide a maintenance reason when disabling a slot.");
  if (slotType === "reserved" && !reservedFor) throw new Error("Describe who may use this reserved slot.");
  return { slotCode, zone, slotType, status, reservedFor, disabledReason };
}

app.post("/admin/slots", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const slot = normalizeParkingSlotInput(req.body);
    const [result] = await pool.query(
      `INSERT INTO parking_slots (slot_code, zone, slot_type, reserved_for, status, disabled_reason)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [slot.slotCode, slot.zone, slot.slotType, slot.reservedFor, slot.status, slot.disabledReason]
    );
    await pool.query("INSERT IGNORE INTO parking_zone_settings (zone) VALUES (?)", [slot.zone]);
    await recordSecurityAudit(req, "PARKING_SLOT_CREATED", { targetType: "parking_slot", targetId: result.insertId, metadata: slot });
    return res.redirect("/admin/slots?created=1");
  } catch (error) {
    const message = error.code === "ER_DUP_ENTRY" ? "That slot code already exists." : error.message || "Unable to create parking slot.";
    return res.redirect(`/admin/slots?error=${encodeURIComponent(message)}`);
  }
});

app.post("/admin/slots/:id(\\d+)", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const slotId = Number(req.params.id);
  if (!Number.isInteger(slotId) || slotId <= 0) return res.redirect("/admin/slots?error=Invalid+parking+slot.");
  try {
    const slot = normalizeParkingSlotInput(req.body);
    const [rows] = await pool.query(
      "SELECT current_sticker_id, current_visitor_pass_id FROM parking_slots WHERE id = ? LIMIT 1",
      [slotId]
    );
    if (!rows.length) return res.redirect("/admin/slots?error=Parking+slot+not+found.");
    if (slot.status === "disabled" && (rows[0].current_sticker_id || rows[0].current_visitor_pass_id)) {
      return res.redirect("/admin/slots?error=An+occupied+slot+cannot+be+disabled.");
    }
    await pool.query(
      `UPDATE parking_slots
       SET slot_code = ?, zone = ?, slot_type = ?, reserved_for = ?, status = ?, disabled_reason = ?
       WHERE id = ?`,
      [slot.slotCode, slot.zone, slot.slotType, slot.reservedFor, slot.status, slot.disabledReason, slotId]
    );
    await pool.query("INSERT IGNORE INTO parking_zone_settings (zone) VALUES (?)", [slot.zone]);
    await recordSecurityAudit(req, "PARKING_SLOT_UPDATED", { targetType: "parking_slot", targetId: slotId, metadata: slot });
    return res.redirect("/admin/slots?saved=1");
  } catch (error) {
    const message = error.code === "ER_DUP_ENTRY" ? "That slot code already exists." : error.message || "Unable to update parking slot.";
    return res.redirect(`/admin/slots?error=${encodeURIComponent(message)}`);
  }
});

app.post("/admin/slots/zone-threshold", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const zone = String(req.body.zone || "").trim().slice(0, 50);
  const threshold = Number(req.body.warning_threshold_percent);
  if (!zone || !Number.isInteger(threshold) || threshold < 50 || threshold > 100) {
    return res.redirect("/admin/slots?error=Capacity+threshold+must+be+between+50+and+100+percent.");
  }
  try {
    await pool.query(
      `INSERT INTO parking_zone_settings (zone, warning_threshold_percent)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE warning_threshold_percent = VALUES(warning_threshold_percent)`,
      [zone, threshold]
    );
    await recordSecurityAudit(req, "PARKING_ZONE_THRESHOLD_UPDATED", {
      targetType: "parking_zone",
      targetId: zone,
      metadata: { warning_threshold_percent: threshold }
    });
    await evaluateZoneCapacityAlerts(pool, getAuthActorName(req));
    return res.redirect("/admin/slots?threshold=1");
  } catch (error) {
    console.error("Zone threshold update error:", error);
    return res.redirect("/admin/slots?error=Unable+to+update+the+zone+threshold.");
  }
});

app.get("/admin/updates", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const [insideVehicles, movementLogs] = await Promise.all([
      getInsideVehiclesWithOverstay(pool, 30),
      getRecentMovementLogs(pool, 80)
    ]);
    const overstayAlerts = insideVehicles.filter((item) => item.is_overstay);
    res.render("admin_updates", {
      insideVehicles,
      overstayAlerts,
      movementLogs,
      overstayLimitHours: OVERSTAY_LIMIT_HOURS,
      overstayLimitLabel: formatHoursLabel(OVERSTAY_LIMIT_HOURS)
    });
  } catch (error) {
    console.error("Admin updates page error:", error);
    res.status(500).send("An error occurred loading latest updates.");
  }
});

app.get("/admin/records", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const movementLogs = await getRecentMovementLogs(pool, 220);
    const summary = {
      total: movementLogs.length,
      valid: movementLogs.filter((row) => row.result === "VALID").length,
      entries: movementLogs.filter((row) => row.action === "ENTRY").length,
      exits: movementLogs.filter((row) => row.action === "EXIT").length
    };
    res.render("admin_records", { movementLogs, summary });
  } catch (error) {
    console.error("Admin records page error:", error);
    res.status(500).send("An error occurred loading gate records.");
  }
});

app.get("/admin/scanner-analytics", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const data = await getScannerAnalytics(req.query.days, req.query.gate);
    return res.render("scanner_analytics", data);
  } catch (error) {
    console.error("Scanner analytics page error:", error);
    return res.status(500).send("An error occurred loading scanner analytics.");
  }
});

async function getAdminDataPageModel(req, extra = {}) {
  const flash = req.query.imported
    ? { type: "success", message: `${Number(req.query.imported) || 0} row(s) imported successfully.` }
    : req.query.restored
      ? { type: "success", message: `${Number(req.query.restored) || 0} recovery row(s) restored successfully.` }
      : req.query.backup
        ? { type: "success", message: "Encrypted recovery archive created successfully." }
    : req.query.error
      ? { type: "error", message: String(req.query.error).slice(0, 220) }
      : null;
  return {
    datasets: Object.entries(DATASET_DEFINITIONS)
      .filter(([, value]) => !value.encryptedOnly)
      .map(([key, value]) => ({ key, ...value })),
    archives: await getBackupArchives(),
    backupAutomationEnabled: BACKUP_ENCRYPTION_KEY.length >= 12,
    backupEmailEnabled: Boolean(BACKUP_EMAIL_TO),
    restorePreview: null,
    flash,
    ...extra
  };
}

app.get("/admin/data", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    return res.render("admin_data", await getAdminDataPageModel(req));
  } catch (error) {
    console.error("Admin data page error:", error);
    return res.status(500).send("Unable to load backup and recovery tools.");
  }
});

app.get("/admin/data/export/:dataset", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const dataset = String(req.params.dataset || "");
  if (!DATASET_DEFINITIONS[dataset]) return res.status(404).send("Unknown backup dataset.");
  try {
    const exported = await getDatasetExport(dataset);
    const columns = exported.columns.map((key) => ({ key, label: key }));
    const csv = stringifyCsv(columns, exported.rows);
    const date = new Date().toISOString().slice(0, 10);
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="naap-${dataset}-${date}.csv"`);
    await recordSecurityAudit(req, "DATA_EXPORTED", { targetType: "dataset", targetId: dataset, metadata: { rows: exported.rows.length } });
    return res.send(csv);
  } catch (error) {
    console.error("Data export error:", error);
    return res.status(500).send("Unable to export this dataset.");
  }
});

app.post("/admin/data/import", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const dataset = String(req.body.dataset || "");
  const definition = DATASET_DEFINITIONS[dataset];
  if (!definition?.importable) return res.redirect("/admin/data?error=This+dataset+cannot+be+imported.");
  let records;
  try {
    records = parseCsv(req.body.csv_data, { maxRows: 2000 });
    if (!records.length) throw new Error("The CSV does not contain any data rows.");
  } catch (error) {
    return res.redirect(`/admin/data?error=${encodeURIComponent(error.message || "Invalid CSV file.")}`);
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const result = await importDataset(dataset, records, connection);
    await connection.commit();
    await recordSecurityAudit(req, "DATA_IMPORTED", {
      targetType: "dataset",
      targetId: dataset,
      outcome: result.errors.length ? "partial" : "success",
      metadata: { imported: result.imported, errors: result.errors.slice(0, 10) }
    });
    if (result.errors.length) {
      const message = `${result.imported} imported. ${result.errors[0]}`;
      return res.redirect(`/admin/data?error=${encodeURIComponent(message)}`);
    }
    return res.redirect(`/admin/data?imported=${result.imported}`);
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("Data import error:", error);
    return res.redirect("/admin/data?error=Unable+to+import+this+CSV.");
  } finally {
    connection?.release();
  }
});

app.post("/admin/data/backup", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const passphrase = String(req.body.backup_passphrase || "");
  const confirmation = String(req.body.backup_passphrase_confirmation || "");
  if (passphrase !== confirmation) return res.redirect("/admin/data?error=Backup+passphrases+do+not+match.");
  try {
    const backup = await createStoredRecoveryBackup(passphrase, { userId: req.authUser.id });
    await recordSecurityAudit(req, "ENCRYPTED_BACKUP_CREATED", {
      targetType: "backup",
      targetId: backup.id,
      metadata: { summary: backup.summary }
    });
    res.setHeader("Content-Type", "application/vnd.naap.encrypted-backup+json");
    res.setHeader("Content-Disposition", `attachment; filename="${backup.filename}"`);
    return res.send(backup.encryptedPayload);
  } catch (error) {
    const message = error instanceof BackupValidationError ? error.message : "Unable to create the encrypted backup.";
    console.error("Encrypted backup error:", error.message);
    return res.redirect(`/admin/data?error=${encodeURIComponent(message)}`);
  }
});

app.get("/admin/data/backups/:id/download", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const backupId = Number(req.params.id);
  if (!Number.isInteger(backupId) || backupId <= 0) return res.status(404).send("Backup not found.");
  try {
    const [rows] = await pool.query(
      `SELECT backup_name, encrypted_payload
       FROM backup_archives
       WHERE id = ? AND (expires_at IS NULL OR expires_at > NOW())
       LIMIT 1`,
      [backupId]
    );
    if (!rows.length) return res.status(404).send("Backup not found or expired.");
    res.setHeader("Content-Type", "application/vnd.naap.encrypted-backup+json");
    res.setHeader("Content-Disposition", `attachment; filename="${String(rows[0].backup_name).replace(/[^a-z0-9._-]/gi, "-")}"`);
    await recordSecurityAudit(req, "ENCRYPTED_BACKUP_DOWNLOADED", { targetType: "backup", targetId: backupId });
    return res.send(rows[0].encrypted_payload);
  } catch (error) {
    console.error("Backup download error:", error);
    return res.status(500).send("Unable to download this backup.");
  }
});

app.post(
  "/admin/data/restore-preview",
  requireRole(USER_ROLES.ADMIN),
  backupUpload.single("backup_file"),
  async (req, res) => {
    try {
      if (!req.file?.buffer?.length) throw new BackupValidationError("Choose an encrypted .naapbackup file.");
      const encryptedPayload = req.file.buffer.toString("utf8");
      const payload = validateRecoveryPayload(decryptBackup(encryptedPayload, req.body.backup_passphrase));
      const summary = summarizeBackupPayload(payload);
      const digest = getBackupDigest(encryptedPayload);
      // MySQL TIMESTAMP values have second precision by default. Round before
      // signing so the stored expiry recreates the same confirmation token.
      const expiresAt = new Date(Math.floor((Date.now() + 15 * 60 * 1000) / 1000) * 1000);
      const [result] = await pool.query(
        `INSERT INTO backup_restore_previews
           (requested_by_user_id, encrypted_payload, payload_digest, dataset_summary, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
        [req.authUser.id, encryptedPayload, digest, JSON.stringify(summary), expiresAt]
      );
      const restorePreview = {
        id: result.insertId,
        token: createRestorePreviewToken(req.authUser.id, result.insertId, digest, expiresAt),
        summary,
        createdAt: payload.created_at || null
      };
      await recordSecurityAudit(req, "BACKUP_RESTORE_PREVIEWED", {
        targetType: "backup_restore_preview",
        targetId: result.insertId,
        metadata: { summary }
      });
      return res.render("admin_data", await getAdminDataPageModel(req, { restorePreview }));
    } catch (error) {
      const message = error instanceof BackupValidationError ? error.message : "Unable to validate this recovery archive.";
      console.error("Backup restore preview error:", error.message);
      return res.redirect(`/admin/data?error=${encodeURIComponent(message)}`);
    }
  }
);

app.post("/admin/data/restore-confirm", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const previewId = Number(req.body.preview_id);
  const token = String(req.body.preview_token || "");
  const passphrase = String(req.body.backup_passphrase || "");
  if (!Number.isInteger(previewId) || previewId <= 0) return res.redirect("/admin/data?error=Invalid+restore+confirmation.");
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [rows] = await connection.query(
      `SELECT id, requested_by_user_id, encrypted_payload, payload_digest, expires_at, consumed_at
       FROM backup_restore_previews WHERE id = ? FOR UPDATE`,
      [previewId]
    );
    const preview = rows[0];
    if (!verifyRestorePreviewToken(req.authUser.id, preview, token)) {
      throw new BackupValidationError("Restore preview expired or could not be verified.");
    }
    const payload = validateRecoveryPayload(decryptBackup(preview.encrypted_payload, passphrase));
    let imported = 0;
    for (const dataset of RECOVERY_DATASET_ORDER) {
      if (!DATASET_DEFINITIONS[dataset]?.importable) continue;
      const records = payload.datasets[dataset]?.rows;
      if (!Array.isArray(records) || !records.length) continue;
      const result = await importDataset(dataset, records, connection);
      if (result.errors.length) throw new BackupValidationError(result.errors[0]);
      imported += result.imported;
    }
    await connection.query("UPDATE backup_restore_previews SET consumed_at = NOW() WHERE id = ?", [previewId]);
    await connection.commit();
    await recordSecurityAudit(req, "BACKUP_RESTORED", {
      targetType: "backup_restore_preview",
      targetId: previewId,
      metadata: { imported }
    });
    return res.redirect(`/admin/data?restored=${imported}`);
  } catch (error) {
    try { await connection.rollback(); } catch (_rollbackError) {}
    const message = error instanceof BackupValidationError ? error.message : "Unable to restore this recovery archive.";
    console.error("Backup restore error:", error.message);
    return res.redirect(`/admin/data?error=${encodeURIComponent(message)}`);
  } finally {
    connection?.release();
  }
});

app.get("/admin/alerts", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    await evaluateZoneCapacityAlerts(pool, getAuthActorName(req) || "admin-alerts-page");
    const [alertSummary, alertList] = await Promise.all([
      getOperationalAlertMetrics(pool),
      listAlertsForUser(req.authUser, { limit: 30, offset: 0, status: "all" }, pool)
    ]);
    res.render("admin_alerts", {
      alertSummary,
      initialAlerts: alertList.rows,
      initialTotal: alertList.total
    });
  } catch (error) {
    console.error("Admin alerts page error:", error);
    res.status(500).send("An error occurred loading alerts.");
  }
});

app.get("/guard", requireRole(USER_ROLES.GUARD), async (req, res) => {
  try {
    const data = await getGuardDashboardData();
    res.render("guard_dashboard", data);
  } catch (error) {
    console.error("Guard dashboard error:", error);
    res.status(500).send("An error occurred loading the guard dashboard.");
  }
});

app.get("/admin/users", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const [users] = await pool.query(
      `SELECT
         u.id,
         u.username,
         u.role,
         u.is_active,
         u.must_change_password,
         u.last_login_at,
         u.disabled_at,
         u.disabled_reason,
         u.created_at
       FROM users u
       ORDER BY
         CASE
           WHEN u.role = 'admin' THEN 1
           WHEN u.role = 'guard' THEN 2
           ELSE 99
         END,
         u.username ASC`
    );

    const flash = req.query.success
      ? { type: "success", message: "User saved successfully." }
      : req.query.updated
        ? { type: "success", message: "User updated successfully." }
        : req.query.status
          ? { type: "success", message: "Account status updated successfully." }
        : req.query.deleted
          ? { type: "success", message: "User deleted successfully." }
          : req.query.error === "duplicate"
            ? { type: "error", message: "Username already exists." }
            : req.query.error === "self-delete"
              ? { type: "error", message: "You cannot delete your own account." }
              : req.query.error === "self-role"
                ? { type: "error", message: "You cannot remove your own admin role." }
                : req.query.error === "invalid"
                  ? { type: "error", message: "Invalid user details provided." }
                : req.query.error === "notfound"
                    ? { type: "error", message: "User was not found." }
                    : req.query.error === "last-admin"
                      ? { type: "error", message: "The last active administrator cannot be suspended." }
                      : req.query.error === "self-status"
                        ? { type: "error", message: "You cannot suspend your own account." }
                    : null;

    res.render("admin_users", { users, flash });
  } catch (error) {
    console.error("Admin users page error:", error);
    res.status(500).send("An error occurred loading user management.");
  }
});

app.post("/admin/users", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const role = normalizeRole(req.body.role);

  if (!username || !password || !role || !validatePassword(password).valid) {
    return res.redirect("/admin/users?error=invalid");
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query(
      "INSERT INTO users (username, password, role, must_change_password) VALUES (?, ?, ?, 1)",
      [username, passwordHash, role]
    );
    await recordSecurityAudit(req, "USER_CREATED", { targetType: "user", targetId: username, metadata: { role } });
    return res.redirect("/admin/users?success=1");
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.redirect("/admin/users?error=duplicate");
    }
    console.error("Create user error:", error);
    return res.redirect("/admin/users?error=invalid");
  }
});

app.post("/admin/users/:id/edit", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const userId = Number(req.params.id);
  const username = String(req.body.username || "").trim();
  const role = normalizeRole(req.body.role);
  const password = String(req.body.password || "");

  if (!Number.isInteger(userId) || userId <= 0 || !username || !role) {
    return res.redirect("/admin/users?error=invalid");
  }
  if (password && !validatePassword(password).valid) {
    return res.redirect("/admin/users?error=invalid");
  }

  try {
    const [existingRows] = await pool.query(
      "SELECT id, role FROM users WHERE id = ? LIMIT 1",
      [userId]
    );
    if (!existingRows.length) {
      return res.redirect("/admin/users?error=notfound");
    }

    if (
      req.authUser?.id &&
      Number(req.authUser.id) === userId &&
      role !== USER_ROLES.ADMIN
    ) {
      return res.redirect("/admin/users?error=self-role");
    }

    if (password) {
      const passwordHash = await bcrypt.hash(password, 12);
      await pool.query(
        `UPDATE users
         SET username = ?, role = ?, password = ?, password_changed_at = NOW(), must_change_password = ?
         WHERE id = ?`,
        [username, role, passwordHash, Number(req.authUser?.id) === userId ? 0 : 1, userId]
      );
      await revokeUserSessions(userId, {
        keepSessionId: Number(req.authUser?.id) === userId ? req.sessionID : null
      });
    } else {
      await pool.query(
        `UPDATE users
         SET username = ?, role = ?
         WHERE id = ?`,
        [username, role, userId]
      );
    }

    if (req.authUser?.id && Number(req.authUser.id) === userId) {
      req.session.user = {
        ...(req.session.user || {}),
        username,
        role
      };
    }
    if (!password && existingRows[0].role !== role) {
      await revokeUserSessions(userId);
    }
    await recordSecurityAudit(req, password ? "USER_PASSWORD_RESET" : "USER_UPDATED", {
      targetType: "user",
      targetId: userId,
      metadata: { username, role, password_reset: Boolean(password) }
    });
    return res.redirect("/admin/users?updated=1");
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.redirect("/admin/users?error=duplicate");
    }
    console.error("Update user error:", error);
    return res.redirect("/admin/users?error=invalid");
  }
});

app.post("/admin/users/:id/delete", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const userId = Number(req.params.id);
  if (!Number.isInteger(userId) || userId <= 0) {
    return res.redirect("/admin/users?error=invalid");
  }
  if (req.authUser?.id && Number(req.authUser.id) === userId) {
    return res.redirect("/admin/users?error=self-delete");
  }

  try {
    const [targetRows] = await pool.query("SELECT role, is_active, username FROM users WHERE id = ? LIMIT 1", [userId]);
    if (!targetRows.length) return res.redirect("/admin/users?error=notfound");
    if (targetRows[0].role === USER_ROLES.ADMIN && targetRows[0].is_active) {
      const [[countRow]] = await pool.query("SELECT COUNT(*) AS total FROM users WHERE role = 'admin' AND is_active = 1");
      if (Number(countRow?.total || 0) <= 1) return res.redirect("/admin/users?error=last-admin");
    }
    await revokeUserSessions(userId);
    await pool.query("DELETE FROM users WHERE id = ?", [userId]);
    await recordSecurityAudit(req, "USER_DELETED", {
      targetType: "user",
      targetId: userId,
      metadata: { username: targetRows[0].username, role: targetRows[0].role }
    });
    return res.redirect("/admin/users?deleted=1");
  } catch (error) {
    console.error("Delete user error:", error);
    return res.redirect("/admin/users?error=invalid");
  }
});

app.post("/admin/users/:id/status", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const userId = Number(req.params.id);
  const nextActive = String(req.body.is_active || "") === "1";
  if (!Number.isInteger(userId) || userId <= 0) return res.redirect("/admin/users?error=invalid");
  if (Number(req.authUser.id) === userId) return res.redirect("/admin/users?error=self-status");
  try {
    const [rows] = await pool.query("SELECT id, username, role, is_active FROM users WHERE id = ? LIMIT 1", [userId]);
    if (!rows.length) return res.redirect("/admin/users?error=notfound");
    const target = rows[0];
    if (!nextActive && target.role === USER_ROLES.ADMIN && target.is_active) {
      const [[countRow]] = await pool.query("SELECT COUNT(*) AS total FROM users WHERE role = 'admin' AND is_active = 1");
      if (Number(countRow?.total || 0) <= 1) return res.redirect("/admin/users?error=last-admin");
    }
    await pool.query(
      `UPDATE users
       SET is_active = ?, disabled_at = ?, disabled_reason = ?
       WHERE id = ?`,
      [nextActive ? 1 : 0, nextActive ? null : new Date(), nextActive ? null : "Suspended by administrator", userId]
    );
    if (!nextActive) await revokeUserSessions(userId);
    await recordSecurityAudit(req, nextActive ? "USER_REACTIVATED" : "USER_SUSPENDED", {
      targetType: "user",
      targetId: userId,
      metadata: { username: target.username, role: target.role }
    });
    return res.redirect("/admin/users?status=1");
  } catch (error) {
    console.error("Account status update error:", error);
    return res.redirect("/admin/users?error=invalid");
  }
});

app.get("/visitor-passes", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    const data = await getVisitorModuleData(req.query, pool);
    const flash = req.query.success
      ? { type: "success", message: "Visitor pass request submitted." }
      : req.query.approved
        ? { type: "success", message: "Visitor pass approved successfully." }
        : req.query.rejected
          ? { type: "success", message: "Visitor pass rejected." }
          : req.query.cancelled
            ? { type: "success", message: "Visitor pass request cancelled." }
            : req.query.error === "invalid"
              ? { type: "error", message: "Invalid visitor pass details provided." }
              : req.query.error === "notfound"
                ? { type: "error", message: "Visitor pass not found." }
                : req.query.error === "state"
                  ? { type: "error", message: "This pass cannot be updated in its current state." }
                  : req.query.error === "save"
                    ? { type: "error", message: "Unable to save visitor pass request." }
                    : null;
    return res.render("visitor_passes", {
      ...data,
      flash,
      visitorOverstayLimitLabel: formatHoursLabel(VISITOR_OVERSTAY_HOURS)
    });
  } catch (error) {
    console.error("Visitor passes page error:", error);
    return res.status(500).send("An error occurred loading visitor passes.");
  }
});

app.post("/visitor-passes/register", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  const visitorName = String(req.body.visitor_name || "").trim();
  const visitorType = normalizeVisitorType(req.body.visitor_type);
  const organization = String(req.body.organization || "").trim();
  const contactNumber = String(req.body.contact_number || "").trim();
  const plateNumber = String(req.body.plate_number || "").trim().toUpperCase();
  const vehicleType = String(req.body.vehicle_type || "").trim();
  const purpose = String(req.body.purpose || "").trim();
  const assignedZone = String(req.body.assigned_zone || "Visitor Zone").trim() || "Visitor Zone";
  const validFrom = parseDateTimeInput(req.body.valid_from);
  const validUntil = parseDateTimeInput(req.body.valid_until);

  if (!visitorName || !validFrom || !validUntil || validUntil <= validFrom) {
    return res.redirect("/visitor-passes?error=invalid");
  }

  try {
    let passCode = "";
    for (let i = 0; i < 6; i += 1) {
      const candidate = createVisitorPassCode();
      const [rows] = await pool.query("SELECT id FROM visitor_passes WHERE pass_code = ? LIMIT 1", [candidate]);
      if (!rows.length) {
        passCode = candidate;
        break;
      }
    }
    if (!passCode) {
      throw new Error("Unable to generate unique visitor pass code.");
    }
    const qrToken = createQrToken();
    const requestedBy = getAuthActorName(req);

    const [insertResult] = await pool.query(
      `INSERT INTO visitor_passes (
         pass_code,
         qr_token,
         visitor_type,
         visitor_name,
         organization,
         contact_number,
         plate_number,
         vehicle_type,
         purpose,
         requested_by,
         approval_status,
         pass_state,
         valid_from,
         valid_until,
         assigned_zone
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', ?, ?, ?)`,
      [
        passCode,
        qrToken,
        visitorType,
        visitorName,
        organization || null,
        contactNumber || null,
        plateNumber || null,
        vehicleType || null,
        purpose || null,
        requestedBy,
        validFrom,
        validUntil,
        assignedZone
      ]
    );

    const [rows] = await pool.query("SELECT * FROM visitor_passes WHERE id = ? LIMIT 1", [insertResult.insertId]);
    const visitorPass = rows.length ? rows[0] : null;
    if (visitorPass) {
      await createVisitorPendingApprovalAlert(pool, visitorPass, requestedBy);
      broadcastNotificationsUpdated("visitor-pass-pending", {
        visitor_pass_id: visitorPass.id,
        pass_code: visitorPass.pass_code
      });
    }
    return res.redirect("/visitor-passes?success=1");
  } catch (error) {
    console.error("Visitor pass register error:", error);
    return res.redirect("/visitor-passes?error=save");
  }
});

app.post("/visitor-passes/:id/approve", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  const visitorPassId = Number(req.params.id);
  if (!Number.isInteger(visitorPassId) || visitorPassId <= 0) {
    return res.redirect("/visitor-passes?error=invalid");
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    await expireStaleVisitorPasses(connection, getAuthActorName(req) || "visitor-approve");

    const [rows] = await connection.query(
      "SELECT id, approval_status, pass_state, valid_until FROM visitor_passes WHERE id = ? FOR UPDATE",
      [visitorPassId]
    );
    if (!rows.length) {
      if (connection) await connection.rollback().catch(() => {});
      return res.redirect("/visitor-passes?error=notfound");
    }

    const visitorPass = rows[0];
    if (![VISITOR_APPROVAL_STATUS.PENDING, VISITOR_APPROVAL_STATUS.APPROVED].includes(visitorPass.approval_status)) {
      if (connection) await connection.rollback().catch(() => {});
      return res.redirect("/visitor-passes?error=state");
    }

    const isExpired = visitorPass.valid_until && new Date(visitorPass.valid_until).getTime() < Date.now();
    await connection.query(
      `UPDATE visitor_passes
       SET
         approval_status = 'APPROVED',
         approved_by = ?,
         approved_at = NOW(),
         pass_state = ?,
         updated_at = NOW()
       WHERE id = ?`,
      [getAuthActorName(req), isExpired ? VISITOR_PASS_STATE.EXPIRED : VISITOR_PASS_STATE.ACTIVE, visitorPassId]
    );
    await resolveVisitorPendingApprovalAlert(connection, visitorPassId, getAuthActorName(req));
    await connection.commit();

    broadcastNotificationsUpdated("visitor-pass-approved", {
      visitor_pass_id: visitorPassId
    });
    return res.redirect("/visitor-passes?approved=1");
  } catch (error) {
    if (connection) await connection.rollback().catch(() => {});
    console.error("Visitor pass approve error:", error);
    return res.redirect("/visitor-passes?error=save");
  } finally {
    if (connection) connection.release();
  }
});

app.post("/visitor-passes/:id/reject", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  const visitorPassId = Number(req.params.id);
  const approvalNote = String(req.body.approval_note || req.body.reason || "").trim();
  if (!Number.isInteger(visitorPassId) || visitorPassId <= 0) {
    return res.redirect("/visitor-passes?error=invalid");
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [rows] = await connection.query(
      "SELECT id, approval_status, pass_state FROM visitor_passes WHERE id = ? FOR UPDATE",
      [visitorPassId]
    );
    if (!rows.length) {
      if (connection) await connection.rollback().catch(() => {});
      return res.redirect("/visitor-passes?error=notfound");
    }

    await connection.query(
      `UPDATE visitor_passes
       SET
         approval_status = 'REJECTED',
         pass_state = 'REVOKED',
         approval_note = ?,
         approved_by = ?,
         approved_at = NOW(),
         assigned_slot_id = NULL,
         updated_at = NOW()
       WHERE id = ?`,
      [approvalNote || "Rejected by staff.", getAuthActorName(req), visitorPassId]
    );
    await connection.query(
      "UPDATE parking_slots SET current_visitor_pass_id = NULL WHERE current_visitor_pass_id = ?",
      [visitorPassId]
    );
    await resolveVisitorPendingApprovalAlert(connection, visitorPassId, getAuthActorName(req));
    await connection.commit();

    broadcastNotificationsUpdated("visitor-pass-rejected", {
      visitor_pass_id: visitorPassId
    });
    return res.redirect("/visitor-passes?rejected=1");
  } catch (error) {
    if (connection) await connection.rollback().catch(() => {});
    console.error("Visitor pass reject error:", error);
    return res.redirect("/visitor-passes?error=save");
  } finally {
    if (connection) connection.release();
  }
});

app.post("/visitor-passes/:id/cancel", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  const visitorPassId = Number(req.params.id);
  if (!Number.isInteger(visitorPassId) || visitorPassId <= 0) {
    return res.redirect("/visitor-passes?error=invalid");
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [rows] = await connection.query(
      "SELECT id FROM visitor_passes WHERE id = ? FOR UPDATE",
      [visitorPassId]
    );
    if (!rows.length) {
      if (connection) await connection.rollback().catch(() => {});
      return res.redirect("/visitor-passes?error=notfound");
    }

    await connection.query(
      `UPDATE visitor_passes
       SET
         approval_status = 'CANCELLED',
         pass_state = 'REVOKED',
         assigned_slot_id = NULL,
         updated_at = NOW()
       WHERE id = ?`,
      [visitorPassId]
    );
    await connection.query(
      "UPDATE parking_slots SET current_visitor_pass_id = NULL WHERE current_visitor_pass_id = ?",
      [visitorPassId]
    );
    await resolveVisitorPendingApprovalAlert(connection, visitorPassId, getAuthActorName(req));
    await connection.commit();
    broadcastNotificationsUpdated("visitor-pass-cancelled", {
      visitor_pass_id: visitorPassId
    });
    return res.redirect("/visitor-passes?cancelled=1");
  } catch (error) {
    if (connection) await connection.rollback().catch(() => {});
    console.error("Visitor pass cancel error:", error);
    return res.redirect("/visitor-passes?error=save");
  } finally {
    if (connection) connection.release();
  }
});

app.get("/visitor-passes/:id/qr", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, qr_token, pass_code, approval_status, pass_state FROM visitor_passes WHERE id = ? LIMIT 1",
      [req.params.id]
    );
    if (!rows.length) return res.status(404).send("Visitor pass not found.");

    const qrPayload = `${APP_BASE_URL}/verify/visitor/${rows[0].qr_token}`;
    const png = await generateBrandedQrPng(qrPayload);
    res.type("png");
    return res.send(png);
  } catch (error) {
    console.error("Visitor QR generation error:", error);
    return res.status(500).send("Unable to generate visitor pass QR.");
  }
});

app.get("/api/visitor-passes/summary", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    await expireStaleVisitorPasses(pool, getAuthActorName(req) || "visitor-summary");
    const [summary, currentInside] = await Promise.all([
      getVisitorSummaryMetrics(pool),
      getCurrentVisitorInsideRows(pool, 50)
    ]);
    const overstayRows = currentInside.filter((row) => row.is_overstay);
    return res.json({
      ok: true,
      summary,
      current_inside_rows: currentInside,
      overstay_rows: overstayRows,
      visitor_overstay_limit_hours: VISITOR_OVERSTAY_HOURS
    });
  } catch (error) {
    console.error("Visitor summary API error:", error);
    return res.status(500).json({ ok: false, message: "Failed to load visitor summary." });
  }
});

app.get("/api/visitor-passes", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    await expireStaleVisitorPasses(pool, getAuthActorName(req) || "visitor-passes-api");
    const rows = await listVisitorPasses(req.query, pool);
    return res.json({ ok: true, rows });
  } catch (error) {
    console.error("Visitor passes API error:", error);
    return res.status(500).json({ ok: false, message: "Failed to load visitor passes.", rows: [] });
  }
});

app.get("/api/visitor-logs", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    const rows = await listVisitorScanLogs(req.query, pool);
    return res.json({ ok: true, rows });
  } catch (error) {
    console.error("Visitor logs API error:", error);
    return res.status(500).json({ ok: false, message: "Failed to load visitor logs.", rows: [] });
  }
});

// API: inside vehicles (for dashboard auto-refresh)
app.get("/api/inside-vehicles", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    const [insideVehicles, insideMetrics] = await Promise.all([
      getInsideVehiclesWithOverstay(pool, 20),
      getInsideVehicleMetrics(pool)
    ]);
    const overstayAlerts = insideVehicles.filter((item) => item.is_overstay);
    res.json({
      ok: true,
      insideVehicles,
      overstayAlerts,
      currentlyInside: insideMetrics.total_inside,
      overstayAlertCount: insideMetrics.overstay_count,
      overstayLimitHours: OVERSTAY_LIMIT_HOURS,
      overstayLimitLabel: formatHoursLabel(OVERSTAY_LIMIT_HOURS)
    });
  } catch (error) {
    console.error("Inside vehicles API error:", error);
    res.status(500).json({ ok: false, message: "Failed to fetch vehicles." });
  }
});

// API: full dashboard stats refresh (metrics + movement log)
app.get("/api/dashboard-stats", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const data = await getDashboardData();
    res.json({ ok: true, ...data });
  } catch (error) {
    console.error("Dashboard stats API error:", error);
    res.status(500).json({ ok: false, message: "Failed to fetch dashboard stats." });
  }
});

// API: notification center summary for current user
app.get("/api/notifications/summary", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    await refreshOperationalState(getAuthActorName(req) || "notification-summary");
    const [summary, operational] = await Promise.all([
      getNotificationSummaryForUser(req.authUser, pool),
      getOperationalAlertMetrics(pool)
    ]);
    res.json({
      ok: true,
      summary,
      operational,
      server_time: new Date().toISOString()
    });
  } catch (error) {
    console.error("Notification summary error:", error);
    res.status(500).json({
      ok: false,
      message: "Failed to load notification summary.",
      summary: {
        total: 0,
        active_total: 0,
        unread_total: 0,
        invalid_active: 0,
        full_zone_active: 0,
        low_slot_active: 0,
        pending_active: 0,
        suspicious_active: 0
      }
    });
  }
});

// API: notification listing with filters
app.get("/api/notifications", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    const listResult = await listAlertsForUser(req.authUser, {
      status: req.query.status,
      type: req.query.type,
      severity: req.query.severity,
      readState: req.query.read_state,
      query: req.query.q,
      from: req.query.from,
      to: req.query.to,
      limit: req.query.limit,
      offset: req.query.offset
    }, pool);

    res.json({
      ok: true,
      ...listResult
    });
  } catch (error) {
    console.error("Notification list error:", error);
    res.status(500).json({
      ok: false,
      message: "Failed to load notifications.",
      rows: [],
      total: 0
    });
  }
});

// API: mark notification as read for current user
app.post("/api/notifications/:id/read", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  const alertId = Number(req.params.id);
  if (!Number.isInteger(alertId) || alertId <= 0) {
    return res.status(400).json({ ok: false, message: "Invalid notification id." });
  }

  try {
    await markAlertReadForUser(pool, alertId, req.authUser?.id);
    const summary = await getNotificationSummaryForUser(req.authUser, pool);
    broadcastNotificationsUpdated("notification-read", {
      alert_id: alertId,
      by_user: req.authUser?.username || "user"
    });
    return res.json({ ok: true, alert_id: alertId, summary });
  } catch (error) {
    console.error("Notification read error:", error);
    return res.status(500).json({ ok: false, message: "Failed to mark notification as read." });
  }
});

// API: mark all visible notifications as read for current user
app.post("/api/notifications/read-all", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    const affected = await markAllAlertsReadForUser(pool, req.authUser);
    const summary = await getNotificationSummaryForUser(req.authUser, pool);
    broadcastNotificationsUpdated("notification-read-all", {
      by_user: req.authUser?.username || "user",
      affected
    });
    return res.json({ ok: true, affected, summary });
  } catch (error) {
    console.error("Notification read-all error:", error);
    return res.status(500).json({ ok: false, message: "Failed to mark all notifications as read." });
  }
});

// API: resolve alert (operational state change)
app.post("/api/notifications/:id/resolve", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  const alertId = Number(req.params.id);
  if (!Number.isInteger(alertId) || alertId <= 0) {
    return res.status(400).json({ ok: false, message: "Invalid notification id." });
  }

  try {
    const [rows] = await pool.query("SELECT id, status FROM alerts WHERE id = ? LIMIT 1", [alertId]);
    if (!rows.length) {
      return res.status(404).json({ ok: false, message: "Notification not found." });
    }
    if (rows[0].status === ALERT_STATUS.RESOLVED) {
      await markAlertReadForUser(pool, alertId, req.authUser?.id);
      return res.json({ ok: true, already_resolved: true, alert_id: alertId });
    }

    await pool.query(
      `UPDATE alerts
       SET
         status = 'resolved',
         resolved_at = NOW(),
         resolved_by = ?
       WHERE id = ?`,
      [getAuthActorName(req), alertId]
    );
    await markAlertReadForUser(pool, alertId, req.authUser?.id);
    const summary = await getNotificationSummaryForUser(req.authUser, pool);
    broadcastNotificationsUpdated("notification-resolved", {
      alert_id: alertId,
      by_user: req.authUser?.username || "user"
    });
    return res.json({ ok: true, alert_id: alertId, summary });
  } catch (error) {
    console.error("Notification resolve error:", error);
    return res.status(500).json({ ok: false, message: "Failed to resolve notification." });
  }
});

app.get("/api/admin-records", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const movementLogs = await getRecentMovementLogs(pool, 220);
    const summary = {
      total: movementLogs.length,
      valid: movementLogs.filter((row) => row.result === "VALID").length,
      entries: movementLogs.filter((row) => row.action === "ENTRY").length,
      exits: movementLogs.filter((row) => row.action === "EXIT").length
    };
    res.json({ ok: true, movementLogs, summary });
  } catch (error) {
    console.error("Admin records API error:", error);
    res.status(500).json({
      ok: false,
      message: "Failed to fetch gate records.",
      movementLogs: [],
      summary: { total: 0, valid: 0, entries: 0, exits: 0 }
    });
  }
});

// API: parking history filtered by day and time window
app.get("/api/parking-history", requireRole(USER_ROLES.ADMIN), async (req, res) => {
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
         AND DATE(sl.scanned_at + INTERVAL 8 HOUR) = ?
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
app.get("/api/parking-slot-history", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
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

app.get("/students", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const allowedPageSizes = new Set([10, 25, 50]);
    const allowedVehicleStates = new Set(["all", "with_vehicle", "without_vehicle"]);
    const allowedStickerStates = new Set(["all", "active", "expired", "revoked", "none"]);
    const allowedSortFields = Object.freeze({
      name: "s.full_name",
      course: "s.program",
      year: "CAST(s.year_level AS UNSIGNED)",
      registered: "s.created_at"
    });
    const allowedSortDirections = new Set(["asc", "desc"]);
    const requestedPage = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const requestedPageSize = Number.parseInt(req.query.page_size, 10) || 10;
    const pageSize = allowedPageSizes.has(requestedPageSize) ? requestedPageSize : 10;
    const filters = {
      q: String(req.query.q || "").trim().slice(0, 100),
      course: String(req.query.course || "").trim(),
      year_level: String(req.query.year_level || "").trim(),
      vehicle_status: allowedVehicleStates.has(String(req.query.vehicle_status || ""))
        ? String(req.query.vehicle_status)
        : "all",
      sticker_status: allowedStickerStates.has(String(req.query.sticker_status || ""))
        ? String(req.query.sticker_status)
        : "all",
      sort: Object.prototype.hasOwnProperty.call(allowedSortFields, String(req.query.sort || ""))
        ? String(req.query.sort)
        : "registered",
      direction: allowedSortDirections.has(String(req.query.direction || "").toLowerCase())
        ? String(req.query.direction).toLowerCase()
        : "desc"
    };

    const whereParts = [];
    const whereParams = [];
    if (filters.q) {
      const searchTerm = `%${filters.q}%`;
      whereParts.push(`(
        s.student_number LIKE ?
        OR s.full_name LIKE ?
        OR s.email LIKE ?
        OR s.program LIKE ?
        OR EXISTS (
          SELECT 1 FROM vehicles search_vehicle
          WHERE search_vehicle.student_id = s.id
            AND (search_vehicle.plate_number LIKE ? OR search_vehicle.model LIKE ?)
        )
      )`);
      whereParams.push(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm);
    }
    if (filters.course) {
      whereParts.push("s.program = ?");
      whereParams.push(filters.course);
    }
    if (filters.year_level) {
      whereParts.push("s.year_level = ?");
      whereParams.push(filters.year_level);
    }
    if (filters.vehicle_status === "with_vehicle") {
      whereParts.push("EXISTS (SELECT 1 FROM vehicles vehicle_filter WHERE vehicle_filter.student_id = s.id)");
    } else if (filters.vehicle_status === "without_vehicle") {
      whereParts.push("NOT EXISTS (SELECT 1 FROM vehicles vehicle_filter WHERE vehicle_filter.student_id = s.id)");
    }
    if (filters.sticker_status !== "all") {
      whereParts.push(`COALESCE((
        SELECT CASE
          WHEN sticker_filter.status = 'revoked' THEN 'revoked'
          WHEN sticker_filter.expires_at IS NOT NULL AND DATE(sticker_filter.expires_at) < DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR) THEN 'expired'
          ELSE 'active'
        END
        FROM vehicles sticker_vehicle
        INNER JOIN stickers sticker_filter ON sticker_filter.id = (
          SELECT latest_sticker.id
          FROM stickers latest_sticker
          WHERE latest_sticker.vehicle_id = sticker_vehicle.id
          ORDER BY latest_sticker.created_at DESC, latest_sticker.id DESC
          LIMIT 1
        )
        WHERE sticker_vehicle.student_id = s.id
        ORDER BY CASE
          WHEN sticker_filter.status = 'active'
            AND (sticker_filter.expires_at IS NULL OR DATE(sticker_filter.expires_at) >= DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR)) THEN 1
          WHEN sticker_filter.status = 'active' THEN 2
          ELSE 3
        END
        LIMIT 1
      ), 'none') = ?`);
      whereParams.push(filters.sticker_status);
    }

    const whereSql = whereParts.length ? `WHERE ${whereParts.join(" AND ")}` : "";
    const [summaryResult, countResult] = await Promise.all([
      pool.query(`
        SELECT
          (SELECT COUNT(*) FROM students) AS student_count,
          (SELECT COUNT(*) FROM vehicles) AS vehicle_count
      `),
      pool.query(`SELECT COUNT(*) AS total FROM students s ${whereSql}`, whereParams)
    ]);
    const total = Number(countResult[0][0]?.total || 0);
    const totalPages = Math.max(1, Math.ceil(total / pageSize));
    const page = Math.min(requestedPage, totalPages);
    const offset = (page - 1) * pageSize;
    const sortColumn = allowedSortFields[filters.sort];
    const sortDirection = filters.direction === "asc" ? "ASC" : "DESC";
    const [studentRows] = await pool.query(
      `SELECT s.* FROM students s ${whereSql} ORDER BY ${sortColumn} ${sortDirection}, s.id ${sortDirection} LIMIT ? OFFSET ?`,
      [...whereParams, pageSize, offset]
    );

    const studentIds = studentRows.map((student) => Number(student.id)).filter(Number.isFinite);
    let vehicleRows = [];
    let stickerRows = [];
    if (studentIds.length) {
      const placeholders = studentIds.map(() => "?").join(", ");
      const [vehicleResult] = await pool.query(
        `SELECT v.* FROM vehicles v WHERE v.student_id IN (${placeholders}) ORDER BY v.created_at ASC, v.id ASC`,
        studentIds
      );
      vehicleRows = vehicleResult;
      const vehicleIds = vehicleRows.map((vehicle) => Number(vehicle.id)).filter(Number.isFinite);
      if (vehicleIds.length) {
        const stickerPlaceholders = vehicleIds.map(() => "?").join(", ");
        const [stickerResult] = await pool.query(
          `SELECT id, vehicle_id, status, expires_at, created_at,
                  CASE
                    WHEN status = 'revoked' THEN 'revoked'
                    WHEN expires_at IS NOT NULL AND DATE(expires_at) < DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR) THEN 'expired'
                    ELSE 'active'
                  END AS display_status
           FROM stickers
           WHERE vehicle_id IN (${stickerPlaceholders})
           ORDER BY created_at DESC, id DESC`,
          vehicleIds
        );
        stickerRows = stickerResult;
      }
    }

    const latestStickerByVehicle = new Map();
    stickerRows.forEach((sticker) => {
      if (!latestStickerByVehicle.has(sticker.vehicle_id)) {
        latestStickerByVehicle.set(sticker.vehicle_id, {
          ...sticker,
          display_status: sticker.display_status
        });
      }
    });
    const vehiclesByStudent = new Map();
    vehicleRows.forEach((vehicle) => {
      const studentVehicles = vehiclesByStudent.get(vehicle.student_id) || [];
      studentVehicles.push({ ...vehicle, latest_sticker: latestStickerByVehicle.get(vehicle.id) || null });
      vehiclesByStudent.set(vehicle.student_id, studentVehicles);
    });
    // Attach vehicles array to each student
    const students = studentRows.map((student) => {
      const academicProgram = findAcademicProgram(student.program);
      const vehicles = vehiclesByStudent.get(student.id) || [];
      const stickerStates = vehicles.map((vehicle) => vehicle.latest_sticker?.display_status).filter(Boolean);
      const stickerStatus = stickerStates.includes("active")
        ? "active"
        : stickerStates.includes("expired")
          ? "expired"
          : stickerStates.includes("revoked")
            ? "revoked"
            : "none";
      return {
        ...student,
        program_is_official: Boolean(academicProgram),
        program_display: academicProgram?.code || academicProgram?.name || student.program || "",
        program_name: academicProgram?.name || student.program || "",
        year_level_label: getYearLevelLabel(student.year_level),
        vehicles,
        sticker_status: stickerStatus
      };
    });
    const flash = req.query.imported
      ? { type: "success", message: `${Number(req.query.imported) || 0} student record(s) imported successfully.` }
      : req.query.import_error
      ? { type: "error", message: String(req.query.import_error).slice(0, 220) }
      : req.query.success
      ? { type: "success", message: "Student saved successfully." }
      : req.query.vsuccess
      ? { type: "success", message: "Vehicle registered successfully." }
      : req.query.esuccess
      ? { type: "success", message: "Record updated successfully." }
      : req.query.error === "duplicate"
      ? { type: "error", message: "A student with that student number already exists." }
      : req.query.error === "vduplicate"
      ? { type: "error", message: "A vehicle with that plate number already exists." }
      : req.query.error === "academic"
      ? { type: "error", message: "Select a valid course and year level." }
      : req.query.error === "delete"
      ? { type: "error", message: "Unable to delete student — they may still have linked vehicles." }
      : req.query.deleted
      ? { type: "success", message: "Student deleted successfully." }
      : req.query.vdeleted
      ? { type: "success", message: "Vehicle deleted successfully." }
      : null;
    res.render("students", {
      students,
      flash,
      academicProgramGroups: ACADEMIC_PROGRAM_GROUPS,
      yearLevels: YEAR_LEVELS,
      filters,
      directorySummary: {
        students: Number(summaryResult[0][0]?.student_count || 0),
        vehicles: Number(summaryResult[0][0]?.vehicle_count || 0)
      },
      pagination: {
        page,
        pageSize,
        total,
        totalPages,
        from: total ? offset + 1 : 0,
        to: Math.min(offset + studentRows.length, total)
      },
      makeStudentDirectoryQuery: (overrides = {}) => {
        const values = { ...filters, page, page_size: pageSize, ...overrides };
        const params = new URLSearchParams();
        ["q", "course", "year_level", "vehicle_status", "sticker_status", "sort", "direction", "page", "page_size"].forEach((key) => {
          const value = values[key];
          if (value === undefined || value === null || value === "" || value === "all") return;
          params.set(key, String(value));
        });
        const query = params.toString();
        return `/students${query ? `?${query}` : ""}#directory`;
      }
    });
  } catch (error) {
    console.error("Students error:", error);
    res.status(500).send("An error occurred loading students.");
  }
});

app.get("/students/import/template", requireRole(USER_ROLES.ADMIN), (_req, res) => {
  const columns = STUDENT_IMPORT_COLUMNS.map((key) => ({ key, label: key }));
  const csv = stringifyCsv(columns, []);
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", "attachment; filename=naap-student-import-template.csv");
  return res.send(csv);
});

app.post("/students/import/preview", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const csvData = String(req.body.csv_data || "");
  try {
    const document = parseStudentImportCsv(csvData);
    const existingStudentNumbers = await getExistingStudentNumbers(document);
    const validation = validateStudentImportDocument(document, existingStudentNumbers);
    return res.json({
      ok: true,
      ...validation,
      previewToken: createStudentImportPreviewToken(req, csvData)
    });
  } catch (error) {
    return res.status(400).json({
      ok: false,
      message: String(error.message || "Unable to validate this CSV file.").slice(0, 220)
    });
  }
});

app.post("/students/import", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const csvData = String(req.body.csv_data || "");
  if (!verifyStudentImportPreviewToken(req, csvData, req.body.preview_token)) {
    return res.redirect(`/students?import_error=${encodeURIComponent("Preview expired or the file changed. Validate the CSV again before importing.")}#directory`);
  }

  let document;
  try {
    document = parseStudentImportCsv(csvData);
  } catch (error) {
    return res.redirect(`/students?import_error=${encodeURIComponent(error.message || "Invalid CSV file.")}#directory`);
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const existingStudentNumbers = await getExistingStudentNumbers(document, connection);
    const validation = validateStudentImportDocument(document, existingStudentNumbers);
    if (!validation.canImport) {
      const firstError = validation.headerErrors[0]
        || validation.rows.find((row) => row.issues.length)?.issues[0]
        || "The CSV contains invalid rows.";
      if (connection) await connection.rollback().catch(() => {});
      return res.redirect(`/students?import_error=${encodeURIComponent(firstError)}#directory`);
    }
    await saveStudentImportRows(validation.rows, connection, {
      updateEmail: document.headers.includes("email")
    });
    await connection.commit();
    await recordSecurityAudit(req, "DATA_IMPORTED", {
      targetType: "dataset",
      targetId: "students",
      metadata: {
        imported: validation.total,
        created: validation.createCount,
        updated: validation.updateCount
      }
    });
    return res.redirect(`/students?imported=${validation.total}#directory`);
  } catch (error) {
    if (connection) await connection.rollback().catch(() => {});
    console.error("Student CSV import error:", error);
    return res.redirect(`/students?import_error=${encodeURIComponent("Unable to import the CSV. No records were changed.")}#directory`);
  } finally {
    if (connection) connection.release();
  }
});

app.post("/students", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const { student_number, full_name, program, year_level, email, plate_number, model, color } = req.body;
  const normalizedProgram = String(program || "").trim();
  const normalizedYearLevel = String(year_level || "").trim();
  if (!isValidAcademicProgram(normalizedProgram) || !isValidYearLevel(normalizedYearLevel)) {
    return res.redirect("/students?error=academic");
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [result] = await connection.query(
      "INSERT INTO students (student_number, full_name, program, year_level, email) VALUES (?, ?, ?, ?, ?)",
      [student_number, full_name, normalizedProgram, normalizedYearLevel, email || null]
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
    if (connection) await connection.rollback().catch(() => {});
    if (error.code === "ER_DUP_ENTRY") {
      return res.redirect("/students?error=duplicate");
    }
    console.error("Create student error:", error);
    res.redirect("/students?error=1");
  } finally {
    if (connection) connection.release();
  }
});

app.post("/students/:id/edit", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const { student_number, full_name, program, year_level, email } = req.body;
  const normalizedProgram = String(program || "").trim();
  const normalizedYearLevel = String(year_level || "").trim();

  try {
    const [existingRows] = await pool.query(
      "SELECT program FROM students WHERE id = ? LIMIT 1",
      [req.params.id]
    );
    if (!existingRows.length) return res.redirect("/students?error=1");

    const isUnchangedLegacyProgram = normalizedProgram
      && normalizedProgram === String(existingRows[0].program || "").trim();
    if ((!isValidAcademicProgram(normalizedProgram) && !isUnchangedLegacyProgram)
        || !isValidYearLevel(normalizedYearLevel)) {
      return res.redirect("/students?error=academic");
    }

    await pool.query(
      "UPDATE students SET student_number = ?, full_name = ?, program = ?, year_level = ?, email = ? WHERE id = ?",
      [student_number, full_name, normalizedProgram, normalizedYearLevel, email || null, req.params.id]
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

app.post("/students/:id/delete", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    await pool.query("DELETE FROM students WHERE id = ?", [req.params.id]);
    res.redirect("/students?deleted=1");
  } catch (error) {
    console.error("Delete student error:", error);
    res.redirect("/students?error=delete");
  }
});

// /vehicles → redirect to unified page
app.get("/vehicles", requireRole(USER_ROLES.ADMIN), (req, res) => {
  res.redirect("/students");
});

app.post("/vehicles", requireRole(USER_ROLES.ADMIN), async (req, res) => {
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

app.post("/vehicles/:id/edit", requireRole(USER_ROLES.ADMIN), async (req, res) => {
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

app.post("/vehicles/:id/delete", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    await pool.query("DELETE FROM vehicles WHERE id = ?", [req.params.id]);
    res.redirect("/students?vdeleted=1");
  } catch (error) {
    console.error("Delete vehicle error:", error);
    res.redirect("/students?error=delete");
  }
});

async function loadOptionalStickerRows(label, sql) {
  try {
    const [rows] = await pool.query(sql);
    return { available: true, rows };
  } catch (error) {
    console.warn(`Sticker dashboard ${label} unavailable:`, error.code || error.message);
    return { available: false, rows: [] };
  }
}

async function getStickerManagementData() {
  const [vehicleResult, stickerResult] = await Promise.all([
    pool.query(
      `SELECT v.id, v.plate_number, v.model, s.full_name, s.student_number
       FROM vehicles v
       JOIN students s ON s.id = v.student_id
       ORDER BY v.id DESC`
    ),
    pool.query(
      `SELECT st.*, v.plate_number, v.model, s.full_name, s.student_number, s.email
       FROM stickers st
       JOIN vehicles v ON v.id = st.vehicle_id
       JOIN students s ON s.id = v.student_id
       ORDER BY st.id DESC`
    )
  ]);

  const [scanStats, qrHistory, latestEmailJobs, emailHistory] = await Promise.all([
    loadOptionalStickerRows(
      "scan history",
      `SELECT sticker_id, MAX(scanned_at) AS last_scanned_at,
              SUM(CASE WHEN result <> 'VALID' THEN 1 ELSE 0 END) AS rejected_scan_count
       FROM scan_logs
       WHERE sticker_id IS NOT NULL
       GROUP BY sticker_id`
    ),
    loadOptionalStickerRows(
      "QR replacement history",
      `SELECT sticker_id, COUNT(*) AS qr_rotation_count
       FROM sticker_qr_history
       GROUP BY sticker_id`
    ),
    loadOptionalStickerRows(
      "latest email status",
      `SELECT ej.id, ej.sticker_id, ej.status, ej.attempts, ej.last_error, ej.sent_at
       FROM email_delivery_jobs ej
       JOIN (
         SELECT sticker_id, MAX(id) AS latest_id
         FROM email_delivery_jobs
         GROUP BY sticker_id
       ) latest ON latest.latest_id = ej.id`
    ),
    loadOptionalStickerRows(
      "email history",
      `SELECT ej.id, ej.sticker_id, ej.recipient, ej.status, ej.attempts,
              ej.max_attempts, ej.last_error, ej.created_at, ej.sent_at,
              st.sticker_code, s.full_name
       FROM email_delivery_jobs ej
       JOIN stickers st ON st.id = ej.sticker_id
       JOIN vehicles v ON v.id = st.vehicle_id
       JOIN students s ON s.id = v.student_id
       ORDER BY ej.id DESC
       LIMIT 30`
    )
  ]);

  const scanStatsBySticker = new Map(scanStats.rows.map((row) => [Number(row.sticker_id), row]));
  const qrHistoryBySticker = new Map(qrHistory.rows.map((row) => [Number(row.sticker_id), row]));
  const latestEmailBySticker = new Map(latestEmailJobs.rows.map((row) => [Number(row.sticker_id), row]));
  const stickers = stickerResult[0].map((sticker) => {
    const stickerId = Number(sticker.id);
    const scan = scanStatsBySticker.get(stickerId);
    const rotation = qrHistoryBySticker.get(stickerId);
    const email = latestEmailBySticker.get(stickerId);
    return {
      ...sticker,
      email_job_id: email?.id || null,
      email_status: email?.status || null,
      email_attempts: Number(email?.attempts || 0),
      email_last_error: email?.last_error || null,
      email_sent_at: email?.sent_at || null,
      last_scanned_at: scan?.last_scanned_at || null,
      rejected_scan_count: Number(scan?.rejected_scan_count || 0),
      qr_rotation_count: Number(rotation?.qr_rotation_count || 0)
    };
  });

  return {
    vehicles: vehicleResult[0],
    stickers,
    emailDeliveries: emailHistory.rows,
    emailDeliveryAvailable: latestEmailJobs.available && emailHistory.available
  };
}

app.get("/stickers", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const { vehicles, stickers, emailDeliveries, emailDeliveryAvailable } = await getStickerManagementData();
    const flash = req.query.success
      ? { type: "success", message: "Sticker issued successfully." }
      : req.query.revoked
      ? { type: "success", message: "Sticker has been revoked." }
      : req.query.rotate === "success"
      ? { type: "success", message: "QR code replaced. The previous QR no longer grants access." }
      : req.query.rotate === "inactive"
      ? { type: "error", message: "Only an active, unexpired sticker can receive a replacement QR." }
      : req.query.rotate
      ? { type: "error", message: "The QR code could not be replaced." }
      : req.query.email === "queued"
      ? { type: "success", message: "QR email queued. Delivery continues safely in the background." }
      : req.query.email === "already_queued"
      ? { type: "success", message: "A QR email for this sticker is already queued." }
      : req.query.email === "retry_queued"
      ? { type: "success", message: "Email delivery was queued for another attempt." }
      : req.query.email === "no_email"
      ? { type: "error", message: "This student does not have a valid email address. Add one in Student Management first." }
      : req.query.email === "inactive"
      ? { type: "error", message: "Only an active, unexpired sticker QR code can be emailed." }
      : req.query.email === "not_configured"
      ? { type: "error", message: "Email delivery is not ready yet. Ask the system administrator to connect a mail service." }
      : req.query.email === "failed"
      ? { type: "error", message: "The email could not be sent. Check the mail server settings and try again." }
      : req.query.email === "not_found"
      ? { type: "error", message: "Sticker not found." }
      : req.query.email === "rate_limited"
      ? { type: "error", message: "Too many QR emails were requested. Wait a few minutes and try again." }
      : null;
    res.render("stickers", {
      stickers,
      vehicles,
      emailDeliveries,
      emailDeliveryAvailable,
      APP_BASE_URL,
      flash
    });
  } catch (error) {
    console.error("Stickers error:", error);
    res.status(500).send("An error occurred loading stickers.");
  }
});

app.post("/stickers", requireRole(USER_ROLES.ADMIN), async (req, res) => {
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

app.post("/stickers/:id/revoke", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    await pool.query("UPDATE stickers SET status = 'revoked' WHERE id = ?", [req.params.id]);
    await recordSecurityAudit(req, "STICKER_REVOKED", { targetType: "sticker", targetId: req.params.id });
    res.redirect("/stickers?revoked=1");
  } catch (error) {
    console.error("Revoke sticker error:", error);
    res.status(400).send("Unable to revoke sticker.");
  }
});

app.get("/stickers/:id/qr", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT qr_token FROM stickers WHERE id = ?", [req.params.id]);
    if (rows.length === 0) return res.status(404).send("Sticker not found");

    const requestBaseUrl = `${req.protocol}://${req.get("host")}`;
    const verifyUrl = `${requestBaseUrl}/verify/${rows[0].qr_token}`;
    const png = await generateBrandedQrPng(verifyUrl);
    res.type("png");
    res.send(png);
  } catch (error) {
    console.error("QR generation error:", error);
    res.status(500).send("Unable to generate QR code.");
  }
});

app.get("/stickers/:id/print", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const sticker = await getStickerEmailDetails(req.params.id);
    if (!sticker) return res.status(404).send("Sticker not found.");
    return res.render("sticker_print", { sticker, verifyUrl: `${APP_BASE_URL.replace(/\/+$/, "")}/verify/${sticker.qr_token}` });
  } catch (error) {
    console.error("Sticker print page error:", error);
    return res.status(500).send("Unable to prepare this sticker for printing.");
  }
});

app.post("/stickers/:id/rotate", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const stickerId = Number(req.params.id);
  const reason = String(req.body.reason || "Replaced by administrator").trim().slice(0, 255);
  if (!Number.isInteger(stickerId) || stickerId <= 0) return res.redirect("/stickers?rotate=not_found");
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [rows] = await connection.query(
      "SELECT id, qr_token, status, expires_at FROM stickers WHERE id = ? FOR UPDATE",
      [stickerId]
    );
    const sticker = rows[0];
    if (!isStickerEmailEligible(sticker)) {
      await connection.rollback();
      return res.redirect("/stickers?rotate=inactive");
    }
    await connection.query(
      `INSERT INTO sticker_qr_history (sticker_id, previous_qr_token, rotated_by_user_id, reason)
       VALUES (?, ?, ?, ?)`,
      [stickerId, sticker.qr_token, req.authUser.id, reason || null]
    );
    await connection.query("UPDATE stickers SET qr_token = ? WHERE id = ?", [createQrToken(), stickerId]);
    await connection.query(
      `UPDATE email_delivery_jobs
       SET status = 'failed', last_error = 'QR was replaced before delivery.', next_attempt_at = NULL
       WHERE sticker_id = ? AND status IN ('queued', 'retrying', 'sending')`,
      [stickerId]
    );
    await connection.commit();
    await recordSecurityAudit(req, "STICKER_QR_ROTATED", {
      targetType: "sticker",
      targetId: stickerId,
      metadata: { reason: reason || null }
    });
    return res.redirect("/stickers?rotate=success");
  } catch (error) {
    if (connection) await connection.rollback();
    console.error("QR rotation error:", error);
    return res.redirect("/stickers?rotate=failed");
  } finally {
    connection?.release();
  }
});

app.post("/stickers/:id/email", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const emailRateKey = `admin:${req.authUser.id}`;
  const emailRateState = qrEmailRateLimiter.check(emailRateKey);
  if (!emailRateState.allowed) {
    res.setHeader("Retry-After", String(emailRateState.retryAfterSeconds));
    await recordSecurityAudit(req, "STICKER_QR_EMAIL_RATE_LIMITED", {
      targetType: "sticker",
      targetId: req.params.id,
      outcome: "blocked"
    });
    return res.redirect("/stickers?email=rate_limited");
  }
  qrEmailRateLimiter.record(emailRateKey);
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const [lockedRows] = await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [req.params.id]);
    if (!lockedRows.length) {
      await connection.rollback();
      return res.redirect("/stickers?email=not_found");
    }
    const sticker = await getStickerEmailDetails(req.params.id, connection);
    if (!isStickerEmailEligible(sticker)) {
      await connection.rollback();
      return res.redirect("/stickers?email=inactive");
    }

    const recipient = normalizeEmailAddress(sticker.email);
    if (!recipient) {
      await connection.rollback();
      return res.redirect("/stickers?email=no_email");
    }
    const [existingRows] = await connection.query(
      `SELECT id FROM email_delivery_jobs
       WHERE sticker_id = ? AND status IN ('queued', 'retrying', 'sending')
       LIMIT 1`,
      [sticker.id]
    );
    if (existingRows.length) {
      await connection.rollback();
      return res.redirect("/stickers?email=already_queued");
    }
    const [jobResult] = await connection.query(
      `INSERT INTO email_delivery_jobs (sticker_id, recipient, requested_by_user_id)
       VALUES (?, ?, ?)`,
      [sticker.id, recipient, req.authUser.id]
    );
    await connection.commit();
    await recordSecurityAudit(req, "STICKER_QR_EMAIL_QUEUED", {
      targetType: "sticker",
      targetId: sticker.id,
      metadata: { student_id: sticker.student_id, job_id: jobResult.insertId }
    });
    setImmediate(() => processEmailDeliveryJobs());
    return res.redirect("/stickers?email=queued");
  } catch (error) {
    try { await connection.rollback(); } catch (_rollbackError) {}
    console.error("QR email queue error:", error);
    return res.redirect("/stickers?email=failed");
  } finally {
    connection?.release();
  }
});

app.post("/admin/email-deliveries/:id/retry", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  const jobId = Number(req.params.id);
  if (!Number.isInteger(jobId) || jobId <= 0) return res.redirect("/stickers?email=not_found");
  try {
    const [result] = await pool.query(
      `UPDATE email_delivery_jobs
       SET status = 'queued', attempts = 0, next_attempt_at = NOW(), last_error = NULL, sent_at = NULL
       WHERE id = ? AND status = 'failed'`,
      [jobId]
    );
    if (!result.affectedRows) return res.redirect("/stickers?email=not_found");
    await recordSecurityAudit(req, "STICKER_QR_EMAIL_RETRY_QUEUED", {
      targetType: "email_delivery",
      targetId: jobId
    });
    setImmediate(() => processEmailDeliveryJobs());
    return res.redirect("/stickers?email=retry_queued#email-deliveries");
  } catch (error) {
    console.error("Email retry error:", error);
    return res.redirect("/stickers?email=failed#email-deliveries");
  }
});

app.get("/verify/:token", async (req, res) => {
  try {
    const verification = await getVerificationState(req.params.token);
    const viewer = getSessionUser(req);
    const canViewPrivateDetails = viewer?.role === USER_ROLES.ADMIN || viewer?.role === USER_ROLES.GUARD;
    let lastAction = null;
    let currentSlot = null;
    let parkingSlotOverview = { slots: [], summary: { total: 0, available: 0, occupied: 0, disabled: 0 } };
    if (canViewPrivateDetails && verification.ok && verification.sticker) {
       const lastMovement = await getLastValidMovement(verification.sticker.id);
       if (lastMovement) lastAction = lastMovement.action;
       currentSlot = await getCurrentParkingSlotBySticker(verification.sticker.id);
       parkingSlotOverview = await getParkingSlotOverview();
    }
    const result = canViewPrivateDetails
      ? { ...verification, last_action: lastAction, current_slot: currentSlot }
      : {
          ok: Boolean(verification.ok),
          result: verification.ok ? "VALID" : "INVALID",
          message: verification.ok
            ? "This NAAP parking credential is active. Staff sign-in is required to view details."
            : "This NAAP parking credential could not be verified. Please contact authorized staff."
        };
    res.render("verify", { result, parkingSlotOverview });
  } catch (error) {
    console.error("Verify GET error:", error);
    res.status(500).send("An error occurred during verification.");
  }
});

app.post("/verify/:token/movement", requireRole(USER_ROLES.GUARD), async (req, res) => {
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
            assignedByGuard: getAuthActorName(req),
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

app.get("/scanner", requireRole(USER_ROLES.GUARD), (req, res) => {
  res.render("scanner");
});

app.get("/scanner/auto", requireRole(USER_ROLES.GUARD), (req, res) => {
  const deferEntryConfirmation = String(req.query.mode || "").trim().toLowerCase() === "remote";
  res.render("scanner_auto", {
    scanCooldownSeconds: SCAN_COOLDOWN_SECONDS,
    deferEntryConfirmation
  });
});

// API: live SSE stream for notification center updates
app.get("/api/notifications/events", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  const client = openEventStream({
    req, res, clients: notificationSseClients, sessionStore,
    keepaliveMs: AUTO_SCAN_SSE_KEEPALIVE_SECONDS * 1000
  });
  if (!await client.authorize()) return;

  client.send("connected", {
    ok: true,
    client_id: client.id,
    keepalive_seconds: AUTO_SCAN_SSE_KEEPALIVE_SECONDS,
    server_time: new Date().toISOString()
  });

  try {
    const summary = await getNotificationSummaryForUser(req.authUser, pool);
    client.send("notifications-summary", {
      summary,
      server_time: new Date().toISOString()
    });
  } catch (error) {
    client.send("notifications-summary", {
      summary: {
        total: 0,
        active_total: 0,
        unread_total: 0,
        invalid_active: 0,
        full_zone_active: 0,
        low_slot_active: 0,
        pending_active: 0,
        suspicious_active: 0
      },
      message: "Unable to load notification summary. Please try again.",
      server_time: new Date().toISOString()
    });
  }
});

// API: live SSE stream for guard queue + phone heartbeat updates
app.get("/api/auto-scan/events", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const client = openEventStream({
    req, res, clients: autoScanSseClients, sessionStore,
    keepaliveMs: AUTO_SCAN_SSE_KEEPALIVE_SECONDS * 1000
  });
  if (!await client.authorize()) return;

  client.send("connected", {
    ok: true,
    client_id: client.id,
    keepalive_seconds: AUTO_SCAN_SSE_KEEPALIVE_SECONDS,
    server_time: new Date().toISOString()
  });

  try {
    const snapshot = await getAutoScanHealthSnapshot(5);
    client.send("queue-health", {
      ...snapshot,
      reason: "initial-sync"
    });
  } catch (error) {
    client.send("queue-health", {
      rows: [],
      primary: null,
      total_devices: 0,
      online_devices: 0,
      offline_devices: 0,
      online_window_seconds: AUTO_SCAN_ONLINE_WINDOW_SECONDS,
      heartbeat_interval_seconds: AUTO_SCAN_HEARTBEAT_INTERVAL_SECONDS,
      server_time: new Date().toISOString(),
      reason: "initial-sync-error",
      message: "Unable to load health snapshot. Please try again."
    });
  }
});

// API: phone scanner heartbeat for guard queue health
app.post("/api/auto-scan/heartbeat", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const gate = normalizeGateId(req.body.gate || req.body.gate_id || "Main Gate");
  const deviceId = normalizeAutoScanDeviceId(
    req.body.device_id || req.body.deviceId || req.headers["x-device-id"]
  );
  const markScanReceived = req.body.mark_scan_received === true
    || String(req.body.mark_scan_received || "").toLowerCase() === "true"
    || String(req.body.mark_scan_received || "") === "1";

  try {
    await upsertAutoScanHeartbeat({
      deviceId,
      gateId: gate,
      actorName: getAuthActorName(req),
      markScanReceived
    });
    const snapshot = await getAutoScanHealthSnapshot(5);
    res.json({
      ok: true,
      device_id: deviceId,
      gate_id: gate,
      ...snapshot
    });
    broadcastAutoScanHealth(markScanReceived ? "scan-heartbeat" : "heartbeat");
  } catch (error) {
    console.error("Auto scan heartbeat error:", error);
    res.status(500).json({ ok: false, message: "Failed to update scanner heartbeat." });
  }
});

// API: guard queue health snapshot (phone online/offline + last scan)
app.get("/api/auto-scan/health", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const limit = Number(req.query.limit) || 12;
  try {
    const snapshot = await getAutoScanHealthSnapshot(limit);
    res.json({
      ok: true,
      ...snapshot
    });
  } catch (error) {
    console.error("Auto scan health fetch error:", error);
    res.status(500).json({ ok: false, message: "Failed to load scanner health.", rows: [], primary: null });
  }
});

// API: phone camera auto-detection (ENTRY requires guard confirmation, EXIT is auto-recorded)
app.post("/api/auto-scan/detect", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const token = normalizeQrTokenInput(req.body.token);
  const gate = normalizeGateId(req.body.gate || "Main Gate");
  const deviceId = normalizeAutoScanDeviceId(
    req.body.device_id || req.body.deviceId || req.headers["x-device-id"]
  );
  const deferEntryConfirmation = req.body.defer_entry_confirmation === true
    || String(req.body.defer_entry_confirmation || "").toLowerCase() === "true"
    || String(req.body.defer_entry_confirmation || "") === "1";
  const behaviorRisk = normalizeBehaviorRiskPayload(req.body);
  const riskNote = buildRiskSummaryNote(behaviorRisk);
  const snapshotDataUrl = typeof req.body.snapshot_data_url === "string"
    ? req.body.snapshot_data_url
    : "";
  const guardName = getAuthActorName(req);

  if (!token) {
    return res.status(400).json({
      ok: false,
      message: "Missing QR token.",
      behavior_risk: behaviorRisk
    });
  }

  try {
    try {
      await upsertAutoScanHeartbeat({
        deviceId,
        gateId: gate,
        actorName: guardName,
        markScanReceived: true
      });
      broadcastAutoScanHealth("scan-detected");
    } catch (heartbeatError) {
      console.warn("Auto scan detect heartbeat warning:", heartbeatError.message);
    }

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
        `Auto camera verification failed ${riskNote}`.trim(),
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
      await createInvalidQrAlert(pool, {
        result: verification.result || "INVALID",
        reason: verification.message || "Automatic camera verification failed.",
        qrValue: token,
        gate,
        source: "camera_phone",
        actorName: guardName,
        relatedVehicleId: verification.sticker?.vehicle_id_ref || verification.sticker?.vehicle_id || null,
        scanLogId: scanLog?.id || null
      });
      await evaluateSuspiciousScanSignals(pool, {
        qrValue: token,
        gate,
        source: "camera_phone",
        actorName: guardName,
        result: verification.result || "INVALID",
        scanLogId: scanLog?.id || null
      });
      broadcastNotificationsUpdated("auto-invalid-verification", {
        gate_id: gate,
        qr_value: token,
        result: verification.result || "INVALID"
      });

      return res.json({
        ...verification,
        sticker: getAutoStickerPayload(verification.sticker),
        action: "VERIFY",
        movement_saved: false,
        requires_confirmation: false,
        behavior_risk: behaviorRisk,
        snapshot_path: scanLog?.snapshot_path || snapshotPath || null,
        scan_log_id: scanLog?.id || null,
        scanned_at: scanLog?.scanned_at || null
      });
    }

    const sticker = verification.sticker;
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const expiredPendingIds = await expireStalePendingAutoEntries(connection);
      await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [sticker.id]);

      const lastMovement = await getLastValidMovement(sticker.id, connection);
      const duplicateInfo = getDuplicateScanInfo(lastMovement);
      if (duplicateInfo.duplicate) {
        await connection.rollback();
        await reportDuplicateScan({
          qrValue: token,
          gate,
          source: "camera_phone",
          actorName: guardName,
          deniedReason: `Duplicate phone scan blocked within ${SCAN_COOLDOWN_SECONDS} seconds cooldown.`
        });
        return res.json({
          ok: false,
          result: "VALID",
          message: `Scan ignored to prevent duplicate. Please wait ${SCAN_COOLDOWN_SECONDS} seconds before rescanning.`,
          duplicate_scan: true,
          cooldown_seconds: SCAN_COOLDOWN_SECONDS,
          seconds_since_last_scan: duplicateInfo.secondsSinceLastScan,
          action: lastMovement?.action || null,
          sticker: getAutoStickerPayload(sticker),
          behavior_risk: behaviorRisk,
          scanned_at: lastMovement?.scanned_at || null
        });
      }

      const action = lastMovement && lastMovement.action === "ENTRY" ? "EXIT" : "ENTRY";

      if (action === "ENTRY") {
        if (deferEntryConfirmation) {
          const existingPending = await getPendingAutoEntryBySticker(sticker.id, connection, true);
          if (existingPending) {
            await connection.rollback();
            return res.json({
              ok: true,
              result: "VALID",
              action: "ENTRY",
              movement_saved: false,
              requires_confirmation: false,
              queued_for_guard: true,
              pending_entry_id: existingPending.id,
              message: "Entry is already queued for guard confirmation.",
              sticker: getAutoStickerPayload(sticker),
              behavior_risk: behaviorRisk,
              snapshot_path: existingPending.snapshot_path || null,
              queued_at: existingPending.created_at || null
            });
          }

          if (!snapshotDataUrl) {
            throw new Error("Snapshot capture failed. Keep the camera active and scan again.");
          }
          const snapshotPath = await saveSnapshotDataUrl(snapshotDataUrl, "auto-entry-pending");
          if (!snapshotPath) {
            throw new Error("Snapshot capture failed. Keep the camera active and scan again.");
          }

          const queuedEntry = await createPendingAutoEntryWithDb(connection, {
            stickerId: sticker.id,
            studentId: sticker.student_id_ref || null,
            vehicleId: sticker.vehicle_id_ref || sticker.vehicle_id || null,
            qrValue: token,
            gateId: gate,
            snapshotPath,
            requestedByGuard: guardName,
            scanSource: "camera_phone"
          });

          await connection.commit();
          broadcastExpiredPendingEntries(expiredPendingIds);
          broadcastNotificationsUpdated("pending-entry-created", {
            pending_entry_id: queuedEntry?.id || null,
            gate_id: gate,
            qr_value: token
          });
          broadcastAutoScanSse("pending-entry-created", {
            pending_entry_id: queuedEntry?.id || null,
            pending_entry: queuedEntry || null,
            gate_id: gate,
            device_id: deviceId,
            server_time: new Date().toISOString()
          });
          return res.json({
            ok: true,
            result: "VALID",
            action: "ENTRY",
            movement_saved: false,
            requires_confirmation: false,
            queued_for_guard: true,
            pending_entry_id: queuedEntry?.id || null,
            message: "ENTRY detected. Waiting for guard confirmation on monitor console.",
            sticker: getAutoStickerPayload(sticker),
            behavior_risk: behaviorRisk,
            snapshot_path: queuedEntry?.snapshot_path || snapshotPath || null,
            queued_at: queuedEntry?.created_at || null
          });
        }

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
          behavior_risk: behaviorRisk,
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
        `Auto camera exit ${riskNote}`.trim(),
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
      broadcastExpiredPendingEntries(expiredPendingIds);
      await evaluateZoneCapacityAlerts(pool, guardName || "auto-exit");
      broadcastNotificationsUpdated("movement-recorded", {
        movement_action: "EXIT",
        gate_id: gate,
        qr_value: token
      });
      broadcastAutoScanSse("pending-entry-sync", {
        reason: "exit-recorded",
        gate_id: gate,
        device_id: deviceId,
        server_time: new Date().toISOString()
      });

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
        behavior_risk: behaviorRisk,
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
      message: error.message || "Failed to process automatic scan.",
      behavior_risk: behaviorRisk
    });
  }
});

// API: guard confirms ENTRY after auto-detection and slot selection
app.post("/api/auto-scan/confirm-entry", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const token = normalizeQrTokenInput(req.body.token);
  const gate = String(req.body.gate || "Main Gate").trim() || "Main Gate";
  const slotId = Number(req.body.slot_id);
  const behaviorRisk = normalizeBehaviorRiskPayload(req.body);
  const riskNote = buildRiskSummaryNote(behaviorRisk);
  const snapshotDataUrl = typeof req.body.snapshot_data_url === "string"
    ? req.body.snapshot_data_url
    : "";
  const guardName = getAuthActorName(req);

  if (!token) {
    return res.status(400).json({
      ok: false,
      message: "Missing QR token.",
      behavior_risk: behaviorRisk
    });
  }
  if (!Number.isInteger(slotId) || slotId <= 0) {
    return res.status(400).json({
      ok: false,
      message: "Please choose a parking slot before recording entry.",
      behavior_risk: behaviorRisk
    });
  }

  try {
    const verification = await getVerificationState(token);
    if (!verification.ok) {
      await createInvalidQrAlert(pool, {
        result: verification.result || "INVALID",
        reason: verification.message || "Entry confirmation failed: sticker no longer valid.",
        qrValue: token,
        gate,
        source: "camera_phone",
        actorName: guardName
      });
      await evaluateSuspiciousScanSignals(pool, {
        qrValue: token,
        gate,
        source: "camera_phone",
        actorName: guardName,
        result: verification.result || "INVALID"
      });
      broadcastNotificationsUpdated("auto-confirm-invalid", {
        gate_id: gate,
        qr_value: token,
        result: verification.result || "INVALID"
      });
      return res.status(400).json({
        ok: false,
        message: verification.message,
        behavior_risk: behaviorRisk
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
        await reportDuplicateScan({
          qrValue: token,
          gate,
          source: "camera_phone",
          actorName: guardName,
          deniedReason: `Duplicate entry confirm blocked within ${SCAN_COOLDOWN_SECONDS} seconds cooldown.`
        });
        return res.status(400).json({
          ok: false,
          duplicate_scan: true,
          message: `Scan ignored to prevent duplicate. Please wait ${SCAN_COOLDOWN_SECONDS} seconds before rescanning.`,
          cooldown_seconds: SCAN_COOLDOWN_SECONDS,
          seconds_since_last_scan: duplicateInfo.secondsSinceLastScan,
          behavior_risk: behaviorRisk
        });
      }

      if (lastMovement && lastMovement.action === "ENTRY") {
        await connection.rollback();
        await evaluateSuspiciousScanSignals(pool, {
          qrValue: token,
          gate,
          source: "camera_phone",
          actorName: guardName,
          result: "VALID",
          deniedReason: "Vehicle is already marked as inside during auto entry confirmation."
        });
        broadcastNotificationsUpdated("entry-denied-already-inside", {
          gate_id: gate,
          qr_value: token
        });
        return res.status(400).json({
          ok: false,
          duplicate_movement: true,
          message: "Vehicle is already marked as inside. Record EXIT first.",
          behavior_risk: behaviorRisk
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
        `Auto camera entry confirmed by guard ${riskNote}`.trim(),
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
      await evaluateZoneCapacityAlerts(pool, guardName || "auto-confirm-entry");
      broadcastNotificationsUpdated("movement-recorded", {
        movement_action: "ENTRY",
        gate_id: gate,
        qr_value: token
      });

      return res.json({
        ok: true,
        movement_saved: true,
        result: "VALID",
        action: "ENTRY",
        message: `ENTRY recorded. Assigned slot ${assignedSlot.slot_code}.`,
        sticker: getAutoStickerPayload(sticker),
        behavior_risk: behaviorRisk,
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
    res.status(400).json({
      ok: false,
      message: error.message || "Failed to record entry.",
      behavior_risk: behaviorRisk
    });
  }
});

// API: pending phone-scanned ENTRY requests for laptop guard monitoring
app.get("/api/auto-scan/pending-entries", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const limit = Number(req.query.limit) || 25;
  try {
    const expiredPendingIds = await expireStalePendingAutoEntries();
    broadcastExpiredPendingEntries(expiredPendingIds);
    const rows = await listPendingAutoEntries(limit);
    res.json({
      ok: true,
      rows,
      pending_count: rows.length,
      expiry_minutes: AUTO_PENDING_EXPIRY_MINUTES
    });
  } catch (error) {
    console.error("Pending auto entry list error:", error);
    res.status(500).json({ ok: false, message: "Failed to load pending auto entries.", rows: [] });
  }
});

// API: guard confirms a pending phone-scanned ENTRY and assigns slot
app.post("/api/auto-scan/pending-entries/:id/confirm", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const entryId = Number(req.params.id);
  const slotId = Number(req.body.slot_id);
  const guardName = getAuthActorName(req);
  const requestedGate = String(req.body.gate || "").trim();

  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).json({ ok: false, message: "Invalid pending entry id." });
  }
  if (!Number.isInteger(slotId) || slotId <= 0) {
    return res.status(400).json({ ok: false, message: "Please choose a parking slot before confirming entry." });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const expiredPendingIds = await expireStalePendingAutoEntries(connection);

    const pendingEntry = await getPendingAutoEntryByIdForUpdate(entryId, connection);
    if (!pendingEntry) {
      if (connection) await connection.rollback().catch(() => {});
      return res.status(404).json({ ok: false, message: "Pending entry was not found." });
    }
    if (pendingEntry.status !== "PENDING") {
      if (connection) await connection.rollback().catch(() => {});
      return res.status(400).json({
        ok: false,
        message: `This request is already ${String(pendingEntry.status).toLowerCase()}.`
      });
    }
    if (!pendingEntry.sticker_id || !pendingEntry.qr_value) {
      await connection.query(
        `UPDATE auto_scan_queue
         SET
           status = 'REJECTED',
           confirmed_by_guard = ?,
           confirmed_at = NOW(),
           confirm_note = 'Missing sticker/token data for confirmation'
         WHERE id = ?`,
        [guardName, entryId]
      );
      await resolvePendingApprovalAlert(connection, entryId, guardName);
      await connection.commit();
      broadcastExpiredPendingEntries(expiredPendingIds);
      broadcastNotificationsUpdated("pending-entry-rejected", {
        pending_entry_id: entryId,
        reason: "missing-token-data"
      });
      broadcastAutoScanSse("pending-entry-updated", {
        pending_entry_id: entryId,
        status: "REJECTED",
        reason: "missing-token-data",
        server_time: new Date().toISOString()
      });
      return res.status(400).json({ ok: false, message: "Pending entry data is incomplete." });
    }

    const verification = await getVerificationState(pendingEntry.qr_value);
    if (!verification.ok) {
      await connection.query(
        `UPDATE auto_scan_queue
         SET
           status = 'REJECTED',
           confirmed_by_guard = ?,
           confirmed_at = NOW(),
           confirm_note = ?
         WHERE id = ?`,
        [guardName, verification.message || "Sticker is not valid anymore.", entryId]
      );
      await resolvePendingApprovalAlert(connection, entryId, guardName);
      await createInvalidQrAlert(connection, {
        result: verification.result || "INVALID",
        reason: verification.message || "Pending entry was rejected: sticker no longer valid.",
        qrValue: pendingEntry.qr_value,
        gate: pendingEntry.gate_id || requestedGate || "Main Gate",
        source: pendingEntry.scan_source || "camera_phone",
        actorName: guardName,
        relatedVehicleId: pendingEntry.vehicle_id || null
      });
      await evaluateSuspiciousScanSignals(connection, {
        qrValue: pendingEntry.qr_value,
        gate: pendingEntry.gate_id || requestedGate || "Main Gate",
        source: pendingEntry.scan_source || "camera_phone",
        actorName: guardName,
        result: verification.result || "INVALID",
        deniedReason: "Pending entry was denied because sticker is no longer valid."
      });
      await connection.commit();
      broadcastExpiredPendingEntries(expiredPendingIds);
      broadcastNotificationsUpdated("pending-entry-rejected", {
        pending_entry_id: entryId,
        reason: "sticker-invalid"
      });
      broadcastAutoScanSse("pending-entry-updated", {
        pending_entry_id: entryId,
        status: "REJECTED",
        reason: "sticker-invalid",
        server_time: new Date().toISOString()
      });
      return res.status(400).json({ ok: false, message: verification.message || "Sticker is no longer valid." });
    }

    const sticker = verification.sticker;
    await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [sticker.id]);
    const lastMovement = await getLastValidMovement(sticker.id, connection);
    if (lastMovement && lastMovement.action === "ENTRY") {
      await connection.query(
        `UPDATE auto_scan_queue
         SET
           status = 'REJECTED',
           confirmed_by_guard = ?,
           confirmed_at = NOW(),
           confirm_note = 'Vehicle already has an active ENTRY record'
         WHERE id = ?`,
        [guardName, entryId]
      );
      await resolvePendingApprovalAlert(connection, entryId, guardName);
      await evaluateSuspiciousScanSignals(connection, {
        qrValue: pendingEntry.qr_value,
        gate: pendingEntry.gate_id || requestedGate || "Main Gate",
        source: pendingEntry.scan_source || "camera_phone",
        actorName: guardName,
        result: "VALID",
        deniedReason: "Pending entry rejected because vehicle is already marked inside."
      });
      await connection.commit();
      broadcastExpiredPendingEntries(expiredPendingIds);
      broadcastNotificationsUpdated("pending-entry-rejected", {
        pending_entry_id: entryId,
        reason: "already-inside"
      });
      broadcastAutoScanSse("pending-entry-updated", {
        pending_entry_id: entryId,
        status: "REJECTED",
        reason: "already-inside",
        server_time: new Date().toISOString()
      });
      return res.status(409).json({
        ok: false,
        message: "Vehicle is already marked as inside. Record EXIT first."
      });
    }

    const assignedSlot = await assignParkingSlot(connection, sticker.id, slotId);
    const finalGate = requestedGate || pendingEntry.gate_id || "Main Gate";
    const scanLog = await insertScanLogWithDb(
      connection,
      sticker.id,
      "VALID",
      "ENTRY",
      finalGate,
      "Auto phone scan entry confirmed on monitor",
      {
        gateId: finalGate,
        slotId: assignedSlot.id,
        qrValue: pendingEntry.qr_value,
        studentId: sticker.student_id_ref || pendingEntry.student_id || null,
        vehicleId: sticker.vehicle_id_ref || sticker.vehicle_id || pendingEntry.vehicle_id || null,
        assignedArea: assignedSlot.zone || null,
        assignedByGuard: guardName,
        scanSource: "camera_phone",
        snapshotPath: pendingEntry.snapshot_path || null,
        status: "AUTHORIZED"
      }
    );

    await connection.query(
      `UPDATE auto_scan_queue
       SET
         status = 'CONFIRMED',
         gate_id = ?,
         confirmed_by_guard = ?,
         confirmed_at = NOW(),
         assigned_slot_id = ?,
         linked_scan_log_id = ?,
         confirm_note = 'Confirmed by guard monitor'
       WHERE id = ?`,
      [finalGate, guardName, assignedSlot.id, scanLog?.id || null, entryId]
    );
    await resolvePendingApprovalAlert(connection, entryId, guardName);

    await connection.commit();
    broadcastExpiredPendingEntries(expiredPendingIds);
    await evaluateZoneCapacityAlerts(pool, guardName || "pending-confirm");
    broadcastNotificationsUpdated("pending-entry-confirmed", {
      pending_entry_id: entryId,
      gate_id: finalGate,
      slot_code: assignedSlot.slot_code
    });
    broadcastAutoScanSse("pending-entry-updated", {
      pending_entry_id: entryId,
      status: "CONFIRMED",
      reason: "confirmed-by-guard",
      gate_id: finalGate,
      slot_id: assignedSlot.id,
      slot_code: assignedSlot.slot_code,
      server_time: new Date().toISOString()
    });
    broadcastAutoScanSse("pending-entry-sync", {
      reason: "entry-confirmed",
      server_time: new Date().toISOString()
    });
    return res.json({
      ok: true,
      movement_saved: true,
      action: "ENTRY",
      pending_entry_id: entryId,
      message: `ENTRY recorded. Assigned slot ${assignedSlot.slot_code}.`,
      sticker: getAutoStickerPayload(sticker),
      parking_slot: assignedSlot.slot_code,
      assigned_area: assignedSlot.zone,
      assigned_by_guard: guardName,
      gate_id: finalGate,
      snapshot_path: scanLog?.snapshot_path || pendingEntry.snapshot_path || null,
      scan_log_id: scanLog?.id || null,
      scanned_at: scanLog?.scanned_at || null
    });
  } catch (error) {
    if (connection) await connection.rollback().catch(() => {});
    console.error("Confirm pending auto entry error:", error);
    return res.status(400).json({ ok: false, message: error.message || "Failed to confirm pending entry." });
  } finally {
    if (connection) connection.release();
  }
});

// API: guard cancels a pending phone-scanned ENTRY request
app.post("/api/auto-scan/pending-entries/:id/cancel", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const entryId = Number(req.params.id);
  const guardName = getAuthActorName(req);
  const reason = String(req.body.reason || "Cancelled by guard monitor.").trim();

  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).json({ ok: false, message: "Invalid pending entry id." });
  }

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const expiredPendingIds = await expireStalePendingAutoEntries(connection);
    const pendingEntry = await getPendingAutoEntryByIdForUpdate(entryId, connection);
    if (!pendingEntry) {
      if (connection) await connection.rollback().catch(() => {});
      return res.status(404).json({ ok: false, message: "Pending entry was not found." });
    }
    if (pendingEntry.status !== "PENDING") {
      if (connection) await connection.rollback().catch(() => {});
      return res.status(400).json({
        ok: false,
        message: `This request is already ${String(pendingEntry.status).toLowerCase()}.`
      });
    }

    await connection.query(
      `UPDATE auto_scan_queue
       SET
         status = 'CANCELLED',
         confirmed_by_guard = ?,
         confirmed_at = NOW(),
         confirm_note = ?
       WHERE id = ?`,
      [guardName, reason || "Cancelled by guard monitor.", entryId]
    );
    await resolvePendingApprovalAlert(connection, entryId, guardName);
    await connection.commit();
    broadcastExpiredPendingEntries(expiredPendingIds);
    broadcastNotificationsUpdated("pending-entry-cancelled", {
      pending_entry_id: entryId
    });
    broadcastAutoScanSse("pending-entry-updated", {
      pending_entry_id: entryId,
      status: "CANCELLED",
      reason: "cancelled-by-guard",
      server_time: new Date().toISOString()
    });
    return res.json({ ok: true, cancelled: true, pending_entry_id: entryId });
  } catch (error) {
    if (connection) await connection.rollback().catch(() => {});
    console.error("Cancel pending auto entry error:", error);
    return res.status(400).json({ ok: false, message: error.message || "Failed to cancel pending entry." });
  } finally {
    if (connection) connection.release();
  }
});

// API: search students/vehicles by plate, name, or student number
app.get("/api/gate-lookup", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const q = String(req.query.q || "").trim();
  if (!q) return res.json({ ok: false, message: "No query provided.", results: [] });

  try {
    await expireStaleVisitorPasses(pool, getAuthActorName(req) || "gate-lookup");
    const like = `%${q}%`;
    const [studentResults] = await pool.query(
      `SELECT
         'student' AS entity_type,
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
         NULL AS visitor_pass_id,
         NULL AS visitor_type,
         NULL AS approval_status,
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
          OR s.qr_token LIKE ?
          OR s.sticker_code LIKE ?
       ORDER BY st.full_name ASC
       LIMIT 10`,
      [like, like, like, like, like]
    );

    const [visitorResults] = await pool.query(
      `SELECT
         'visitor' AS entity_type,
         NULL AS vehicle_id,
         vp.plate_number,
         vp.vehicle_type AS model,
         NULL AS color,
         vp.visitor_name AS full_name,
         vp.pass_code AS student_number,
         CASE
           WHEN vp.pass_state = 'EXPIRED' THEN 'expired'
           WHEN vp.approval_status = 'PENDING' THEN 'pending'
           WHEN vp.approval_status IN ('REJECTED', 'CANCELLED') THEN 'revoked'
           WHEN vp.pass_state IN ('ACTIVE', 'INSIDE', 'EXITED') THEN 'active'
           ELSE LOWER(vp.pass_state)
         END AS sticker_status,
         vp.pass_code AS sticker_code,
         vp.qr_token,
         vp.valid_until AS expires_at,
         vp.id AS visitor_pass_id,
         vp.visitor_type,
         vp.approval_status,
         (
           SELECT vsl2.action
           FROM visitor_scan_logs vsl2
           WHERE vsl2.visitor_pass_id = vp.id
             AND vsl2.result = 'VALID'
             AND vsl2.action IN ('ENTRY', 'EXIT')
           ORDER BY vsl2.scanned_at DESC, vsl2.id DESC
           LIMIT 1
         ) AS last_action,
         (
           SELECT ps.slot_code
           FROM parking_slots ps
           WHERE ps.current_visitor_pass_id = vp.id
           LIMIT 1
         ) AS current_slot
       FROM visitor_passes vp
       WHERE vp.visitor_name LIKE ?
          OR vp.pass_code LIKE ?
          OR vp.plate_number LIKE ?
          OR vp.qr_token LIKE ?
          OR vp.organization LIKE ?
       ORDER BY vp.created_at DESC
       LIMIT 10`,
      [like, like, like, like, like]
    );

    const results = [...studentResults, ...visitorResults]
      .sort((a, b) => String(a.full_name || "").localeCompare(String(b.full_name || "")))
      .slice(0, 14);
    res.json({ ok: true, results });
  } catch (error) {
    console.error("Gate lookup error:", error);
    res.status(500).json({ ok: false, message: "Search failed.", results: [] });
  }
});

app.get("/api/parking-slots", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    const scope = String(req.query.scope || "all").toLowerCase();
    const slots = await getAvailableParkingSlots(pool, { scope });
    res.json({ ok: true, slots });
  } catch (error) {
    console.error("Parking slots API error:", error);
    res.status(500).json({ ok: false, message: "Failed to load parking slots.", slots: [] });
  }
});

app.get("/api/parking-slot-overview", requireRole(USER_ROLES.ADMIN, USER_ROLES.GUARD), async (req, res) => {
  try {
    const scope = String(req.query.scope || "all").toLowerCase();
    const overview = await getParkingSlotOverview(pool, { scope });
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

// API: manually record ENTRY or EXIT for student sticker or visitor pass token
app.post("/api/manual-movement", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const token = normalizeQrTokenInput(req.body.token);
  const { action, gate, slot_id } = req.body;
  const selectedAction = String(action || "").toUpperCase();
  const slotId = slot_id ? Number(slot_id) : null;
  const entityType = String(req.body.entity_type || "student").trim().toLowerCase();
  const actorName = getAuthActorName(req);
  const gateName = gate || "Manual Gate";

  if (!token) return res.status(400).json({ ok: false, message: "Missing sticker token." });
  if (!["ENTRY", "EXIT"].includes(selectedAction)) {
    return res.status(400).json({ ok: false, message: "Invalid action." });
  }

  try {
    if (entityType === "visitor") {
      const verification = await getVisitorPassVerificationState(token, pool);
      if (!verification.ok) {
        const deniedLog = verification.visitor_pass?.id
          ? await insertVisitorScanLog(
              verification.visitor_pass.id,
              verification.result || "INVALID",
              "DENIED",
              gateName,
              verification.message || "Visitor movement denied.",
              {
                gateId: gateName,
                qrValue: token,
                assignedByGuard: actorName,
                scanSource: "manual",
                status: "DENIED"
              }
            )
          : null;

        await createVisitorAccessAlert(pool, {
          result: verification.result || "INVALID",
          reason: verification.message || "Visitor access denied.",
          qrValue: token,
          gate: gateName,
          source: "manual",
          actorName,
          relatedVisitorPassId: verification.visitor_pass?.id || null,
          passCode: verification.visitor_pass?.pass_code || null
        });
        broadcastNotificationsUpdated("visitor-manual-denied", {
          gate_id: gateName,
          qr_value: token,
          result: verification.result || "INVALID",
          visitor_scan_log_id: deniedLog?.id || null
        });
        return res.json({ ok: false, message: verification.message, movement_saved: false });
      }

      const visitorPass = verification.visitor_pass;
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        await connection.query("SELECT id FROM visitor_passes WHERE id = ? FOR UPDATE", [visitorPass.id]);

        const lastMovement = await getLastVisitorMovement(visitorPass.id, connection);
        if (lastMovement && lastMovement.action === selectedAction) {
          await connection.rollback();
          await createVisitorAccessAlert(pool, {
            result: "INVALID",
            reason: `Visitor ${selectedAction} denied: last movement is already ${selectedAction}.`,
            qrValue: token,
            gate: gateName,
            source: "manual",
            actorName,
            relatedVisitorPassId: visitorPass.id,
            passCode: visitorPass.pass_code
          });
          broadcastNotificationsUpdated("visitor-duplicate-movement-blocked", {
            gate_id: gateName,
            qr_value: token,
            action: selectedAction,
            visitor_pass_id: visitorPass.id
          });
          return res.json({
            ok: false,
            movement_saved: false,
            duplicate_movement: true,
            message: `Visitor's last recorded movement is already ${selectedAction}.`
          });
        }

        let currentSlot = null;
        if (selectedAction === "ENTRY") {
          if (!slotId) {
            await connection.rollback();
            return res.status(400).json({ ok: false, message: "Please select a visitor parking slot before recording entry." });
          }
          currentSlot = await assignVisitorParkingSlot(connection, visitorPass.id, slotId);
        } else {
          currentSlot = await getCurrentParkingSlotByVisitorPass(visitorPass.id, connection);
        }

        const movementLog = await insertVisitorScanLogWithDb(
          connection,
          visitorPass.id,
          "VALID",
          selectedAction,
          gateName,
          "Visitor movement recorded via Gate Console",
          {
            gateId: gateName,
            slotId: currentSlot?.id || null,
            qrValue: token,
            assignedByGuard: actorName,
            scanSource: "manual",
            status: "AUTHORIZED"
          }
        );

        if (selectedAction === "ENTRY") {
          await connection.query(
            `UPDATE visitor_passes
             SET
               pass_state = 'INSIDE',
               last_entry_at = NOW(),
               assigned_slot_id = ?,
               assigned_zone = ?,
               updated_at = NOW()
             WHERE id = ?`,
            [currentSlot?.id || null, currentSlot?.zone || visitorPass.assigned_zone || "Visitor Zone", visitorPass.id]
          );
        } else {
          await releaseVisitorParkingSlot(connection, visitorPass.id);
          await connection.query(
            `UPDATE visitor_passes
             SET
               pass_state = 'EXITED',
               last_exit_at = NOW(),
               updated_at = NOW()
             WHERE id = ?`,
            [visitorPass.id]
          );
        }

        await connection.commit();
        await evaluateZoneCapacityAlerts(pool, actorName || "manual-visitor-movement");
        await evaluateVisitorOverstayAlerts(pool, actorName || "manual-visitor-movement");
        broadcastNotificationsUpdated("visitor-movement-recorded", {
          movement_action: selectedAction,
          gate_id: gateName,
          qr_value: token,
          visitor_pass_id: visitorPass.id
        });

        return res.json({
          ok: true,
          movement_saved: true,
          entity_type: "visitor",
          action: selectedAction,
          parking_slot: currentSlot?.slot_code || null,
          visitor_pass_id: visitorPass.id,
          pass_code: visitorPass.pass_code,
          scan_log_id: movementLog?.id || null,
          scanned_at: movementLog?.scanned_at || null
        });
      } catch (err) {
        await connection.rollback();
        throw err;
      } finally {
        connection.release();
      }
    }

    const verification = await getVerificationState(token);
    if (!verification.ok) {
      const invalidScanLog = await insertScanLog(
        verification.sticker?.id || null,
        verification.result || "INVALID",
        "VERIFY",
        gateName,
        verification.message || "Manual movement rejected: invalid sticker.",
        {
          gateId: gateName,
          qrValue: token,
          studentId: verification.sticker?.student_id_ref || null,
          vehicleId: verification.sticker?.vehicle_id_ref || verification.sticker?.vehicle_id || null,
          assignedByGuard: actorName,
          scanSource: "manual",
          status: normalizeScanStatus(verification.result || "INVALID")
        }
      );
      await createInvalidQrAlert(pool, {
        result: verification.result || "INVALID",
        reason: verification.message || "Manual movement rejected due to invalid sticker.",
        qrValue: token,
        gate: gateName,
        source: "manual",
        actorName,
        relatedVehicleId: verification.sticker?.vehicle_id_ref || verification.sticker?.vehicle_id || null,
        scanLogId: invalidScanLog?.id || null
      });
      await evaluateSuspiciousScanSignals(pool, {
        qrValue: token,
        gate: gateName,
        source: "manual",
        actorName,
        result: verification.result || "INVALID",
        scanLogId: invalidScanLog?.id || null
      });
      broadcastNotificationsUpdated("manual-invalid-movement", {
        gate_id: gateName,
        qr_value: token,
        result: verification.result || "INVALID"
      });
      return res.json({ ok: false, message: verification.message, movement_saved: false });
    }

    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      await connection.query("SELECT id FROM stickers WHERE id = ? FOR UPDATE", [verification.sticker.id]);

      const lastMovement = await getLastValidMovement(verification.sticker.id, connection);
      if (lastMovement && lastMovement.action === selectedAction) {
        await connection.rollback();
        await evaluateSuspiciousScanSignals(pool, {
          qrValue: token,
          gate: gateName,
          source: "manual",
          actorName,
          result: "VALID",
          deniedReason: `Manual ${selectedAction} denied: last movement is already ${selectedAction}.`
        });
        broadcastNotificationsUpdated("manual-duplicate-movement-blocked", {
          gate_id: gateName,
          qr_value: token,
          action: selectedAction
        });
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
        gateName,
        "Recorded via Gate Console",
        {
          gateId: gateName,
          slotId: currentSlot?.id || null,
          qrValue: token,
          studentId: verification.sticker.student_id_ref || null,
          vehicleId: verification.sticker.vehicle_id_ref || verification.sticker.vehicle_id || null,
          assignedArea: currentSlot?.zone || null,
          assignedByGuard: actorName,
          scanSource: "manual",
          status: "AUTHORIZED"
        }
      );

      if (selectedAction === "EXIT") {
        await releaseParkingSlot(connection, verification.sticker.id);
      }

      await connection.commit();
      await evaluateZoneCapacityAlerts(pool, actorName || "manual-movement");
      broadcastNotificationsUpdated("movement-recorded", {
        movement_action: selectedAction,
        gate_id: gateName,
        qr_value: token
      });

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
app.post("/api/force-exit", requireRole(USER_ROLES.ADMIN), async (req, res) => {
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
          assignedByGuard: getAuthActorName(req),
          scanSource: "manual",
          status: "AUTHORIZED"
        }
      );
      await releaseParkingSlot(connection, sticker_id);
      await connection.commit();
      await evaluateZoneCapacityAlerts(pool, getAuthActorName(req) || "force-exit");
      broadcastNotificationsUpdated("movement-recorded", {
        movement_action: "EXIT",
        gate_id: gate || "Admin Console",
        sticker_id
      });

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

app.get("/reports", requireRole(USER_ROLES.ADMIN), async (req, res) => {
  try {
    const filters = buildReportFilters(req.query);
    const data = await getReportsData(filters);
    const format = String(req.query.format || "").trim().toLowerCase();

    if (format === "csv" || format === "excel") {
      const header = [
        "event_time",
        "pass_type",
        "identity_number",
        "identity_name",
        "plate_number",
        "vehicle_type",
        "zone",
        "gate",
        "action",
      ];
      const lines = [header.join(",")];
      for (const row of data.exportRows) {
        lines.push(
          [
            escapeCsvCell(row.scanned_at),
            escapeCsvCell(row.pass_type),
            escapeCsvCell(row.identity_number),
            escapeCsvCell(row.identity_name),
            escapeCsvCell(row.plate_number),
            escapeCsvCell(row.vehicle_type),
            escapeCsvCell(row.zone),
            escapeCsvCell(row.gate),
            escapeCsvCell(row.action),
          ].join(",")
        );
      }

      const filename = `naap-analytics-movement-${filters.from}-to-${filters.to}.csv`;
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      return res.send(lines.join("\n"));
    }

    if (format === "analytics_csv") {
      const lines = [];
      lines.push("NAAP Parking Analytics");
      lines.push(`Date Range,${escapeCsvCell(`${data.filters.from} to ${data.filters.to}`)}`);
      lines.push(`Preset,${escapeCsvCell(data.filters.preset)}`);
      lines.push(`Gate Filter,${escapeCsvCell(data.filters.gate)}`);
      lines.push(`Zone Filter,${escapeCsvCell(data.filters.zone)}`);
      lines.push(`Pass Type Filter,${escapeCsvCell(data.filters.pass_type)}`);
      lines.push(`Vehicle Type Filter,${escapeCsvCell(data.filters.vehicle_type)}`);
      lines.push("");

      lines.push("Summary");
      lines.push("metric,value");
      lines.push(`total_vehicles_today,${escapeCsvCell(data.summary.total_vehicles_today)}`);
      lines.push(`active_parked_vehicles,${escapeCsvCell(data.summary.active_parked_vehicles)}`);
      lines.push(`busiest_hour_today,${escapeCsvCell(data.summary.busiest_hour_today)}`);
      lines.push(`most_used_zone,${escapeCsvCell(data.summary.most_used_zone)}`);
      lines.push(`average_parking_duration,${escapeCsvCell(data.summary.average_parking_duration_label)}`);
      lines.push(`total_overstay_cases,${escapeCsvCell(data.summary.total_overstay_cases)}`);
      lines.push(`available_slots_now,${escapeCsvCell(data.summary.available_slots_now)}`);
      lines.push("");

      lines.push("Busiest Hours");
      lines.push("hour_slot,total_scans");
      data.charts.busiestHours.forEach((row) => {
        lines.push([escapeCsvCell(row.bucket), escapeCsvCell(row.total)].join(","));
      });
      lines.push("");

      lines.push("Zone Usage");
      lines.push("zone,total_entries,share_percent");
      data.charts.zoneUsage.forEach((row) => {
        lines.push([escapeCsvCell(row.zone), escapeCsvCell(row.total), escapeCsvCell(row.percent)].join(","));
      });
      lines.push("");

      lines.push("Overstay Frequency (Daily)");
      lines.push("date,total_overstay_cases");
      data.charts.overstayByDay.forEach((row) => {
        lines.push([escapeCsvCell(row.bucket), escapeCsvCell(row.total)].join(","));
      });
      lines.push("");

      lines.push("Slot Trend");
      lines.push("bucket,entries,exits,occupied,available");
      data.charts.slotTrends.forEach((row) => {
        lines.push([
          escapeCsvCell(row.bucket),
          escapeCsvCell(row.entries),
          escapeCsvCell(row.exits),
          escapeCsvCell(row.occupied),
          escapeCsvCell(row.available)
        ].join(","));
      });

      const filename = `naap-analytics-summary-${filters.from}-to-${filters.to}.csv`;
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      return res.send(lines.join("\n"));
    }

    const printMode = format === "print";
    res.render("reports", {
      ...data,
      printMode
    });
  } catch (error) {
    console.error("Reports error:", error);
    res.status(500).send("An error occurred loading reports.");
  }
});

app.post("/api/scan", requireRole(USER_ROLES.GUARD), async (req, res) => {
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

app.post("/api/scanner-metrics", requireRole(USER_ROLES.GUARD), async (req, res) => {
  try {
    const metric = normalizeScannerMetricPayload(req.body, req);
    const inserted = await insertScannerMetric(metric);
    return res.json({ ok: true, inserted, event_id: metric.eventId });
  } catch (error) {
    console.error("Scanner metric error:", error);
    return res.status(400).json({ ok: false, message: "Unable to save scanner performance metric." });
  }
});

app.post("/api/scanner-metrics/batch", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const items = Array.isArray(req.body.metrics) ? req.body.metrics.slice(0, 100) : [];
  if (!items.length) return res.json({ ok: true, accepted_event_ids: [] });
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const acceptedEventIds = [];
    for (const item of items) {
      const metric = normalizeScannerMetricPayload({ ...item, network_mode: item.network_mode || "offline" }, req);
      await insertScannerMetric(metric, connection);
      acceptedEventIds.push(metric.eventId);
    }
    await connection.commit();
    return res.json({ ok: true, accepted_event_ids: acceptedEventIds });
  } catch (error) {
    if (connection) await connection.rollback().catch(() => {});
    console.error("Scanner metric batch error:", error);
    return res.status(400).json({ ok: false, message: "Unable to synchronize scanner metrics." });
  } finally {
    if (connection) connection.release();
  }
});

// PWA Offline Sync: Download active roster to local DB
app.get("/api/sync-roster", requireRole(USER_ROLES.GUARD), async (req, res) => {
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
        st.student_number,
        (
          SELECT sl.action FROM scan_logs sl
          WHERE sl.sticker_id = s.id AND sl.result = 'VALID' AND sl.action IN ('ENTRY', 'EXIT')
          ORDER BY sl.scanned_at DESC, sl.id DESC LIMIT 1
        ) AS last_action,
        (
          SELECT ps.slot_code FROM parking_slots ps
          WHERE ps.current_sticker_id = s.id LIMIT 1
        ) AS current_slot
      FROM stickers s
      JOIN vehicles v ON v.id = s.vehicle_id
      JOIN students st ON st.id = v.student_id
      WHERE s.status = 'active'
        AND (s.expires_at IS NULL OR s.expires_at >= DATE(UTC_TIMESTAMP() + INTERVAL 8 HOUR))
    `);
    res.json({ ok: true, roster });
  } catch (error) {
    console.error("Sync roster error:", error);
    res.status(500).json({ ok: false, message: "Failed to download roster." });
  }
});

// PWA Offline Sync: Upload pending outbox to main DB
app.post("/api/sync-queue", requireRole(USER_ROLES.GUARD), async (req, res) => {
  const movements = Array.isArray(req.body.movements) ? req.body.movements.slice(0, 100) : [];
  if (!movements.length) return res.json({ ok: true, accepted_event_ids: [], results: [] });
  if (movements.some(movement => !movement || typeof movement !== "object" || Array.isArray(movement))) {
    return res.status(400).json({ ok: false, message: "Invalid offline movement data." });
  }
  movements.sort((a, b) => Number(a.offline_timestamp || 0) - Number(b.offline_timestamp || 0));

  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();
    const acceptedEventIds = [];
    const results = [];
    for (const movement of movements) {
      const legacyEventId = `legacy-${crypto.createHash("sha256").update(JSON.stringify(movement)).digest("hex").slice(0, 48)}`;
      const eventId = normalizeClientEventId(movement.event_id || legacyEventId, "offline");
      const [receiptRows] = await connection.query("SELECT id FROM offline_sync_receipts WHERE event_id = ? LIMIT 1", [eventId]);
      if (receiptRows.length) {
        acceptedEventIds.push(eventId);
        results.push({ event_id: eventId, status: "duplicate" });
        continue;
      }

      const token = normalizeQrTokenInput(movement.token);
      const [stickerRows] = token ? await connection.query(
        `SELECT s.id, s.status, s.expires_at, v.id AS vehicle_id, st.id AS student_id
         FROM stickers s JOIN vehicles v ON v.id = s.vehicle_id JOIN students st ON st.id = v.student_id
         WHERE s.qr_token = ? LIMIT 1 FOR UPDATE`,
        [token]
      ) : [[]];
      const sticker = stickerRows[0];
      if (!sticker || sticker.status !== "active" || isExpired(sticker.expires_at)) {
        await connection.query(
          "INSERT INTO offline_sync_receipts (event_id, action, synced_by_user_id, occurred_at) VALUES (?, 'REJECTED', ?, NOW())",
          [eventId, req.authUser.id]
        );
        acceptedEventIds.push(eventId);
        results.push({ event_id: eventId, status: "rejected", reason: "Sticker is no longer valid." });
        continue;
      }

      const lastMovement = await getLastValidMovement(sticker.id, connection);
      const expectedAction = lastMovement?.action === "ENTRY" ? "EXIT" : "ENTRY";
      const requestedAction = String(movement.action || "").trim().toUpperCase();
      const offlineDate = new Date(Number(movement.offline_timestamp));
      const isOlderMovement = lastMovement?.scanned_at && Number.isFinite(offlineDate.getTime())
        && offlineDate.getTime() < new Date(lastMovement.scanned_at).getTime();
      if (requestedAction !== expectedAction || isOlderMovement) {
        await connection.query(
          "INSERT INTO offline_sync_receipts (event_id, sticker_id, action, synced_by_user_id, occurred_at) VALUES (?, ?, 'REJECTED', ?, NOW())",
          [eventId, sticker.id, req.authUser.id]
        );
        acceptedEventIds.push(eventId);
        results.push({ event_id: eventId, status: "rejected", reason: "Offline movement conflicts with the current entry/exit state. Review the movement log." });
        continue;
      }
      const action = requestedAction;
      const gate = normalizeGateId(movement.gate || "Offline Scan");
      let scannedAt = new Date();
      if (!Number.isNaN(offlineDate.getTime()) && Math.abs(Date.now() - offlineDate.getTime()) <= 30 * 24 * 60 * 60 * 1000) {
        scannedAt = offlineDate;
      }
      let currentSlot = action === "EXIT" ? await getCurrentParkingSlotBySticker(sticker.id, connection) : null;
      if (action === "ENTRY") {
        const [availableSlots] = await connection.query(
          `SELECT id
           FROM parking_slots
           WHERE status = 'available'
             AND current_sticker_id IS NULL
             AND current_visitor_pass_id IS NULL
           ORDER BY zone ASC, slot_code ASC
           LIMIT 1
           FOR UPDATE`
        );
        if (availableSlots.length) {
          currentSlot = await assignParkingSlot(connection, sticker.id, availableSlots[0].id);
        }
      }
      const scanLog = await insertScanLogWithDb(
        connection,
        sticker.id,
        "VALID",
        action,
        gate,
        action === "ENTRY" && !currentSlot
            ? "Synced from offline device; no parking slot was available"
            : "Synced from offline device",
        {
          gateId: gate,
          slotId: currentSlot?.id || null,
          qrValue: token,
          studentId: sticker.student_id,
          vehicleId: sticker.vehicle_id,
          assignedArea: currentSlot?.zone || null,
          assignedByGuard: getAuthActorName(req),
          scanSource: "offline_sync",
          status: "AUTHORIZED"
        }
      );
      await connection.query("UPDATE scan_logs SET scanned_at = ? WHERE id = ?", [scannedAt, scanLog.id]);
      if (action === "EXIT") await releaseParkingSlot(connection, sticker.id);
      await connection.query(
        `INSERT INTO offline_sync_receipts (event_id, sticker_id, action, scan_log_id, synced_by_user_id, occurred_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [eventId, sticker.id, action, scanLog.id, req.authUser.id, scannedAt]
      );
      acceptedEventIds.push(eventId);
      results.push({
        event_id: eventId,
        status: action === "ENTRY" && !currentSlot ? "synced_no_slot" : "synced",
        action,
        parking_slot: currentSlot?.slot_code || null
      });
    }
    await connection.commit();
    await evaluateZoneCapacityAlerts(pool, getAuthActorName(req) || "offline-sync");
    broadcastNotificationsUpdated("offline-queue-synced", {
      synced_count: acceptedEventIds.length
    });
    await recordSecurityAudit(req, "OFFLINE_QUEUE_SYNCED", {
      metadata: {
        received: movements.length,
        accepted: acceptedEventIds.length,
        rejected: results.filter(result => result.status === "rejected").map(result => ({
          ...result,
          requested_action: movements.find(movement => movement.event_id === result.event_id)?.action || null
        }))
      }
    });
    return res.json({ ok: true, synced_count: acceptedEventIds.length, accepted_event_ids: acceptedEventIds, results });
  } catch (error) {
    if (connection) await connection.rollback().catch(() => {});
    console.error("Sync queue error:", error);
    return res.status(500).json({ ok: false, message: "Failed to sync offline queue." });
  } finally {
    if (connection) connection.release();
  }
});

app.use((err, req, res, next) => {
  if (!err) return next();

  const isApi = req.path.startsWith("/api/");

  if (err instanceof multer.MulterError) {
    const message = err.code === "LIMIT_FILE_SIZE"
      ? "The backup file is too large. Maximum size is 20 MB."
      : "The backup upload could not be accepted.";
    if (isApi) return res.status(400).json({ ok: false, message });
    if (req.path === "/admin/data/restore-preview") {
      return res.redirect(`/admin/data?error=${encodeURIComponent(message)}`);
    }
    return res.status(400).send(message);
  }

  if (err.type === "entity.too.large") {
    if (isApi) {
      return res.status(413).json({
        ok: false,
        message: "Scan snapshot is too large. Keep the camera closer to the QR and try again."
      });
    }
    return res.status(413).send("Request payload is too large.");
  }

  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    if (isApi) {
      return res.status(400).json({ ok: false, message: "Invalid JSON payload." });
    }
    return res.status(400).send("Invalid request payload.");
  }

  console.error("Unhandled request error:", err);
  if (isApi) {
    return res.status(err.status || 500).json({
      ok: false,
      message: err.message || "Server error while handling request."
    });
  }
  return res.status(err.status || 500).send("An unexpected server error occurred.");
});

async function startServer() {
  try {
    const migratedSnapshots = await preparePrivateSnapshotStorage();
    if (migratedSnapshots > 0) {
      console.log(`Moved ${migratedSnapshots} scan snapshot(s) to protected storage.`);
    }
    await ensureDatabaseSchema();
    await sessionStore.onReady();
    setImmediate(() => {
      processEmailDeliveryJobs();
      suspendInactiveGuards().catch((error) => console.error("Inactive guard cleanup error:", error.message));
      runDataRetentionCleanup();
      ensureAutomatedRecoveryBackup().catch((error) => console.error("Automated backup error:", error.message));
    });
    const emailTimer = setInterval(processEmailDeliveryJobs, EMAIL_WORKER_INTERVAL_MS);
    const maintenanceTimer = setInterval(() => {
      suspendInactiveGuards().catch((error) => console.error("Inactive guard cleanup error:", error.message));
      runDataRetentionCleanup();
    }, 6 * 60 * 60 * 1000);
    const backupTimer = setInterval(() => {
      ensureAutomatedRecoveryBackup().catch((error) => console.error("Automated backup error:", error.message));
    }, 60 * 60 * 1000);
    emailTimer.unref();
    maintenanceTimer.unref();
    backupTimer.unref();
    app.listen(PORT, () => {
      console.log(`NAAP Parking app running at ${APP_BASE_URL}`);
    });
  } catch (error) {
    console.error("Failed to initialize database schema:", error.message);
    process.exit(1);
  }
}

startServer();
