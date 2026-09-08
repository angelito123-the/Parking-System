const nodemailer = require("nodemailer");

class MailConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = "MailConfigurationError";
    this.code = "MAIL_NOT_CONFIGURED";
  }
}

function normalizeEmailAddress(value) {
  const email = String(value || "").trim();
  if (
    !email
    || email.length > 254
    || /[\r\n]/.test(email)
    || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  ) {
    return null;
  }
  return email;
}

function getSmtpConfig(env = process.env) {
  const host = String(env.SMTP_HOST || "").trim();
  const port = Number(env.SMTP_PORT || 587);
  const user = String(env.SMTP_USER || "").trim();
  const pass = String(env.SMTP_PASS || "");
  const from = String(env.SMTP_FROM || user).trim();

  if (!host || !Number.isInteger(port) || port < 1 || port > 65535 || !from) {
    throw new MailConfigurationError(
      "SMTP_HOST, a valid SMTP_PORT, and SMTP_FROM (or SMTP_USER) are required."
    );
  }
  if (/[\r\n]/.test(from)) {
    throw new MailConfigurationError("SMTP_FROM must not contain line breaks.");
  }
  if ((user && !pass) || (!user && pass)) {
    throw new MailConfigurationError("SMTP_USER and SMTP_PASS must be configured together.");
  }

  const secureValue = String(env.SMTP_SECURE || "").trim().toLowerCase();
  const secure = secureValue
    ? ["1", "true", "yes", "on"].includes(secureValue)
    : port === 465;

  return {
    from,
    transport: {
      host,
      port,
      secure,
      requireTLS: !secure,
      disableFileAccess: true,
      disableUrlAccess: true,
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 30_000,
      tls: { minVersion: "TLSv1.2" },
      ...(user ? { auth: { user, pass } } : {})
    }
  };
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function sendStudentQrEmail(details, options = {}) {
  const recipient = normalizeEmailAddress(details?.to);
  if (!recipient) throw new TypeError("A valid student email address is required.");
  if (!Buffer.isBuffer(details?.qrPng) || details.qrPng.length === 0) {
    throw new TypeError("A QR PNG attachment is required.");
  }

  const smtp = options.smtp || getSmtpConfig(options.env);
  const transporter = options.transporter || nodemailer.createTransport(smtp.transport);
  const studentName = String(details.studentName || "Student").trim() || "Student";
  const studentNumber = String(details.studentNumber || "").trim();
  const stickerCode = String(details.stickerCode || "Parking sticker")
    .replace(/[\r\n]+/g, " ")
    .trim()
    .slice(0, 120) || "Parking sticker";
  const plateNumber = String(details.plateNumber || "").trim();
  let verifyUrl = "";
  try {
    const parsedVerifyUrl = new URL(String(details.verifyUrl || "").trim());
    if (["http:", "https:"].includes(parsedVerifyUrl.protocol)) verifyUrl = parsedVerifyUrl.href;
  } catch (_error) {
    verifyUrl = "";
  }
  const safeFilenameCode = stickerCode.replace(/[^a-z0-9_-]+/gi, "-").replace(/^-+|-+$/g, "") || "parking-sticker";
  const filename = `${safeFilenameCode}-qr.png`;
  const detailLines = [
    studentNumber ? `Student number: ${studentNumber}` : null,
    `Sticker code: ${stickerCode}`,
    plateNumber ? `Vehicle plate: ${plateNumber}` : null,
    verifyUrl ? `Verification link: ${verifyUrl}` : null
  ].filter(Boolean);

  return transporter.sendMail({
    from: smtp.from,
    to: recipient,
    subject: `Your NAAP parking QR code - ${stickerCode}`,
    text: [
      `Hello ${studentName},`,
      "",
      "Your NAAP parking QR code is attached to this email. Keep it available for parking verification.",
      "",
      ...detailLines,
      "",
      "If you did not expect this email, contact the NAAP parking administrator."
    ].join("\n"),
    html: `
      <p>Hello ${escapeHtml(studentName)},</p>
      <p>Your NAAP parking QR code is shown below and attached to this email. Keep it available for parking verification.</p>
      <p><img src="cid:parking-qr" width="320" height="320" alt="NAAP parking QR code"></p>
      <ul>
        ${studentNumber ? `<li><strong>Student number:</strong> ${escapeHtml(studentNumber)}</li>` : ""}
        <li><strong>Sticker code:</strong> ${escapeHtml(stickerCode)}</li>
        ${plateNumber ? `<li><strong>Vehicle plate:</strong> ${escapeHtml(plateNumber)}</li>` : ""}
      </ul>
      ${verifyUrl ? `<p><a href="${escapeHtml(verifyUrl)}">Open parking verification</a></p>` : ""}
      <p>If you did not expect this email, contact the NAAP parking administrator.</p>
    `,
    attachments: [{
      filename,
      content: details.qrPng,
      contentType: "image/png",
      cid: "parking-qr",
      contentDisposition: "attachment"
    }],
    disableFileAccess: true,
    disableUrlAccess: true
  });
}

async function sendBackupArchiveEmail(details, options = {}) {
  const recipient = normalizeEmailAddress(details?.to);
  if (!recipient) throw new TypeError("A valid backup recipient email address is required.");
  const content = Buffer.isBuffer(details?.content)
    ? details.content
    : Buffer.from(String(details?.content || ""), "utf8");
  if (!content.length || content.length > 20 * 1024 * 1024) {
    throw new TypeError("Encrypted backup attachment must be between 1 byte and 20 MB.");
  }
  const smtp = options.smtp || getSmtpConfig(options.env);
  const transporter = options.transporter || nodemailer.createTransport(smtp.transport);
  const filename = String(details?.filename || "naap-backup.naapbackup")
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 160) || "naap-backup.naapbackup";

  return transporter.sendMail({
    from: smtp.from,
    to: recipient,
    subject: "NAAP encrypted parking backup",
    text: [
      "An encrypted NAAP parking recovery archive is attached.",
      "Keep the backup encryption passphrase separate from this email.",
      "Only an authorized administrator should restore this archive."
    ].join("\n"),
    attachments: [{
      filename,
      content,
      contentType: "application/vnd.naap.encrypted-backup+json",
      contentDisposition: "attachment"
    }],
    disableFileAccess: true,
    disableUrlAccess: true
  });
}

module.exports = {
  MailConfigurationError,
  getSmtpConfig,
  normalizeEmailAddress,
  sendBackupArchiveEmail,
  sendStudentQrEmail
};
