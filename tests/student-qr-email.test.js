const test = require("node:test");
const assert = require("node:assert/strict");
const {
  MailConfigurationError,
  getSmtpConfig,
  normalizeEmailAddress,
  sendStudentQrEmail
} = require("../lib/student-qr-email");

test("builds authenticated STARTTLS SMTP settings from environment values", () => {
  assert.deepEqual(getSmtpConfig({
    SMTP_HOST: "smtp.example.com",
    SMTP_PORT: "587",
    SMTP_SECURE: "false",
    SMTP_USER: "parking@example.com",
    SMTP_PASS: "app-password",
    SMTP_FROM: "NAAP Parking <parking@example.com>"
  }), {
    from: "NAAP Parking <parking@example.com>",
    transport: {
      host: "smtp.example.com",
      port: 587,
      secure: false,
      auth: { user: "parking@example.com", pass: "app-password" }
    }
  });
});

test("requires complete SMTP configuration", () => {
  assert.throws(
    () => getSmtpConfig({ SMTP_HOST: "smtp.example.com", SMTP_USER: "admin@example.com" }),
    MailConfigurationError
  );
});

test("normalizes valid recipients and rejects unsafe addresses", () => {
  assert.equal(normalizeEmailAddress(" student@example.edu.ph "), "student@example.edu.ph");
  assert.equal(normalizeEmailAddress("student@example.edu.ph\nBcc: attacker@example.com"), null);
  assert.equal(normalizeEmailAddress("not-an-email"), null);
});

test("sends a branded QR attachment with student and sticker details", async () => {
  let sentMessage;
  const transporter = {
    async sendMail(message) {
      sentMessage = message;
      return { messageId: "test-message" };
    }
  };

  const result = await sendStudentQrEmail({
    to: "student@example.edu.ph",
    studentName: "Ava <Student>",
    studentNumber: "2026-001",
    stickerCode: "STK-2026-01",
    plateNumber: "ABC 1234",
    verifyUrl: "https://parking.example/verify/token",
    qrPng: Buffer.from("png-bytes")
  }, {
    transporter,
    smtp: { from: "NAAP Parking <parking@example.com>" }
  });

  assert.equal(result.messageId, "test-message");
  assert.equal(sentMessage.to, "student@example.edu.ph");
  assert.match(sentMessage.subject, /STK-2026-01/);
  assert.match(sentMessage.html, /Ava &lt;Student&gt;/);
  assert.equal(sentMessage.attachments[0].filename, "STK-2026-01-qr.png");
  assert.equal(sentMessage.attachments[0].contentType, "image/png");
  assert.deepEqual(sentMessage.attachments[0].content, Buffer.from("png-bytes"));
});
