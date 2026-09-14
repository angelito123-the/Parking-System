const nodemailer = require('nodemailer');

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

function getMailConfig(env = process.env) {
  const provider = String(env.MAIL_PROVIDER || (env.BREVO_API_KEY || env.RENDER === 'true' ? 'brevo' : 'smtp')).trim().toLowerCase();
  if (provider === 'smtp') return { provider, ...getSmtpConfig(env) };
  if (provider !== 'brevo') throw new MailConfigurationError('MAIL_PROVIDER must be brevo or smtp.');
  const apiKey = String(env.BREVO_API_KEY || '').trim();
  const email = normalizeEmailAddress(env.MAIL_FROM_EMAIL);
  const name = String(env.MAIL_FROM_NAME || 'NAAP Parking').trim();
  if (!apiKey || /[\r\n]/.test(apiKey) || !email || /[\r\n]/.test(name)) {
    throw new MailConfigurationError('Email sending needs setup: add BREVO_API_KEY and a verified MAIL_FROM_EMAIL in Render Environment.');
  }
  return { provider, apiKey, from: { address: email, name } };
}

function getMailConfigurationIssue(env = process.env) {
  try { getMailConfig(env); return null; }
  catch (error) { return error.message; }
}

function providerError(status, code) {
  let message = 'The email service rejected the message. Check the verified sender and recipient address.';
  if (status === 401) message = 'The email service rejected its API key. Update BREVO_API_KEY in Render Environment.';
  else if (status === 403) message = 'The email service has not authorized sending. Check sender verification, account activation, and authorized IPs in Brevo.';
  else if (status === 402 || code === 'not_enough_credits') message = 'The email service has reached its sending quota. Check the allowance in Brevo before retrying.';
  else if (status === 429) message = 'The email service is temporarily rate limited. Delivery will be retried.';
  else if (status >= 500) message = 'The email service is temporarily unavailable. Delivery will be retried.';
  const error = new Error(message);
  error.code = 'MAIL_PROVIDER_REJECTED';
  error.retryable = status === 429 || status >= 500;
  return error;
}

function createMailDelivery(options = {}) {
  // Preserve injected SMTP transports used by callers and tests.
  const config = options.smtp ? { provider: 'smtp', ...options.smtp } : getMailConfig(options.env);
  if (config.provider === 'smtp') {
    const transporter = options.transporter || nodemailer.createTransport(config.transport);
    return { from: config.from, supportsInlineImages: true, sendMail: message => transporter.sendMail(message) };
  }
  const fetchRequest = options.fetch || globalThis.fetch;
  return {
    from: config.from,
    supportsInlineImages: false,
    async sendMail(message) {
      const payload = {
        sender: { email: config.from.address, name: config.from.name },
        to: [{ email: message.to }],
        subject: message.subject,
        textContent: message.text,
        ...(message.html ? { htmlContent: message.html } : {}),
        attachment: (message.attachments || []).map(item => ({
          // The recovery archive remains encrypted; .txt is accepted by mail
          // providers that reject the application's custom file extension.
          name: item.filename.endsWith('.naapbackup') ? item.filename + '.txt' : item.filename,
          content: item.content.toString('base64')
        }))
      };
      let response;
      try {
        response = await fetchRequest('https://api.brevo.com/v3/smtp/email', {
          method: 'POST', redirect: 'error',
          headers: { 'api-key': config.apiKey, 'content-type': 'application/json', accept: 'application/json' },
          body: JSON.stringify(payload), signal: AbortSignal.timeout(15000)
        });
      } catch (_error) {
        const error = new Error('The email service could not be reached. Delivery will be retried.');
        error.code = 'MAIL_CONNECTION_FAILED';
        error.retryable = true;
        throw error;
      }
      let data;
      try {
        const parsed = await response.json();
        data = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
      }
      catch (_error) { data = {}; }
      if (!response.ok) throw providerError(response.status, data.code);
      if (typeof data.messageId !== 'string' || !data.messageId.trim()) {
        const error = new Error('The email service returned no delivery receipt. Check Brevo delivery logs before retrying.');
        error.code = 'MAIL_RECEIPT_MISSING';
        error.retryable = false;
        throw error;
      }
      return { messageId: data.messageId, accepted: [message.to] };
    }
  };
}

module.exports = { MailConfigurationError, getSmtpConfig, normalizeEmailAddress, getMailConfig, getMailConfigurationIssue, createMailDelivery };
