const test = require('node:test');
const assert = require('node:assert/strict');
const { getMailConfig, getMailConfigurationIssue, createMailDelivery, MailConfigurationError } = require('../lib/mail-transport');
const { sendStudentQrEmail, sendBackupArchiveEmail } = require('../lib/student-qr-email');
const env = { MAIL_PROVIDER: 'brevo', BREVO_API_KEY: 'test-key-never-used-on-network', MAIL_FROM_EMAIL: 'parking@example.edu.ph', MAIL_FROM_NAME: 'NAAP Parking' };
const details = { to: 'student@gmail.com', studentName: 'Example Student', studentNumber: '2026-001', stickerCode: 'STK-01', plateNumber: 'ABC 123', verifyUrl: 'https://parking.example/verify/test-token', qrPng: Buffer.from('test-png') };
const response = (status, data) => ({ ok: status >= 200 && status < 300, status, async json() { return data; } });

test('Render selects HTTPS delivery without falling back to blocked SMTP ports', () => {
  assert.equal(getMailConfig({ ...env, MAIL_PROVIDER: '', RENDER: 'true' }).provider, 'brevo');
  assert.throws(() => getMailConfig({ RENDER: 'true', SMTP_HOST: 'smtp.gmail.com', SMTP_USER: 'sender@gmail.com', SMTP_PASS: 'test' }), MailConfigurationError);
  assert.match(getMailConfigurationIssue({ RENDER: 'true' }), /BREVO_API_KEY/);
  assert.equal(getMailConfigurationIssue(env), null);
});

test('explicit SMTP configuration remains available on supported hosts', () => {
  const config = getMailConfig({ RENDER: 'true', MAIL_PROVIDER: 'smtp', SMTP_HOST: 'smtp.example.com', SMTP_FROM: 'sender@example.com' });
  assert.equal(config.provider, 'smtp');
  assert.equal(config.transport.port, 587);
});

test('missing credentials, invalid senders, and header injection fail before a request', async () => {
  for (const broken of [ { BREVO_API_KEY: '' }, { MAIL_FROM_EMAIL: 'invalid' }, { MAIL_FROM_NAME: 'Parking\r\nBcc: intruder@example.com' }, { BREVO_API_KEY: 'key\r\ninjected' } ]) {
    let requests = 0;
    await assert.rejects(sendStudentQrEmail(details, { env: { ...env, ...broken }, fetch: async () => { requests++; } }), MailConfigurationError);
    assert.equal(requests, 0);
  }
});

test('Gmail recipient receives a request with the QR attachment and verified sender via HTTPS', async () => {
  let request;
  const result = await sendStudentQrEmail(details, { env, fetch: async (url, options) => { request = { url, ...options }; return response(201, { messageId: '<provider-receipt>' }); } });
  assert.equal(request.url, 'https://api.brevo.com/v3/smtp/email');
  assert.equal(request.method, 'POST');
  assert.equal(request.redirect, 'error');
  assert.equal(request.headers['api-key'], env.BREVO_API_KEY);
  assert.ok(request.signal instanceof AbortSignal);
  const body = JSON.parse(request.body);
  assert.deepEqual(body.to, [{ email: 'student@gmail.com' }]);
  assert.deepEqual(body.sender, { email: env.MAIL_FROM_EMAIL, name: 'NAAP Parking' });
  assert.equal(body.attachment[0].name, 'STK-01-qr.png');
  assert.deepEqual(Buffer.from(body.attachment[0].content, 'base64'), details.qrPng);
  assert.match(body.htmlContent, /https:\/\/parking.example\/verify\/test-token/);
  assert.doesNotMatch(body.htmlContent, /cid:parking-qr/);
  assert.doesNotMatch(request.body, /test-key-never-used-on-network/);
  assert.equal(result.messageId, '<provider-receipt>');
});

for (const [status, retryable] of [[400, false], [401, false], [402, false], [403, false], [429, true], [500, true], [503, true]]) {
  test('HTTP ' + status + ' returns a safe error with the correct retry behavior', async () => {
    await assert.rejects(sendStudentQrEmail(details, { env, fetch: async () => response(status, { message: env.BREVO_API_KEY }) }), error => {
      assert.equal(error.retryable, retryable);
      assert.equal(error.code, 'MAIL_PROVIDER_REJECTED');
      assert.ok(!error.message.includes(env.BREVO_API_KEY));
      return true;
    });
  });
}

for (const data of [{}, null, { messageId: '' }]) {
  test('a successful HTTP response without a receipt is not reported as sent: ' + JSON.stringify(data), async () => {
    await assert.rejects(sendStudentQrEmail(details, { env, fetch: async () => response(201, data) }), error => error.code === 'MAIL_RECEIPT_MISSING' && error.retryable === false);
  });
}

test('connection errors are safe to display and eligible for a later retry', async () => {
  await assert.rejects(sendStudentQrEmail(details, { env, fetch: async () => { throw new Error('request with ' + env.BREVO_API_KEY); } }), error => error.code === 'MAIL_CONNECTION_FAILED' && error.retryable === true && !error.message.includes(env.BREVO_API_KEY));
});

test('backup delivery keeps the attachment encrypted and uses a supported extension', async () => {
  let payload;
  await sendBackupArchiveEmail({ to: 'admin@gmail.com', filename: 'recovery.naapbackup', content: Buffer.from('encrypted archive') }, { env, fetch: async (_url, options) => { payload = JSON.parse(options.body); return response(201, { messageId: '<backup>' }); } });
  assert.equal(payload.attachment[0].name, 'recovery.naapbackup.txt');
  assert.equal(Buffer.from(payload.attachment[0].content, 'base64').toString(), 'encrypted archive');
});
