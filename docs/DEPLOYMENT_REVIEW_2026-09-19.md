# Deployment review — 19 September 2026

The reviewed release passes the automated code, browser, workflow, and production
startup checks below. Actual Gmail delivery and physical phone camera operation
still require a live check before operational handover. This review does not
certify every device, external service, or production record.

## Fixes from this review

- Database and session-store failures could expose internal exception text to
  API clients. Movement and parking-space error handlers now return a safe
  fallback for unexpected exceptions while preserving deliberately written
  validation messages, such as an occupied parking space. The final API error
  handler also avoids returning raw exception details.
- Authenticated HTML and QR responses lacked a general cache-prevention policy.
  Dynamic responses now use `Cache-Control: private, no-store`. Public stylesheet,
  script, and icon caching remains available. Regression checks cover login,
  account pages, logout redirects, and public stylesheet caching.
- The package engine now targets Node.js 24 LTS instead of allowing unsupported
  Node.js majors. The production build was exercised with Node.js 24.18.0.
  [Node release status](https://nodejs.org/en/about/previous-releases) and
  [Render runtime selection](https://render.com/docs/node-version) explain this
  choice. A separately configured Render `NODE_VERSION` takes precedence over
  the package engine range.

## Verification

| Check | Result |
| --- | --- |
| Code tests | 146 passed, including four new error/privacy regressions |
| Simulated camera tests | 26 passed across desktop and phone Chromium |
| Desktop, phone, and dark-theme UI tests | 50 passed; 4 skips for inapplicable viewport checks |
| Local integration workflows | All 12 groups passed after the error-handling fix |
| Authenticated pages | 19 administrator/guard pages loaded without uncaught JavaScript errors with external page resources blocked |
| Database | Fresh schema initialization and operational schema verification passed |
| Syntax and templates | 63 JavaScript files checked; 25 EJS templates compiled |
| Clean production dependency install | `npm ci --omit=dev` passed with no known dependency vulnerabilities reported |
| Production-mode smoke checks | Startup, database health, login, secure cookie flags, 9 private pages, QR downloads, and cross-site write rejection passed |
| Application restart | Database-backed login session remained usable after restart |
| Logout | Existing login cookie could no longer access the protected QR image |
| Repository contents | No tracked `.env`, dependency directory, runtime snapshot directory, or log files |

The workflow checks cover student/vehicle registration, QR issuance and replacement,
manual entry/exit, duplicate prevention, phone-to-guard entry confirmation, offline
retry/conflict/stale-event handling, account demotion/deletion session revocation,
visitor approval and movement, CSV import with tamper rejection, and encrypted
backup restore with replay rejection. Tests used a disposable local database;
no production records were changed and no real emails were sent.

An older local test database crashed while reading schema metadata. It was
replaced with a newly initialized test instance; fresh setup and workflows then
passed. This was a local test-environment failure, not an observed production
database failure.

## Live checks and remaining handover steps

At review time, the existing Render deployment of `57034eb` reported success.
Its health endpoint returned `200 {"ok":true}`, sign-in loaded, anonymous access
to protected pages redirected to sign-in, and public assets matched GitHub.
The first request timed out; subsequent checks succeeded. A free Render service
can take about a minute to wake after inactivity, so the initial timeout alone
does not establish an application defect. See [Render's free service behavior](https://render.com/docs/free#spinning-down-on-idle).

Before operational handover:

1. Send one QR email to a Gmail inbox and open its PNG attachment. Production
   Brevo credentials and delivery logs were unavailable for this review; use
   [the existing email setup guide](./EMAIL_SETUP_RENDER.md) if setup is incomplete.
2. On the actual gate phone/browser, allow camera access, scan a printed QR,
   confirm entry from the guard screen, and record exit. Automated camera tests
   use a simulated video source and cannot confirm physical camera behavior.
3. Keep a downloaded encrypted backup and its passphrase available for recovery.
   Backup creation and restoration passed locally; production backup configuration
   and an off-device copy were not independently verified.

The review applies to the committed release plus these fixes. Ten pre-existing
modified workspace files were kept separate from the release; their changes
were preserved and were not silently published.
