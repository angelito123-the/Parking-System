# Code review ? 12 September 2026

Reviewed the deployed baseline cae9416 in an isolated checkout and local review database. Existing uncommitted parking-zone changes were excluded.

## Confirmed bugs fixed

1. **Live streams survived logout and session revocation (high).** Both notification and scanner endpoints authorized only the opening request. An already-open connection could keep receiving updates after its login session was removed. Streams now record their session and user identity and close on logout, password-related revocation, suspension, role changes, or account deletion through the existing revocation function. Keeping the current session while revoking other devices preserves its connection. Session rows that have already disappeared do not prevent local cleanup.
2. **Disconnecting during startup leaked connections and timers (medium).** Disconnect handlers were registered after awaiting the initial database snapshot. Closing a tab during that query missed cleanup. The shared stream module registers response-close, response-error, and request-abort handlers before asynchronous work. Cleanup is idempotent, clears timers, resolves pending authorization, and prevents late snapshots from writing to disconnected clients.
3. **Expired login-limiter entries accumulated (medium).** Entries were pruned only when the same client returned. Traffic from unique clients left expired keys in memory. A periodic sweep during rate-limit checks now removes inactive keys while preserving recent attempts. No background timer is needed.

The first six stream regression cases failed against the original implementation and passed after the fix. The limiter regression likewise failed with 201 retained entries where only one active client should remain, then passed after cleanup was added.

## Shared stream lifecycle

Notification and scanner streaming now use lib/event-stream.js instead of duplicate header, timer, write, and cleanup implementations in server.js. The public event names and snapshot payloads are preserved; client identifiers are opaque UUIDs.

The module validates the backing session at connection startup and on each heartbeat (20 seconds by default). This catches expiry, removal by another server, identity/role changes, and forced password changes. Local revocations close streams immediately; changes made elsewhere are detected on the next check. A cookie-expiry timer closes idle streams, and broadcasts also check expiry before writing. Failed or unresponsive session checks close the connection; stalled readers and broken sockets are removed instead of buffering updates indefinitely. Snapshot errors use a user-facing message rather than exposing database error text.

## Verification

- npm test: 122 automated tests passed, including 25 additional stream and limiter cases.
- Local MariaDB check: both endpoints delivered their initial snapshots, logout ended both HTTP response bodies, and reconnection with the old cookie returned 401.
- System integration review: 12 workflow groups passed, covering registration, QR rotation, entry/exit, duplicate prevention, remote queue confirmation, offline replay/conflict/stale handling, account revocation, visitors, CSV import, encrypted backup restore, 19 admin/guard pages, and private-cache behavior after logout.
- UI browser suite: 29 passed, four platform-specific cases skipped; desktop and emulated phone profiles.
- Camera browser suite: 26 passed with simulated camera input.
- npm audit --omit=dev: zero reported production dependency vulnerabilities at review time.

## Remaining maintenance work and limits

server.js still exceeds 9,000 lines and mixes routing, SQL, background workers, reporting, notifications, backup handling, and parking workflows. views/students.ejs exceeds 2,000 lines and views/scanner_auto.ejs exceeds 1,700, mixing markup with substantial page behavior. These are confirmed maintenance concerns, not proof that each path is broken. Extract route groups and services in small changes backed by workflow tests, then move page scripts into dedicated assets.

Session revocation and session listing still scan serialized rows from the sessions table. An indexed user-to-session association would reduce that cost as usage grows; changing the storage schema needs its own migration and tests.

This review does not establish that every path is bug-free. Tests used local records, Chromium, emulated phones, and simulated camera input. Physical-phone camera permissions, Safari, real email delivery, multi-instance deployment, and sustained production load were not exercised. Production records were not used for mutation tests.
