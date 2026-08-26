// Initialize IndexedDB for offline data storage
const DB_NAME = 'NaapOfflineDB';
const DB_VERSION = 1;

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      // Roster table: active valid stickers with vehicle/student info
      if (!db.objectStoreNames.contains('roster')) {
        const rosterStore = db.createObjectStore('roster', { keyPath: 'qr_token' });
        rosterStore.createIndex('plate_number', 'plate_number', { unique: false });
        rosterStore.createIndex('student_number', 'student_number', { unique: false });
        rosterStore.createIndex('full_name', 'full_name', { unique: false });
      }
      // Outbox table: pending movements that happened offline
      if (!db.objectStoreNames.contains('outbox')) {
        db.createObjectStore('outbox', { keyPath: 'id', autoIncrement: true });
      }
    };
  });
}

function dbTransaction(storeName, mode, callback) {
  return openDB().then(db => {
    return new Promise((resolve, reject) => {
      let requestResult;
      let settled = false;
      const finish = (handler, value) => {
        if (settled) return;
        settled = true;
        db.close();
        handler(value);
      };

      let transaction;
      try {
        transaction = db.transaction(storeName, mode);
        const request = callback(transaction.objectStore(storeName));
        request.onsuccess = () => { requestResult = request.result; };
        request.onerror = () => finish(reject, request.error || new Error('IndexedDB request failed.'));
      } catch (error) {
        finish(reject, error);
        return;
      }

      transaction.oncomplete = () => finish(resolve, requestResult);
      transaction.onerror = () => finish(reject, transaction.error || new Error('IndexedDB transaction failed.'));
      transaction.onabort = () => finish(reject, transaction.error || new Error('IndexedDB transaction was aborted.'));
    });
  });
}

const OfflineManager = {
  isOnline: navigator.onLine,
  statusCallback: null,
  rosterSyncPromise: null,
  queueSyncPromise: null,

  init(statusCb) {
    this.statusCallback = statusCb;
    window.addEventListener('online', () => this.handleStatusChange(true));
    window.addEventListener('offline', () => this.handleStatusChange(false));
    this.handleStatusChange(navigator.onLine);
    
    // Attempt initial sync on load if online
    if (this.isOnline) {
      this.syncRoster();
      this.processQueue();
    }
  },

  handleStatusChange(online) {
    this.isOnline = online;
    if (this.statusCallback) this.statusCallback(online);
    if (online) {
      this.syncRoster();
      this.processQueue();
    }
  },

  // ─── ROSTER SYNC (Download mode) ──────────────────────────────────────────

  syncRoster() {
    if (!this.isOnline) return Promise.resolve();
    if (this.rosterSyncPromise) return this.rosterSyncPromise;
    this.rosterSyncPromise = this.performRosterSync()
      .finally(() => { this.rosterSyncPromise = null; });
    return this.rosterSyncPromise;
  },

  async performRosterSync() {
    try {
      const response = await fetch('/api/sync-roster');
      if (!response.ok) throw new Error(`Roster sync failed (${response.status}).`);
      const data = await response.json();
      if (!data.ok || !Array.isArray(data.roster)) throw new Error(data.message || 'Invalid roster response.');

      const db = await openDB();
      await new Promise((resolve, reject) => {
        const transaction = db.transaction('roster', 'readwrite');
        const store = transaction.objectStore('roster');
        transaction.oncomplete = () => { db.close(); resolve(); };
        transaction.onerror = () => { db.close(); reject(transaction.error || new Error('Roster storage failed.')); };
        transaction.onabort = () => { db.close(); reject(transaction.error || new Error('Roster storage was aborted.')); };
        const clearRequest = store.clear();
        clearRequest.onsuccess = () => {
          data.roster.forEach(vehicle => store.put(vehicle));
        };
      });
      console.log(`Offline roster synced: ${data.roster.length} active vehicles.`);
    } catch (err) {
      console.error('Failed to sync roster:', err);
    }
  },

  async verifyOfflineToken(token) {
    const vehicle = await dbTransaction('roster', 'readonly', store => store.get(token));
    if (!vehicle) {
      return { ok: false, result: "INVALID", message: "Sticker not found in offline DB." };
    }
    // For offline, we trust the downloaded list which only contains ACTIVE and non-expired vehicles.
    return { ok: true, result: "VALID", message: "Offline Verification successful.", sticker: vehicle };
  },

  async searchOfflineRoster(query) {
    const q = String(query).toLowerCase().trim();
    if (!q) return [];

    const roster = await dbTransaction('roster', 'readonly', store => store.getAll());
    return roster.filter(vehicle => (
      String(vehicle.plate_number || '').toLowerCase().includes(q) ||
      String(vehicle.student_number || '').toLowerCase().includes(q) ||
      String(vehicle.full_name || '').toLowerCase().includes(q)
    )).slice(0, 10);
  },

  // ─── OUTBOX SYNC (Upload mode) ────────────────────────────────────────────

  async queueMovement(token, action, gate, scannedAtMs) {
    const safeToken = String(token || '').trim();
    const actionUpper = String(action || '').trim().toUpperCase();
    const safeTimestamp = Number(scannedAtMs);
    const timestamp = Number.isFinite(safeTimestamp) && safeTimestamp > 0 ? safeTimestamp : Date.now();
    if (!safeToken) throw new Error('Cannot queue an offline movement without a QR token.');
    if (!['ENTRY', 'EXIT'].includes(actionUpper)) throw new Error('Invalid offline movement action.');

    // Prevent duplicate offline queue buildup (15-second cooldown)
    const recent = await dbTransaction('outbox', 'readonly', store => store.getAll());

    const isDuplicate = recent.some(m => 
      m.token === safeToken &&
      m.action === actionUpper &&
      (timestamp - (m.offline_timestamp || timestamp)) < 15000
    );

    if (isDuplicate) {
      console.log("Duplicate offline scan blocked by cooldown.");
      return { duplicate: true };
    }

    const movement = {
      token: safeToken,
      action: actionUpper,
      gate: String(gate || 'Offline Scan').trim().slice(0, 80) || 'Offline Scan',
      offline_timestamp: timestamp
    };
    
    await dbTransaction('outbox', 'readwrite', store => store.add(movement));
    
    // If online, immediately try to process the queue
    if (this.isOnline) {
      setTimeout(() => this.processQueue(), 500); // Debounce lightly
    }
  },

  processQueue() {
    if (!this.isOnline) return Promise.resolve();
    if (this.queueSyncPromise) return this.queueSyncPromise;
    this.queueSyncPromise = this.performQueueSync()
      .catch(err => console.error('Failed to sync offline queue. Will retry next time online:', err))
      .finally(() => { this.queueSyncPromise = null; });
    return this.queueSyncPromise;
  },

  async performQueueSync() {
    const movements = await dbTransaction('outbox', 'readonly', store => store.getAll());

    if (movements.length === 0) return;
    console.log(`Processing ${movements.length} logged offline movements...`);

    try {
      const response = await fetch('/api/sync-queue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ movements })
      });
      if (!response.ok) throw new Error(`Queue sync failed (${response.status}).`);
      const data = await response.json();
      if (!data.ok) throw new Error(data.message || 'Server rejected the offline queue.');

      if (data.ok) {
        // Clear processed items from outbox
        const db = await openDB();
        await new Promise((resolve, reject) => {
          const transaction = db.transaction('outbox', 'readwrite');
          const store = transaction.objectStore('outbox');
          transaction.oncomplete = () => { db.close(); resolve(); };
          transaction.onerror = () => { db.close(); reject(transaction.error || new Error('Queue cleanup failed.')); };
          transaction.onabort = () => { db.close(); reject(transaction.error || new Error('Queue cleanup was aborted.')); };
          for (const movement of movements) store.delete(movement.id);
        });
        console.log('Offline queue successfully synced to server.');
      }
    } catch (err) {
      console.error('Failed to sync offline queue. Will retry next time online:', err);
    }
  }
};

window.OfflineManager = OfflineManager;
