// Initialize IndexedDB for offline data storage
const DB_NAME = 'NaapOfflineDB';
const DB_VERSION = 2;

function createClientEventId(prefix = 'event') {
  if (self.crypto && typeof self.crypto.randomUUID === 'function') {
    return `${prefix}-${self.crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
}

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
      if (!db.objectStoreNames.contains('metricsOutbox')) {
        db.createObjectStore('metricsOutbox', { keyPath: 'id', autoIncrement: true });
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
  queueStatusCallback: null,
  rosterSyncPromise: null,
  queueSyncPromise: null,

  init(statusCb, queueStatusCb) {
    this.statusCallback = statusCb;
    this.queueStatusCallback = queueStatusCb || null;
    window.addEventListener('online', () => this.handleStatusChange(true));
    window.addEventListener('offline', () => this.handleStatusChange(false));
    this.handleStatusChange(navigator.onLine);
    
    // Attempt initial sync on load if online
    if (this.isOnline) {
      this.syncRoster();
      this.processQueue();
    }
    this.notifyQueueStatus();
  },

  async getQueueStatus() {
    try {
      const [movements, metrics] = await Promise.all([
        dbTransaction('outbox', 'readonly', store => store.count()),
        dbTransaction('metricsOutbox', 'readonly', store => store.count())
      ]);
      return {
        movements: Number(movements) || 0,
        metrics: Number(metrics) || 0,
        total: (Number(movements) || 0) + (Number(metrics) || 0),
        online: this.isOnline,
        syncing: Boolean(this.queueSyncPromise)
      };
    } catch (_error) {
      return { movements: 0, metrics: 0, total: 0, online: this.isOnline, syncing: false };
    }
  },

  async notifyQueueStatus() {
    const status = await this.getQueueStatus();
    if (this.queueStatusCallback) this.queueStatusCallback(status);
    window.dispatchEvent(new CustomEvent('naap-offline-queue-status', { detail: status }));
    return status;
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
      event_id: createClientEventId('movement'),
      token: safeToken,
      action: actionUpper,
      gate: String(gate || 'Offline Scan').trim().slice(0, 80) || 'Offline Scan',
      offline_timestamp: timestamp
    };
    
    await dbTransaction('outbox', 'readwrite', store => store.add(movement));
    try {
      await this.updateRosterMovement(safeToken, actionUpper);
    } catch (error) {
      console.warn('Movement was queued, but the cached roster state could not be updated:', error);
    }
    await this.notifyQueueStatus();
    
    // If online, immediately try to process the queue
    if (this.isOnline) {
      setTimeout(() => this.processQueue(), 500); // Debounce lightly
    }
    return { duplicate: false, queued: true, event_id: movement.event_id };
  },

  async updateRosterMovement(token, action) {
    const db = await openDB();
    await new Promise((resolve, reject) => {
      const transaction = db.transaction('roster', 'readwrite');
      const store = transaction.objectStore('roster');
      const request = store.get(token);
      request.onsuccess = () => {
        if (!request.result) return;
        store.put({
          ...request.result,
          last_action: action,
          current_slot: action === 'EXIT' ? null : request.result.current_slot
        });
      };
      transaction.oncomplete = () => { db.close(); resolve(); };
      transaction.onerror = () => { db.close(); reject(transaction.error || new Error('Offline roster update failed.')); };
      transaction.onabort = () => { db.close(); reject(transaction.error || new Error('Offline roster update was aborted.')); };
    });
  },

  async queueScanMetric(metric) {
    const safeMetric = metric && typeof metric === 'object' ? metric : {};
    const queuedMetric = {
      ...safeMetric,
      event_id: String(safeMetric.event_id || createClientEventId('metric')).slice(0, 80),
      occurred_at: safeMetric.occurred_at || new Date().toISOString(),
      network_mode: this.isOnline ? 'online' : 'offline'
    };

    if (this.isOnline) {
      try {
        const response = await fetch('/api/scanner-metrics', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(queuedMetric)
        });
        if (response.ok) return { queued: false, synced: true, event_id: queuedMetric.event_id };
      } catch (_error) {
        // Fall through to durable local queue.
      }
    }

    await dbTransaction('metricsOutbox', 'readwrite', store => store.add(queuedMetric));
    await this.notifyQueueStatus();
    return { queued: true, synced: false, event_id: queuedMetric.event_id };
  },

  processQueue() {
    if (!this.isOnline) return Promise.resolve();
    if (this.queueSyncPromise) return this.queueSyncPromise;
    this.queueSyncPromise = this.performQueueSync()
      .catch(err => console.error('Failed to sync offline queue. Will retry next time online:', err))
      .finally(() => {
        this.queueSyncPromise = null;
        this.notifyQueueStatus();
      });
    this.notifyQueueStatus();
    return this.queueSyncPromise;
  },

  async performQueueSync() {
    const [movements, metrics] = await Promise.all([
      dbTransaction('outbox', 'readonly', store => store.getAll()),
      dbTransaction('metricsOutbox', 'readonly', store => store.getAll())
    ]);

    if (movements.length > 0) {
      const legacyMovements = [];
      for (const movement of movements) {
        if (!movement.event_id) {
          movement.event_id = createClientEventId('movement');
          legacyMovements.push(movement);
        }
      }
      if (legacyMovements.length) {
        const db = await openDB();
        await new Promise((resolve, reject) => {
          const transaction = db.transaction('outbox', 'readwrite');
          const store = transaction.objectStore('outbox');
          legacyMovements.forEach((movement) => store.put(movement));
          transaction.oncomplete = () => { db.close(); resolve(); };
          transaction.onerror = () => { db.close(); reject(transaction.error || new Error('Offline queue upgrade failed.')); };
          transaction.onabort = () => { db.close(); reject(transaction.error || new Error('Offline queue upgrade was aborted.')); };
        });
      }
      const response = await fetch('/api/sync-queue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ movements })
      });
      if (!response.ok) throw new Error(`Queue sync failed (${response.status}).`);
      const data = await response.json();
      if (!data.ok) throw new Error(data.message || 'Server rejected the offline queue.');
      const accepted = new Set(Array.isArray(data.accepted_event_ids) ? data.accepted_event_ids : movements.map(item => item.event_id));
      await this.deleteQueuedItems('outbox', movements.filter(item => accepted.has(item.event_id)));
    }

    if (metrics.length > 0) {
      const response = await fetch('/api/scanner-metrics/batch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ metrics })
      });
      if (!response.ok) throw new Error(`Metric sync failed (${response.status}).`);
      const data = await response.json();
      if (!data.ok) throw new Error(data.message || 'Server rejected scanner metrics.');
      const accepted = new Set(Array.isArray(data.accepted_event_ids) ? data.accepted_event_ids : metrics.map(item => item.event_id));
      await this.deleteQueuedItems('metricsOutbox', metrics.filter(item => accepted.has(item.event_id)));
    }
    await this.notifyQueueStatus();
  },

  async deleteQueuedItems(storeName, items) {
    if (!Array.isArray(items) || !items.length) return;
    const db = await openDB();
    await new Promise((resolve, reject) => {
      const transaction = db.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);
      transaction.oncomplete = () => { db.close(); resolve(); };
      transaction.onerror = () => { db.close(); reject(transaction.error || new Error('Queue cleanup failed.')); };
      transaction.onabort = () => { db.close(); reject(transaction.error || new Error('Queue cleanup was aborted.')); };
      for (const item of items) store.delete(item.id);
    });
  }
};

window.OfflineManager = OfflineManager;
