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
      const transaction = db.transaction(storeName, mode);
      transaction.onerror = () => reject(transaction.error);
      const request = callback(transaction.objectStore(storeName));
      request.onsuccess = () => resolve(request.result);
    });
  });
}

const OfflineManager = {
  isOnline: navigator.onLine,
  statusCallback: null,

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

  async syncRoster() {
    if (!this.isOnline) return;
    try {
      const response = await fetch('/api/sync-roster');
      const data = await response.json();
      if (!data.ok) return;

      const db = await openDB();
      const transaction = db.transaction('roster', 'readwrite');
      const store = transaction.objectStore('roster');
      
      // Clear existing offline roster to prevent stale data
      await new Promise(r => {
        const req = store.clear();
        req.onsuccess = () => r();
      });

      // Insert fresh data
      data.roster.forEach(vehicle => store.put(vehicle));
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
    
    const db = await openDB();
    const store = db.transaction('roster', 'readonly').objectStore('roster');
    
    return new Promise((resolve) => {
      const results = [];
      store.openCursor().onsuccess = (event) => {
        const cursor = event.target.result;
        if (cursor) {
          const v = cursor.value;
          const match = 
            (v.plate_number && v.plate_number.toLowerCase().includes(q)) ||
            (v.student_number && v.student_number.toLowerCase().includes(q)) ||
            (v.full_name && v.full_name.toLowerCase().includes(q));
          
          if (match && results.length < 10) results.push(v);
          cursor.continue();
        } else {
          resolve(results);
        }
      };
    });
  },

  // ─── OUTBOX SYNC (Upload mode) ────────────────────────────────────────────

  async queueMovement(token, action, gate, scannedAtMs) {
    const timestamp = scannedAtMs || Date.now();
    const actionUpper = action.toUpperCase();

    // Prevent duplicate offline queue buildup (15-second cooldown)
    const db = await openDB();
    const recent = await new Promise(res => {
      const store = db.transaction('outbox', 'readonly').objectStore('outbox');
      store.getAll().onsuccess = (e) => res(e.target.result);
    });

    const isDuplicate = recent.some(m => 
      m.token === token && 
      m.action === actionUpper &&
      (timestamp - (m.offline_timestamp || timestamp)) < 15000
    );

    if (isDuplicate) {
      console.log("Duplicate offline scan blocked by cooldown.");
      return { duplicate: true };
    }

    const movement = {
      token,
      action: actionUpper,
      gate,
      offline_timestamp: timestamp
    };
    
    await new Promise(res => {
      const tx = db.transaction('outbox', 'readwrite');
      tx.objectStore('outbox').add(movement);
      tx.oncomplete = () => res();
    });
    
    // If online, immediately try to process the queue
    if (this.isOnline) {
      setTimeout(() => this.processQueue(), 500); // Debounce lightly
    }
  },

  async processQueue() {
    if (!this.isOnline) return;

    const db = await openDB();
    const movements = await new Promise(res => {
      const store = db.transaction('outbox', 'readonly').objectStore('outbox');
      store.getAll().onsuccess = (e) => res(e.target.result);
    });

    if (movements.length === 0) return;
    console.log(`Processing ${movements.length} logged offline movements...`);

    try {
      const response = await fetch('/api/sync-queue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ movements })
      });
      const data = await response.json();
      
      if (data.ok) {
        // Clear processed items from outbox
        const transaction = db.transaction('outbox', 'readwrite');
        const store = transaction.objectStore('outbox');
        for (const m of movements) {
          store.delete(m.id);
        }
        console.log('Offline queue successfully synced to server.');
      }
    } catch (err) {
      console.error('Failed to sync offline queue. Will retry next time online:', err);
    }
  }
};

window.OfflineManager = OfflineManager;
