const gates = require('./gate-logging');

// Register gate APIs alongside the existing session-protected scanner routes.
module.exports = function registerGateRoutes(app, services) {
  const { pool, requireRole, roles, logger, normalizeToken, verify, lastMovement,
    duplicateInfo, assignSlot, currentSlot, releaseSlot, insertLog, overview } = services;
  const reader = requireRole(roles.ADMIN, roles.GUARD);
  const guard = requireRole(roles.GUARD);
  const admin = requireRole(roles.ADMIN);
  const wrap = handler => async (req, res, next) => {
    try { await handler(req, res, next); }
    catch (error) {
      const publicMessage = services.publicError(error, null);
      if (!publicMessage) logger.error('Gate logging error:', error);
      res.status(error instanceof gates.GateLoggingError ? error.status : publicMessage ? 400 : 500).json({
        ok: false, code: error instanceof gates.GateLoggingError ? error.code : publicMessage ? 'INVALID_REQUEST' : 'SERVER_ERROR',
        message: publicMessage || 'Unable to complete the gate request. Please try again.'
      });
    }
  };

  app.get('/api/gates', reader, wrap(async (_req, res) => res.json({ ok: true, gates: await gates.listGates(pool) })));
  app.post('/api/gates/:id', admin, wrap(async (req, res) => {
    const id = gates.integer(req.params.id, 'gate', null);
    const type = req.body.type;
    if (!['entry', 'exit', 'both'].includes(type)) throw new gates.GateLoggingError('Choose entry, exit, or both.');
    await gates.resolveGate(pool, id);
    await pool.query('UPDATE gates SET type = ? WHERE id = ?', [type, id]);
    await services.audit(req, 'GATE_TYPE_UPDATED', { targetType: 'gate', targetId: id, metadata: { type } });
    res.json({ ok: true, message: 'Gate direction saved.', gate: await gates.resolveGate(pool, id) });
  }));
  app.get('/api/logs', reader, wrap(async (req, res) => res.json({ ok: true, ...await gates.listLogs(pool, req.query) })));
  app.get('/api/vehicle-sessions', reader, wrap(async (req, res) => res.json({ ok: true, ...await gates.listSessions(pool, req.query) })));
  app.get('/api/vehicles/:id/latest-session', reader, wrap(async (req, res) => {
    const id = gates.integer(req.params.id, 'vehicle', null);
    const [vehicles] = await pool.query('SELECT id, plate_number FROM vehicles WHERE id = ?', [id]);
    if (!vehicles.length) throw new gates.GateLoggingError('Vehicle not found.', 'NOT_FOUND', 404);
    const history = await gates.listSessions(pool, { vehicle_id: String(id), limit: '1' });
    res.json({ ok: true, vehicle: vehicles[0], session: history.rows[0] || null });
  }));

  // Existing scanners can keep sending names; numeric IDs take priority when supplied.
  app.post(['/api/scan', '/api/auto-scan/detect', '/api/auto-scan/confirm-entry', '/api/auto-scan/heartbeat', '/api/manual-movement', '/verify/:token/movement'], guard, wrap(async (req, _res, next) => {
    const gate = await gates.resolveGate(pool, req.body.gate_id ?? req.body.gate ?? 'Gate 1');
    req.body.gate = gate.name;
    req.selectedGate = gate;
    next();
  }));

  const loadGateOptions = wrap(async (_req, res, next) => {
    res.locals.gates = await gates.listGates(pool);
    next();
  });
  app.get(['/scanner', '/scanner/auto'], guard, loadGateOptions);
  app.get('/verify/:token', loadGateOptions);
  app.post('/verify/:token/movement', guard, loadGateOptions);

  app.post('/api/scans', guard, wrap(async (req, res) => {
    const rawToken = req.body.qr_data ?? req.body.token;
    if (typeof rawToken !== 'string' || rawToken.length > 2048) throw new gates.GateLoggingError('Provide a valid vehicle QR code.', 'INVALID_QR');
    const token = normalizeToken(rawToken);
    if (!token) throw new gates.GateLoggingError('Provide a vehicle QR code.', 'INVALID_QR');
    const gate = await gates.resolveGate(pool, req.body.gate_id);
    const verification = await verify(token);
    if (!verification.ok) throw new gates.GateLoggingError(verification.message || 'Invalid QR code.', 'INVALID_QR');
    const sticker = verification.sticker;
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const [locked] = await connection.query('SELECT id, status, expires_at FROM stickers WHERE id = ? FOR UPDATE', [sticker.id]);
      if (!locked.length || locked[0].status !== 'active' || services.isExpired(locked[0].expires_at)) {
        throw new gates.GateLoggingError('This QR code is no longer valid.', 'INVALID_QR');
      }
      const previous = await lastMovement(sticker.id, connection);
      if (duplicateInfo(previous).duplicate) throw new gates.GateLoggingError('Duplicate scan ignored. Wait before scanning this vehicle again.', 'DUPLICATE_SCAN', 409);
      const action = previous?.action === 'ENTRY' ? 'EXIT' : 'ENTRY';
      gates.assertGateDirection(gate, action);
      if (action === 'ENTRY' && !req.body.slot_id) {
        await connection.rollback();
        return res.json({ ok: true, movement_saved: false, requires_confirmation: true, scan_type: 'entry', gate,
          message: `Entry detected at ${gate.name}. Select a parking slot and confirm entry.`, parkingSlotOverview: await overview() });
      }
      const slotId = action === 'ENTRY' ? gates.integer(req.body.slot_id, 'parking slot', null) : null;
      const slot = action === 'ENTRY' ? await assignSlot(connection, sticker.id, slotId) : await currentSlot(sticker.id, connection);
      const log = await insertLog(connection, sticker.id, 'VALID', action, gate.name, 'Recorded at configured gate', {
        gateId: gate.name, slotId: slot?.id || null, qrValue: token,
        studentId: sticker.student_id_ref || null, vehicleId: sticker.vehicle_id_ref || sticker.vehicle_id,
        assignedByGuard: req.authUser.username, assignedArea: slot?.zone || null, scanSource: 'gate_scan', status: 'AUTHORIZED'
      });
      if (action === 'EXIT') await releaseSlot(connection, sticker.id);
      await connection.commit();
      // An alert failure must not make a committed movement look unsuccessful.
      try { await services.afterMovement(action, gate.name, sticker.id, req.authUser.username); }
      catch (error) { logger.error('Gate movement notification error:', error); }
      res.status(201).json({ ok: true, movement_saved: true, requires_confirmation: false,
        message: `${action === 'ENTRY' ? 'Entry' : 'Exit'} recorded at ${gate.name}.`,
        scan: { id: log.vehicle_log_id, vehicle_id: sticker.vehicle_id_ref || sticker.vehicle_id,
          guard_id: req.authUser.id, gate_id: gate.id, gate_name: gate.name, scan_type: action.toLowerCase(), scanned_at: log.scanned_at },
        parking_slot: action === 'ENTRY' ? slot?.slot_code || null : null,
        released_slot: action === 'EXIT' ? slot?.slot_code || null : null });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally { connection.release(); }
  }));
};
