(() => {
  const panel = document.getElementById('vehicleGateHistory');
  if (!panel) return;
  const form = document.getElementById('gateHistoryFilters');
  const status = document.getElementById('gateHistoryStatus');
  const table = document.getElementById('gateHistoryTable');
  const previous = document.getElementById('gateHistoryPrevious');
  const next = document.getElementById('gateHistoryNext');
  const pageLabel = document.getElementById('gateHistoryPage');
  const gateSelect = document.getElementById('gateHistoryGate');
  const viewSelect = document.getElementById('gateHistoryView');
  const typeSelect = document.getElementById('gateHistoryType');
  let page = 1;
  let requestNumber = 0;
  let gatesLoaded = false;
  const time = value => value ? new Date(value).toLocaleString('en-PH', { timeZone: 'Asia/Manila' }) : '—';
  const element = (tag, text) => {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text ?? 'Unknown');
    return node;
  };

  async function json(url, options = {}) {
    const response = await (window.NaapApi?.fetch || fetch)(url, { credentials: 'same-origin', ...options });
    const data = await response.json().catch(() => null);
    if (!response.ok || !data?.ok) throw new Error(data?.message || 'Unable to load gate history. Refresh to try again.');
    return data;
  }

  function render(rows, sessions) {
    const headings = sessions
      ? ['Vehicle', 'Entry gate', 'Exit gate', 'Entry time', 'Exit time', 'Entry guard', 'Exit guard']
      : ['Vehicle', 'Guard', 'Gate', 'Scan type', 'Time'];
    const head = element('tr');
    headings.forEach(label => { const cell = element('th', label); cell.scope = 'col'; head.append(cell); });
    table.tHead.replaceChildren(head);
    table.tBodies[0].replaceChildren();
    rows.forEach(row => {
      const tr = element('tr');
      tr.dataset.vehicleId = row.vehicle_id || '';
      const values = sessions
        ? [row.vehicle_plate, row.entry_gate || 'Unknown historical gate', row.exit_gate || (row.exit_time ? 'Unknown historical gate' : 'No exit recorded'), time(row.entry_time), time(row.exit_time), row.entry_guard || 'Unknown', row.exit_guard || '—']
        : [row.vehicle_plate, row.guard_name || 'Unknown', row.gate_name || 'Unknown historical gate', row.scan_type === 'entry' ? 'Entry' : 'Exit', time(row.scanned_at)];
      values.forEach(value => tr.append(element('td', value)));
      table.tBodies[0].append(tr);
    });
  }

  function renderGateSettings(gates) {
    const container = document.getElementById('gateDirectionSettings');
    if (!container) return;
    container.replaceChildren();
    gates.forEach(gate => {
      const gateForm = element('form');
      gateForm.className = 'standard-form-actions';
      const label = element('label', gate.name);
      const select = element('select');
      select.id = `gateDirection${gate.id}`;
      label.htmlFor = select.id;
      ['both', 'entry', 'exit'].forEach(type => select.add(new Option(type === 'both' ? 'Entry and exit' : `${type === 'entry' ? 'Entry' : 'Exit'} only`, type)));
      select.value = gate.type;
      const save = element('button', 'Save direction');
      save.type = 'submit';
      save.className = 'btn-sm';
      gateForm.append(label, select, save);
      gateForm.addEventListener('submit', async event => {
        event.preventDefault();
        event.stopImmediatePropagation();
        const message = document.getElementById('gateDirectionStatus');
        save.disabled = true;
        message.textContent = `Saving ${gate.name}...`;
        try {
          await json(`/api/gates/${gate.id}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: select.value }) });
          message.textContent = `${gate.name} direction saved.`;
        } catch (error) { message.textContent = error.message; }
        finally { save.disabled = false; }
      });
      container.append(gateForm);
    });
  }

  async function load() {
    const current = ++requestNumber;
    previous.disabled = true;
    next.disabled = true;
    panel.setAttribute('aria-busy', 'true');
    status.textContent = 'Loading gate history...';
    try {
      if (!gatesLoaded) {
        const data = await json('/api/gates');
        if (current !== requestNumber) return;
        data.gates.forEach(gate => gateSelect.add(new Option(gate.name, gate.id)));
        renderGateSettings(data.gates);
        gatesLoaded = true;
      }
      const params = new URLSearchParams(new FormData(form));
      const sessions = viewSelect.value === 'sessions';
      params.delete('view');
      params.set('page', page);
      params.set('limit', '10');
      const data = await json(`${sessions ? '/api/vehicle-sessions' : '/api/logs'}?${params}`);
      if (current !== requestNumber) return;
      render(data.rows, sessions);
      status.textContent = data.total ? `${data.total} matching ${sessions ? 'sessions' : 'scans'}. ${sessions ? 'Date filters apply to entry time; the gate filter matches either end.' : ''}` : 'No records match these filters.';
      pageLabel.textContent = `Page ${page} of ${Math.max(1, Math.ceil(data.total / data.limit))}`;
      previous.disabled = page <= 1;
      next.disabled = page * data.limit >= data.total;
    } catch (error) {
      if (current !== requestNumber) return;
      table.tBodies[0].replaceChildren();
      pageLabel.textContent = '';
      status.textContent = error.message;
    } finally { if (current === requestNumber) panel.setAttribute('aria-busy', 'false'); }
  }
  form.addEventListener('submit', event => { event.preventDefault(); event.stopImmediatePropagation(); page = 1; load(); });
  viewSelect.addEventListener('change', () => { typeSelect.disabled = viewSelect.value === 'sessions'; });
  document.getElementById('gateHistoryRefresh').addEventListener('click', () => load());
  previous.addEventListener('click', () => { page--; load(); });
  next.addEventListener('click', () => { page++; load(); });
  load();
})();
