/* Admin map presentation. All selection still goes through the original bay buttons. */
(() => {
  const map = document.getElementById('parkingSlotsList');
  if (!map) return;
  const picker = document.getElementById('parkingZonePicker');
  const controls = document.getElementById('parkingMapControls');
  const find = document.getElementById('findAvailableBay');
  const hint = document.getElementById('parkingMapHint');
  const zoomControls = document.getElementById('parkingMapZoom');
  const legend = [...document.querySelectorAll('[data-map-status]')];
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const labels = { available: 'Available', occupied: 'Occupied', reserved: 'Reserved', disabled: 'Maintenance' };
  const icons = { available: 'ph-check-circle', occupied: 'ph-car', reserved: 'ph-bookmark-simple', disabled: 'ph-prohibit' };
  const code = value => String(value || '').trim().toUpperCase();
  const visualState = slot => {
    const occupancy = String(slot.occupancy || 'available').toLowerCase();
    return occupancy === 'available' ? slot.slot_type === 'reserved' ? 'reserved' : 'available' : occupancy === 'occupied' ? 'occupied' : 'disabled';
  };
  const node = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text != null) element.textContent = text;
    return element;
  };
  const icon = name => { const element = node('i', `ph ${name}`); element.setAttribute('aria-hidden', 'true'); return element; };
  const canAnimate = () => !reduced.matches && !document.hidden && !(navigator.hardwareConcurrency <= 2) && !navigator.connection?.saveData;
  const animations = new Set();
  const animate = (element, frames, delay = 0) => {
    if (!element?.animate || !canAnimate()) return;
    const animation = element.animate(frames, { duration: 240, delay, easing: 'ease-out', fill: 'backwards' });
    animations.add(animation);
    animation.finished.catch(() => {}).finally(() => animations.delete(animation));
  };
  const enter = (element, delay = 0) => animate(element, [{ opacity: 0, transform: 'translateY(4px)' }, { opacity: 1, transform: 'translateY(0)' }], delay);
  const finishMotion = () => { if (!canAnimate()) animations.forEach(animation => animation.finish()); };
  reduced.addEventListener('change', finishMotion);
  document.addEventListener('visibilitychange', finishMotion);
  let activeZone = '';
  let lastSelected = '';
  let highlightStatus = '';
  let focusedCode = '';
  let focusScroll = 0;
  let currentSections = new Map();
  let slotsByCode = new Map();
  let isMapView = true;
  let busy = 0;
  const previousStates = new Map();
  const enteredZones = new Set();
  const zoomLevels = new Map();

  const tooltip = node('div', 'parking-bay-tooltip');
  tooltip.id = 'parkingBayTooltip';
  tooltip.setAttribute('role', 'tooltip');
  tooltip.hidden = true;
  document.body.append(tooltip);
  let tooltipOwner;
  let tooltipTimer;
  const hideTooltip = () => {
    clearTimeout(tooltipTimer);
    tooltip.hidden = true;
    tooltipOwner?.removeAttribute('aria-describedby');
    tooltipOwner = null;
  };
  const showTooltip = tile => {
    const slot = slotsByCode.get(code(tile.dataset.slotCode));
    if (!slot) return;
    hideTooltip();
    tooltipOwner = tile;
    const lines = [`${slot.slot_code} · ${labels[visualState(slot)]}`];
    if (slot.occupied_by_plate) lines.push(`Plate: ${slot.occupied_by_plate}`);
    if (slot.occupied_by_name) lines.push(`Name: ${slot.occupied_by_name}`);
    if (slot.slot_type === 'reserved') lines.push(`Reserved${slot.reserved_for ? ` for ${slot.reserved_for}` : ' space'}`);
    else if (slot.slot_type && slot.slot_type !== 'standard') lines.push(`Space type: ${slot.slot_type}`);
    if (slot.disabled_reason) lines.push(`Reason: ${slot.disabled_reason}`);
    if (slot.occupancy === 'disabled' && slot.occupied_by_type) lines.push('Vehicle still parked');
    tooltip.textContent = lines.join('\n');
    tooltip.hidden = false;
    const box = tile.getBoundingClientRect();
    tooltip.style.left = `${Math.max(8, Math.min(innerWidth - tooltip.offsetWidth - 8, box.left))}px`;
    tooltip.style.top = `${Math.max(8, box.top >= tooltip.offsetHeight + 10 ? box.top - tooltip.offsetHeight - 8 : Math.min(innerHeight - tooltip.offsetHeight - 8, box.bottom + 8))}px`;
    tile.setAttribute('aria-describedby', tooltip.id);
  };
  tooltip.addEventListener('pointerenter', () => clearTimeout(tooltipTimer));
  tooltip.addEventListener('pointerleave', hideTooltip);
  document.addEventListener('keydown', event => { if (event.key === 'Escape') hideTooltip(); });
  window.addEventListener('scroll', hideTooltip, { capture: true, passive: true });
  window.addEventListener('resize', hideTooltip);

  function highlight() {
    legend.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.mapStatus === highlightStatus)));
    map.querySelectorAll('.parking-plan-bay').forEach(tile => {
      tile.classList.toggle('map-status-muted', Boolean(highlightStatus && tile.dataset.parkingVisualState !== highlightStatus));
      tile.classList.toggle('map-status-match', Boolean(highlightStatus && tile.dataset.parkingVisualState === highlightStatus));
    });
  }
  legend.forEach(button => button.addEventListener('click', () => {
    highlightStatus = highlightStatus === button.dataset.mapStatus ? '' : button.dataset.mapStatus;
    highlight();
    hint.textContent = highlightStatus ? `Highlighting ${labels[highlightStatus].toLowerCase()} spaces. Click again to clear.` : 'All statuses shown. Arrow keys move between bays; Enter selects.';
  }));

  function updateZoom(action) {
    const section = currentSections.get(activeZone);
    const grid = section?.querySelector('.parking-plan');
    const viewport = section?.querySelector('.map-bay-viewport');
    const stage = section?.querySelector('.map-bay-stage');
    if (!grid || !viewport || !stage || !isMapView) { zoomControls.hidden = true; return; }
    // Measure the natural drawing again after a resize, not the previous scaled stage.
    grid.classList.remove('map-scaled');
    grid.style.removeProperty('transform');
    stage.style.removeProperty('width');
    stage.style.removeProperty('height');
    const width = grid.offsetWidth;
    const padding = getComputedStyle(viewport);
    const availableWidth = viewport.clientWidth - parseFloat(padding.paddingLeft) - parseFloat(padding.paddingRight);
    const fit = Math.min(1, availableWidth / Math.max(1, width));
    // Compact two-column zones fit naturally. Zoom appears only for a wider drawing.
    zoomControls.hidden = fit >= .999;
    if (zoomControls.hidden) { zoomLevels.delete(activeZone); return; }
    let scale = zoomLevels.get(activeZone) || fit;
    if (action === 'fit') scale = fit;
    if (action === 'in') scale += .15;
    if (action === 'out') scale -= .15;
    scale = Math.min(1, Math.max(Math.min(.4, fit), scale));
    zoomLevels.set(activeZone, scale);
    stage.style.width = `${width * scale}px`;
    stage.style.height = `${grid.offsetHeight * scale}px`;
    grid.classList.add('map-scaled');
    grid.style.transform = `scale(${scale})`;
    zoomControls.querySelector('[data-map-zoom="in"]').disabled = scale >= 1;
    zoomControls.querySelector('[data-map-zoom="out"]').disabled = scale <= Math.min(.4, fit);
  }
  zoomControls.addEventListener('click', event => {
    const button = event.target.closest('[data-map-zoom]');
    if (button) updateZoom(button.dataset.mapZoom);
  });
  let lastWidth = 0;
  new ResizeObserver(entries => {
    const width = entries[0].contentRect.width;
    if (width === lastWidth) return;
    lastWidth = width;
    updateZoom('fit');
  }).observe(map.parentElement);

  function showZone(animateChange = false) {
    currentSections.forEach((section, name) => { section.hidden = name !== activeZone; });
    picker.value = activeZone;
    const section = currentSections.get(activeZone);
    find.disabled = !section?.querySelector('[data-parking-visual-state="available"]');
    find.title = find.disabled ? 'No available bays in this zone with the current filters' : 'Nearest available bay on this map; first by slot number when none is selected';
    if (section && !enteredZones.has(activeZone)) {
      section.querySelectorAll('.parking-plan-bay').forEach((tile, index) => { if (index < 8) enter(tile, index * 12); });
      enteredZones.add(activeZone);
    } else if (section && animateChange) enter(section);
    updateZoom();
  }
  picker.addEventListener('change', () => {
    activeZone = picker.value;
    hideTooltip();
    showZone(true);
    hint.textContent = 'Arrow keys move between bays. Enter selects.';
  });

  function bayRows(section) {
    return [...section.querySelectorAll('.parking-plan-row')].filter(row => row.querySelector('.parking-plan-bay'));
  }
  map.addEventListener('keydown', event => {
    const tile = event.target.closest('.parking-plan-bay');
    if (!tile || !['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const section = tile.closest('.parking-zone-section');
    const rows = bayRows(section);
    const row = tile.parentElement;
    const side = [...row.children].indexOf(tile);
    let target;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
      target = row.children[side + (event.key === 'ArrowLeft' ? -2 : 2)];
    } else if (event.key === 'Home' || event.key === 'End') {
      const tiles = section.querySelectorAll('.parking-plan-bay');
      target = event.key === 'Home' ? tiles[0] : tiles[tiles.length - 1];
    } else {
      target = rows[rows.indexOf(row) + (event.key === 'ArrowUp' ? -1 : 1)]?.children[side];
    }
    if (target?.classList.contains('parking-plan-bay')) target.focus();
  });
  find.addEventListener('click', () => {
    const section = currentSections.get(activeZone);
    if (!section) return;
    const rows = bayRows(section);
    const coordinates = tile => [rows.indexOf(tile.parentElement), [...tile.parentElement.children].indexOf(tile) / 2];
    const selected = section.querySelector('.parking-plan-bay[aria-pressed="true"]');
    const origin = selected ? coordinates(selected) : [0, 0];
    const distance = tile => { const point = coordinates(tile); return Math.abs(point[0] - origin[0]) + Math.abs(point[1] - origin[1]); };
    const candidates = [...section.querySelectorAll('[data-parking-visual-state="available"]')].sort((a, b) => distance(a) - distance(b));
    const candidate = candidates[0];
    if (!candidate) return;
    const targetCode = code(candidate.dataset.slotCode);
    highlightStatus = '';
    candidate.click(); // Reuse the original selection and history flow.
    const target = [...map.querySelectorAll('.parking-plan-bay')].find(tile => code(tile.dataset.slotCode) === targetCode);
    target?.focus({ preventScroll: true });
    target?.scrollIntoView({ block: 'center', behavior: canAnimate() ? 'smooth' : 'auto' });
    hint.textContent = `Available slot ${targetCode} selected. Review its details before assigning a vehicle.`;
  });

  function decorateBay(tile, slot) {
    const state = visualState(slot);
    tile.dataset.parkingVisualState = state;
    tile.dataset.mapHasVehicle = String(Boolean(slot.occupied_by_plate || slot.occupied_by_type || state === 'occupied'));
    const badge = tile.querySelector('.parking-plan-state');
    if (badge) { badge.replaceChildren(icon(icons[state]), document.createTextNode(labels[state])); badge.firstChild.classList.add('parking-plan-state-icon'); }
    const meta = tile.querySelector('.tile-meta');
    if (meta) {
      meta.hidden = !slot.occupied_by_plate;
      meta.textContent = slot.occupied_by_plate || '';
      meta.classList.add('map-plate');
    }
    tile.querySelector('.parking-reserved-label')?.setAttribute('hidden', '');
    tile.setAttribute('aria-label', `Parking slot ${slot.slot_code}, ${labels[state]}${slot.slot_type && slot.slot_type !== 'standard' ? `, ${slot.slot_type} space` : ''}${slot.occupied_by_plate ? `, plate ${slot.occupied_by_plate}` : ''}${slot.occupied_by_name ? `, ${slot.occupied_by_name}` : ''}`);
    if (tile.dataset.mapHasVehicle === 'true') {
      const car = icon('ph-car'); car.classList.add('map-bay-car'); tile.append(car);
      if (state === 'occupied' && previousStates.has(code(slot.slot_code)) && previousStates.get(code(slot.slot_code)) !== 'occupied') {
        const direction = tile === tile.parentElement.firstElementChild ? 10 : -10;
        animate(car, [{ opacity: 0, transform: `translateX(${direction}px)` }, { opacity: 1, transform: 'translateX(0)' }]);
      }
    }
    tile.addEventListener('pointerenter', event => { if (event.pointerType !== 'touch' && matchMedia('(hover: hover)').matches) showTooltip(tile); });
    tile.addEventListener('pointerleave', () => { tooltipTimer = setTimeout(hideTooltip, 160); });
    tile.addEventListener('focus', () => {
      // Position after the browser scrolls a keyboard-focused bay into view.
      requestAnimationFrame(() => { if (document.activeElement === tile) showTooltip(tile); });
    });
    tile.addEventListener('blur', hideTooltip);
  }

  window.NaapAdminMap = {
    beforeRender() {
      focusedCode = map.contains(document.activeElement) ? code(document.activeElement.dataset.slotCode) : '';
      focusScroll = window.scrollY;
      hideTooltip();
    },
    render({ slots, zones, selectedCode }) {
      slotsByCode = new Map(slots.map(slot => [code(slot.slot_code), slot]));
      const grouped = new Map();
      slots.forEach(slot => { const name = slot.zone || 'General'; if (!grouped.has(name)) grouped.set(name, []); grouped.get(name).push(slot); });
      zones.forEach(setting => { if (setting.zone && !grouped.has(setting.zone)) grouped.set(setting.zone, []); });
      currentSections = new Map([...map.querySelectorAll('.parking-zone-section')].map(section => [section.querySelector('[data-parking-zone]').dataset.parkingZone, section]));
      if (grouped.size && !currentSections.size) map.replaceChildren();
      const names = [...grouped.keys()].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
      const options = document.createDocumentFragment();
      names.forEach(name => {
        const records = grouped.get(name);
        const counts = { available: 0, occupied: 0, reserved: 0, disabled: 0 };
        records.forEach(slot => { counts[visualState(slot)]++; });
        const option = node('option', '', `${name} · ${counts.available} available`); option.value = name; options.append(option);
        let section = currentSections.get(name);
        if (!section) { section = node('section', 'parking-zone-section'); section.append(node('div', 'parking-zone-header')); map.append(section); currentSections.set(name, section); }
        const header = section.querySelector('.parking-zone-header');
        const title = node('h4', '', name);
        const summary = node('div', 'map-zone-counts');
        Object.entries(counts).forEach(([status, count]) => { const chip = node('span', `map-zone-count ${status}`); chip.append(icon(icons[status]), node('strong', '', count), node('span', '', labels[status])); summary.append(chip); });
        const percent = records.length ? Math.round(counts.occupied / records.length * 100) : 0;
        const progress = node('div', 'map-zone-progress');
        progress.setAttribute('role', 'progressbar'); progress.setAttribute('aria-label', `${name} occupancy`);
        progress.setAttribute('aria-valuemin', '0'); progress.setAttribute('aria-valuemax', '100'); progress.setAttribute('aria-valuenow', String(percent));
        progress.setAttribute('aria-valuetext', `${counts.occupied} of ${records.length} spaces occupied`);
        const fill = node('span'); fill.style.transform = `scaleX(${percent / 100})`; progress.append(fill);
        const visibleCount = section.querySelectorAll('.parking-plan-bay').length;
        const note = node('p', 'map-zone-note', `${percent}% occupied · ${visibleCount} of ${records.length} spaces shown`);
        header.replaceChildren(title, summary, progress, note);
        const grid = section.querySelector('.parking-plan');
        if (grid) {
          grid.querySelector('.parking-plan-key')?.remove();
          grid.querySelectorAll('.parking-plan-divider-row').forEach(row => row.removeAttribute('aria-hidden'));
          grid.querySelectorAll('.parking-plan-divider').forEach(divider => { divider.textContent = ''; divider.title = 'Parking divider / curb'; divider.setAttribute('role', 'img'); divider.setAttribute('aria-label', 'Parking divider / curb'); });
          grid.querySelectorAll('.parking-plan-row:not(.parking-plan-divider-row)').forEach((row, index) => {
            if (index % 3 === 1) row.querySelector('.parking-plan-lane')?.append(icon('ph-arrow-down'));
          });
          grid.querySelectorAll('.parking-plan-bay').forEach(tile => { const slot = slotsByCode.get(code(tile.dataset.slotCode)); if (slot) decorateBay(tile, slot); });
          const viewport = node('div', 'map-bay-viewport');
          const stage = node('div', 'map-bay-stage');
          grid.replaceWith(viewport); viewport.append(stage); stage.append(grid);
        } else {
          const empty = node('div', 'map-zone-empty');
          empty.append(icon('ph-car'), node('strong', '', records.length ? 'No matching spaces' : 'No spaces in this zone yet'), node('p', '', records.length ? 'Try another search or status filter.' : 'Configured spaces will appear here.'));
          section.append(empty); enter(empty);
        }
      });
      picker.replaceChildren(options);
      picker.disabled = !names.length;
      const selectedTile = [...map.querySelectorAll('.parking-plan-bay')].find(tile => code(tile.dataset.slotCode) === code(selectedCode));
      if (lastSelected !== code(selectedCode) && selectedTile) activeZone = selectedTile.closest('[data-parking-zone]').dataset.parkingZone;
      if (!currentSections.has(activeZone)) activeZone = names[0] || '';
      lastSelected = code(selectedCode);
      highlight();
      showZone();
      slots.forEach(slot => previousStates.set(code(slot.slot_code), visualState(slot)));
      if (focusedCode) {
        const replacement = [...map.querySelectorAll('.parking-plan-bay')].find(tile => code(tile.dataset.slotCode) === focusedCode && !tile.closest('[hidden]'));
        replacement?.focus({ preventScroll: true });
        window.scrollTo({ top: focusScroll, behavior: 'instant' });
      }
    },
    viewChanged(view) {
      isMapView = view === 'map';
      controls.hidden = !isMapView;
      controls.nextElementSibling.hidden = !isMapView;
      document.querySelector('.parking-status-legend').hidden = !isMapView;
      if (isMapView) updateZoom();
      else hideTooltip();
    },
    loading(loading) {
      busy = Math.max(0, busy + (loading ? 1 : -1));
      document.getElementById('parkingMapLoading').hidden = !busy;
      hint.classList.toggle('map-hint-loading', Boolean(busy));
      map.setAttribute('aria-busy', String(Boolean(busy)));
    }
  };
})();
