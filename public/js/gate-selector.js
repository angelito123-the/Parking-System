(() => {
  function allows(select, action) {
    const type = select?.selectedOptions?.[0]?.dataset.gateType;
    return type === 'both' || type === String(action).toLowerCase();
  }
  window.NaapGateSelector = { allows };
  document.querySelectorAll('select[data-gate-select]').forEach(select => {
    const hint = document.createElement('small');
    hint.className = 'helper-text';
    hint.setAttribute('aria-live', 'polite');
    select.after(hint);
    const update = () => {
      const type = select.selectedOptions[0]?.dataset.gateType;
      hint.textContent = type === 'both' ? 'Entry and exit allowed' : type ? `${type === 'entry' ? 'Entry' : 'Exit'} only` : 'No gates available. Reload the page to try again.';
    };
    select.addEventListener('change', update);
    update();
  });
})();
