/* Progressive enhancement: native form validation remains available without JS. */
(function () {
  'use strict';
  let nextId = 0;
  function enhance(form) {
    const fields = [...form.querySelectorAll('input:not([type="hidden"]), select, textarea')];
    const labels = new Map(fields.map(field => {
      const copy = field.labels?.[0]?.cloneNode(true);
      copy?.querySelectorAll('input, select, textarea, button, .req').forEach(node => node.remove());
      return [field, (copy?.textContent || field.name).replace(/\*/g, '').trim()];
    }));
    const feedback = new Map();
    const touched = new Set();
    const summary = document.createElement('div');
    summary.className = 'form-error-summary';
    summary.setAttribute('role', 'alert');
    summary.hidden = true;
    form.prepend(summary);
    let attempted = false;
    let summaryKey = '';

    function label(field) {
      return labels.get(field) || field.name;
    }
    function message(field) {
      if (field.disabled || !field.willValidate) return '';
      const value = field.value;
      if (field.required && !value.trim()) return `${field.tagName === 'SELECT' ? 'Choose' : 'Enter'} ${label(field).toLowerCase()}.`;
      if (field.validity.typeMismatch && field.type === 'email') return 'Enter a complete email address, such as name@example.com.';
      if (field.dataset.passwordRules !== undefined && value && window.NaapPasswordPolicy) {
        const result = window.NaapPasswordPolicy.validatePassword(value);
        if (!result.valid) return result.issues.join(' ');
      }
      if (field.dataset.match) {
        const original = document.getElementById(field.dataset.match);
        if (original && value !== original.value) return 'The passwords do not match. Enter the same new password in both fields.';
      }
      if (field.dataset.after && value) {
        const start = document.getElementById(field.dataset.after);
        if (start?.value && new Date(value) <= new Date(start.value)) return 'Choose an end time after the start time.';
      }
      return field.validity.valid ? '' : field.validationMessage;
    }
    function renderField(field) {
      const error = message(field);
      const node = feedback.get(field);
      const show = Boolean(error && (attempted || touched.has(field)));
      node.hidden = !show;
      node.textContent = show ? error : '';
      if (show) field.setAttribute('aria-invalid', 'true');
      else field.removeAttribute('aria-invalid');
      return error;
    }
    function renderSummary(errors) {
      const key = errors.map(field => field.id).join('|');
      if (key === summaryKey) return;
      summaryKey = key;
      summary.replaceChildren();
      summary.hidden = !errors.length;
      if (!errors.length) return;
      const title = document.createElement('strong');
      title.textContent = `Check ${errors.length === 1 ? 'this field' : `these ${errors.length} fields`} before saving`;
      const list = document.createElement('ul');
      for (const field of errors) {
        const item = document.createElement('li');
        const link = document.createElement('a');
        link.href = '#' + field.id;
        link.textContent = label(field);
        link.addEventListener('click', event => { event.preventDefault(); field.focus(); });
        item.append(link);
        list.append(item);
      }
      summary.append(title, list);
    }
    function refresh() {
      const errors = fields.filter(field => renderField(field));
      if (attempted) renderSummary(errors);
      return errors;
    }
    for (const field of fields) {
      if (!field.id) field.id = 'form-field-' + ++nextId;
      const note = document.createElement('small');
      note.id = field.id + '-error';
      note.className = 'form-field-error';
      note.hidden = true;
      field.insertAdjacentElement('afterend', note);
      const describedBy = (field.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
      field.setAttribute('aria-describedby', [...new Set([...describedBy, note.id])].join(' '));
      feedback.set(field, note);
      field.addEventListener('blur', () => { touched.add(field); renderField(field); });
      field.addEventListener('input', refresh);
      field.addEventListener('change', refresh);
      if (field.type === 'password') {
        const wrapper = document.createElement('div');
        wrapper.className = 'password-field-control';
        field.before(wrapper);
        wrapper.append(field);
        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'password-field-toggle';
        toggle.textContent = 'Show';
        toggle.setAttribute('aria-label', 'Show ' + label(field).toLowerCase());
        toggle.setAttribute('aria-pressed', 'false');
        toggle.addEventListener('click', () => {
          const show = field.type === 'password';
          field.type = show ? 'text' : 'password';
          toggle.textContent = show ? 'Hide' : 'Show';
          toggle.setAttribute('aria-label', (show ? 'Hide ' : 'Show ') + label(field).toLowerCase());
          toggle.setAttribute('aria-pressed', String(show));
        });
        wrapper.append(toggle);
      }
      if (field.dataset.passwordRules !== undefined && window.NaapPasswordPolicy) {
        const list = document.createElement('ul');
        list.className = 'password-requirements';
        list.setAttribute('aria-label', 'Password requirements');
        for (const rule of window.NaapPasswordPolicy.rules) {
          const item = document.createElement('li');
          const status = document.createElement('span');
          status.setAttribute('aria-hidden', 'true');
          item.append(status, document.createTextNode(rule.label));
          const update = () => {
            const met = Boolean(field.value && rule.check(field.value));
            status.textContent = met ? '✓' : '○';
            item.classList.toggle('is-met', met);
          };
          field.addEventListener('input', update);
          update();
          list.append(item);
        }
        note.after(list);
      }
    }
    form.noValidate = true;
    form.addEventListener('submit', event => {
      attempted = true;
      const errors = refresh();
      if (errors.length) {
        event.preventDefault();
        event.stopImmediatePropagation();
        errors[0].focus();
      }
    }, true);
    form.addEventListener('reset', () => {
      attempted = false;
      touched.clear();
      summaryKey = '';
      summary.hidden = true;
      setTimeout(refresh, 0);
    });
  }
  document.querySelectorAll('form[data-form-feedback]').forEach(enhance);
}());
