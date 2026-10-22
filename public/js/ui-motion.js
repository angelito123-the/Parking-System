/* Presentation only: native forms, navigation, and server-provided values stay authoritative. */
(function () {
  'use strict';
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  const lite = Boolean(navigator.connection?.saveData || (navigator.hardwareConcurrency && navigator.hardwareConcurrency <= 2));
  const body = document.body;
  const variants = {
    enter: [{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 1, transform: 'translateY(0)' }],
    fade: [{ opacity: 0.55 }, { opacity: 1 }]
  };
  const animations = new Set();
  const counters = new Set();
  const canAnimate = () => !reduced.matches && !document.hidden && !lite;

  function animate(element, variant = 'enter', delay = 0) {
    if (!element?.animate || !canAnimate()) return;
    const animation = element.animate(variants[variant] || variants.enter, {
      duration: 280, delay: Math.min(delay, 120), easing: 'cubic-bezier(0.2, 0.8, 0.2, 1)', fill: 'backwards'
    });
    animations.add(animation);
    animation.finished.catch(() => {}).finally(() => animations.delete(animation));
  }

  function countUp(element) {
    const original = element.textContent.trim();
    const target = Number(original);
    if (!canAnimate() || !Number.isSafeInteger(target) || target <= 0) return;
    const spoken = document.createElement('span');
    spoken.className = 'sr-only';
    spoken.textContent = original;
    const digits = document.createElement('span');
    digits.setAttribute('aria-hidden', 'true');
    const originalMinWidth = element.style.minWidth;
    element.style.minWidth = `${element.getBoundingClientRect().width}px`;
    element.replaceChildren(spoken, digits);
    const started = performance.now();
    let frame;
    const finish = () => {
      cancelAnimationFrame(frame);
      if (element.contains(digits)) element.textContent = original;
      element.style.minWidth = originalMinWidth;
      counters.delete(finish);
    };
    counters.add(finish);
    function tick(now) {
      // A refresh may replace this value while an entrance is still running.
      if (!element.contains(digits) || !canAnimate()) return finish();
      const progress = Math.min(1, (now - started) / 360);
      digits.textContent = String(Math.round(target * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1) frame = requestAnimationFrame(tick);
      else finish();
    }
    frame = requestAnimationFrame(tick);
  }

  const samples = new Map();
  const metricIds = ['metricStudents', 'metricVehicles', 'metricInside', 'metricOverstay'];
  function sampleMetrics() {
    for (const id of metricIds) {
      const metric = document.getElementById(id);
      if (!metric) continue;
      const value = Number(metric.textContent.trim());
      if (!Number.isFinite(value) || value < 0) continue;
      const card = metric.closest('.hero-card');
      const svg = card?.querySelector('.metric-sparkline');
      if (!svg) continue;
      const series = samples.get(id) || [];
      series.push(value);
      if (series.length > 12) series.shift();
      samples.set(id, series);
      const min = Math.min(...series);
      const span = Math.max(...series) - min;
      const points = series.map((number, index) => [
        series.length === 1 ? 48 : 4 + index * 44 / (series.length - 1),
        span ? 20 - ((number - min) / span) * 16 : 12
      ]);
      const last = points[points.length - 1];
      svg.querySelector('polyline').setAttribute('points', series.length > 1 ? points.map(point => point.join(',')).join(' ') : '');
      svg.querySelector('circle').setAttribute('cx', last[0]);
      svg.querySelector('circle').setAttribute('cy', last[1]);
      const description = `${series.length} reading${series.length === 1 ? '' : 's'} this visit: ${series.join(', ')}. Updates every 20 seconds.`;
      svg.setAttribute('aria-label', description);
      svg.querySelector('title').textContent = description;
      if (id === 'metricOverstay') card.classList.toggle('has-alerts', value > 0);
    }
  }

  function dashboardUpdated() {
    sampleMetrics();
    animate(document.getElementById('insideLastUpdated'), 'fade');
    document.querySelectorAll('#insideVehiclesBody tr, #insideVehiclesCards > *').forEach((row, index) => {
      if (index < 6 && row.getClientRects().length) animate(row, 'enter', index * 20);
    });
  }

  function setDashboardBusy(busy) {
    const panel = document.querySelector('.admin-overview-panel');
    panel?.classList.toggle('is-refreshing', busy);
    const skeleton = document.getElementById('overviewLoading');
    if (skeleton) skeleton.hidden = !busy;
  }

  function changeTheme(apply) {
    // Camera playback must not be captured or paused by a document transition.
    if (!canAnimate() || !document.startViewTransition || document.querySelector('#autoQrReader video, #qr-reader video')) return apply();
    const transition = document.startViewTransition(apply);
    transition.ready.catch(() => {});
  }

  function updateMotionPreference() {
    body.classList.toggle('motion-lite', lite);
    body.classList.toggle('motion-paused', document.hidden);
    if (!canAnimate()) {
      animations.forEach(animation => animation.cancel());
      counters.forEach(finish => finish());
    }
  }
  reduced.addEventListener('change', updateMotionPreference);
  document.addEventListener('visibilitychange', updateMotionPreference);
  updateMotionPreference();
  window.addEventListener('pageswap', event => {
    if (!canAnimate()) event.viewTransition?.skipTransition();
  });

  // Remember only navigation presentation; never store credentials or session details.
  const activeLink = document.querySelector('.side-nav a[aria-current="page"]');
  if (activeLink) {
    try {
      const previous = JSON.parse(sessionStorage.getItem('naap-nav-motion') || 'null');
      const oldLink = [...document.querySelectorAll('.side-nav a')].find(link => link.pathname === previous?.path);
      if (canAnimate() && previous?.role === body.dataset.role && oldLink && oldLink !== activeLink && matchMedia('(min-width: 1081px)').matches) {
        activeLink.style.setProperty('--nav-from', `${oldLink.getBoundingClientRect().top - activeLink.getBoundingClientRect().top}px`);
        activeLink.classList.add('nav-motion-arrive');
      }
      sessionStorage.setItem('naap-nav-motion', JSON.stringify({ path: activeLink.pathname, role: body.dataset.role }));
    } catch (_) { /* Storage restrictions must not affect navigation. */ }
  }

  const loginForm = document.querySelector('.login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', event => {
      if (!event.defaultPrevented) {
        try { sessionStorage.setItem('naap-signin-motion', String(Date.now())); } catch (_) {}
      }
    });
    window.addEventListener('pageswap', event => {
      if (loginForm.dataset.submitting !== '1' || !event.activation?.entry?.url) return;
      const destination = new URL(event.activation.entry.url);
      // pageswap exposes the final URL after the server has processed the native POST.
      if (destination.origin !== location.origin || !['/admin', '/guard'].includes(destination.pathname)) return;
      const button = loginForm.querySelector('.login-btn');
      button.classList.remove('is-loading');
      button.classList.add('is-success');
      button.removeAttribute('aria-busy');
      button.querySelector('.button-label').textContent = 'Signed in';
    });
    window.addEventListener('pageshow', event => {
      // Back/forward cache can restore a disabled submit button from the outgoing page.
      if (!event.persisted) return;
      const button = loginForm.querySelector('.login-btn');
      delete loginForm.dataset.submitting;
      button.disabled = false;
      button.classList.remove('is-loading', 'is-success');
      button.removeAttribute('aria-busy');
      button.querySelector('.button-label').textContent = 'Sign in';
    });
    if (document.querySelector('.login-error')) {
      try { sessionStorage.removeItem('naap-signin-motion'); } catch (_) {}
    }
  } else if (['admin', 'guard'].includes(body.dataset.role)) {
    try {
      const started = Number(sessionStorage.getItem('naap-signin-motion'));
      sessionStorage.removeItem('naap-signin-motion');
      if (started && Date.now() - started >= 0 && Date.now() - started < 120000) {
        window.NaapFeedback?.show('Signed in successfully.', { tone: 'success' });
      }
    } catch (_) {}
  }

  window.NaapMotion = { animate, dashboardUpdated, setDashboardBusy, changeTheme };
  if (body.classList.contains('page-admin') || body.classList.contains('page-dashboard')) {
    sampleMetrics();
    metricIds.forEach(id => { const metric = document.getElementById(id); if (metric) countUp(metric); });
  }
}());
