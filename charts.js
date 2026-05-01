/* global window, document */
// Chart.js helpers for the admin dashboard (loaded dynamically)
(function () {
  'use strict';

  function loadScriptOnce(src) {
    return new Promise((resolve, reject) => {
      const existing = document.querySelector(`script[data-src="${src}"]`);
      if (existing) {
        if (existing.dataset.loaded === '1') return resolve();
        existing.addEventListener('load', () => resolve());
        existing.addEventListener('error', () => reject(new Error(`Failed to load ${src}`)));
        return;
      }

      const s = document.createElement('script');
      s.src = src;
      s.async = true;
      s.dataset.src = src;
      s.addEventListener('load', () => {
        s.dataset.loaded = '1';
        resolve();
      });
      s.addEventListener('error', () => reject(new Error(`Failed to load ${src}`)));
      document.head.appendChild(s);
    });
  }

  async function ensureChartJs() {
    if (window.Chart) return;
    // CDN load (kept simple; no build tools)
    await loadScriptOnce('https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js');
  }

  function upsertSection(container, id, titleText) {
    let section = document.getElementById(id);
    if (!section) {
      section = document.createElement('div');
      section.id = id;
      section.className = 'output-section';
      section.style.display = 'block';

      const h2 = document.createElement('h2');
      h2.textContent = titleText;
      section.appendChild(h2);

      container.appendChild(section);
    }
    return section;
  }

  function renderStatsChart({ container, stats }) {
    const section = upsertSection(container, 'adminDashboardCharts', 'Admin Dashboard (Attack Analytics)');

    let canvas = section.querySelector('canvas');
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.height = 120;
      section.appendChild(canvas);
    }

    const ctx = canvas.getContext('2d');
    const labels = ['SQLi attempts', 'XSS attempts'];
    const values = [stats?.sqli || 0, stats?.xss || 0];

    if (canvas._chart) {
      canvas._chart.data.labels = labels;
      canvas._chart.data.datasets[0].data = values;
      canvas._chart.update();
      return;
    }

    canvas._chart = new window.Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: 'Attempts (window)',
            data: values,
            backgroundColor: ['rgba(239, 68, 68, 0.7)', 'rgba(59, 130, 246, 0.7)'],
            borderColor: ['rgba(239, 68, 68, 1)', 'rgba(59, 130, 246, 1)'],
            borderWidth: 1,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: true },
          title: { display: false },
        },
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });
  }

  function renderLogs({ container, logs }) {
    const section = upsertSection(container, 'adminDashboardLogs', 'Admin Dashboard (Attack Logs)');

    let box = section.querySelector('.output-box');
    if (!box) {
      box = document.createElement('div');
      box.className = 'output-box';
      section.appendChild(box);
    }

    // Keep rendering simple (table-like using <pre>).
    const lines = [];
    for (const row of logs || []) {
      const ts = row.timestamp || '';
      const ip = row.ip || '';
      const type = row.attack_type || '';
      const payload = row.payload || '';
      lines.push(`[${ts}] ${type} from ${ip}\n${payload}\n`);
    }
    box.textContent = lines.length ? lines.join('\n') : 'No attack logs in this window yet.';
  }

  window.CyberDemoCharts = {
    ensureChartJs,
    renderStatsChart,
    renderLogs,
  };
})();

