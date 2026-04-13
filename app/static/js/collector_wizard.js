/* Trust Portal — collector setup wizard (finish page)
 *
 * Handles the "Run Now" buttons on the wizard review page. Each button
 * triggers POST /api/collectors/<name>/run and shows the result inline.
 */
(function () {
    'use strict';

    const resultEl = document.getElementById('wizard-run-result');

    function renderResult(title, data, isOk) {
        if (!resultEl) return;
        const container = document.createElement('div');
        container.className = 'status-banner ' + (isOk ? 'info' : 'error');

        const h = document.createElement('strong');
        h.textContent = title;
        container.appendChild(h);

        const pre = document.createElement('pre');
        pre.className = 'result-body';
        pre.textContent = JSON.stringify(data, null, 2);
        container.appendChild(pre);

        resultEl.innerHTML = '';
        resultEl.appendChild(container);
    }

    document.querySelectorAll('.run-now-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            const url = btn.getAttribute('data-run-url');
            const collector = btn.getAttribute('data-collector');
            const originalLabel = btn.textContent;
            btn.disabled = true;
            btn.textContent = 'Running\u2026';

            fetch(url, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: '{}',
            })
                .then(function (resp) { return resp.json(); })
                .then(function (data) {
                    const ok = data.status === 'success';
                    renderResult(
                        collector.toUpperCase() + ' run ' + (data.status || 'unknown'),
                        data,
                        ok,
                    );
                    if (ok) {
                        // Reload so the status badges pick up the new last_run_status
                        setTimeout(function () { window.location.reload(); }, 1500);
                    }
                })
                .catch(function (err) {
                    renderResult('Run failed', { error: String(err) }, false);
                })
                .finally(function () {
                    btn.disabled = false;
                    btn.textContent = originalLabel;
                });
        });
    });
})();
