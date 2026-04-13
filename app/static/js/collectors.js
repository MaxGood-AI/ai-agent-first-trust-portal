/* Trust Portal — collector configuration page
 *
 * Handles the dynamic bits of /admin/collectors/<name>:
 *   - environment detection (account, region, identity)
 *   - showing/hiding credential-mode panels
 *   - test-connection / recheck-permissions / run-now buttons
 *   - loading + copying the IAM policy JSON
 *
 * All server calls go to the JSON API (/api/collectors/*) which is
 * admin-authenticated via the session cookie set at /admin/login.
 */
(function () {
    'use strict';

    // ---- Environment detection ----

    const envBox = document.getElementById('environment-detection');
    const envText = envBox ? envBox.querySelector('.env-detection-text') : null;

    if (envBox && envText) {
        const url = envBox.getAttribute('data-detect-url');
        fetch(url, { credentials: 'same-origin' })
            .then(function (resp) { return resp.json(); })
            .then(function (data) {
                const parts = [];
                if (data.is_ecs) parts.push('ECS task');
                else parts.push('Non-ECS host');
                if (data.account_id) parts.push('Account ' + data.account_id);
                if (data.default_region) parts.push('Region ' + data.default_region);
                if (data.identity) parts.push('Identity: ' + data.identity);
                envText.textContent = parts.join(' \u00b7 ');

                // Suggest the appropriate credential mode based on detection.
                const recommend = document.createElement('div');
                recommend.className = 'env-detection-hint';
                if (data.account_id) {
                    recommend.textContent = (
                        'Detected AWS identity. Recommended mode: ' +
                        (data.is_ecs
                            ? '"Assume a dedicated collector role" (same-account ECS)'
                            : '"Task role" or "Provide access keys"')
                    );
                } else {
                    recommend.textContent = (
                        'No AWS identity detected. Use "Provide access keys" ' +
                        'or run the portal on an AWS host with an attached role.'
                    );
                }
                envBox.appendChild(recommend);
            })
            .catch(function (err) {
                envText.textContent = 'Unable to detect environment: ' + String(err);
            });
    }

    // ---- Credential-mode panel visibility ----

    const modeSelect = document.getElementById('credential_mode');
    const panels = document.querySelectorAll('.credential-mode-panel');

    function syncPanels() {
        if (!modeSelect) return;
        const mode = modeSelect.value;
        panels.forEach(function (panel) {
            const showFor = panel.getAttribute('data-mode');
            panel.style.display = showFor === mode ? 'block' : 'none';
        });
    }

    if (modeSelect) {
        modeSelect.addEventListener('change', syncPanels);
        syncPanels();
    }

    // ---- Action buttons ----

    const resultEl = document.getElementById('action-result');

    function renderResult(title, data, isOk) {
        if (!resultEl) return;
        const header = document.createElement('h3');
        header.textContent = title;
        header.className = isOk ? 'result-ok' : 'result-err';

        const body = document.createElement('pre');
        body.className = 'result-body';
        body.textContent = JSON.stringify(data, null, 2);

        resultEl.innerHTML = '';
        resultEl.appendChild(header);
        resultEl.appendChild(body);
    }

    function postJson(url) {
        return fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: '{}',
        }).then(function (resp) {
            return resp.json().then(function (data) {
                return { ok: resp.ok, status: resp.status, data: data };
            });
        });
    }

    function wireActionButton(id, onSuccess) {
        const btn = document.getElementById(id);
        if (!btn) return;
        btn.addEventListener('click', function () {
            const url = btn.getAttribute('data-action-url');
            btn.disabled = true;
            btn.textContent = 'Working\u2026';
            const originalLabel = btn.getAttribute('data-original-label') || btn.dataset.originalLabel;
            if (!originalLabel) {
                btn.dataset.originalLabel = btn.textContent;
            }
            postJson(url)
                .then(function (result) {
                    onSuccess(result);
                })
                .catch(function (err) {
                    renderResult('Request failed', { error: String(err) }, false);
                })
                .finally(function () {
                    btn.disabled = false;
                    btn.textContent = btn.dataset.originalLabel || id;
                });
        });
        // Stash the original label so the Working... state can restore it.
        btn.dataset.originalLabel = btn.textContent;
    }

    wireActionButton('test-connection-btn', function (result) {
        renderResult(
            result.data.ok ? 'Connection OK' : 'Connection failed',
            result.data,
            result.data.ok,
        );
    });

    wireActionButton('probe-btn', function (result) {
        renderResult(
            result.data.ok ? 'All permissions granted' : 'Some permissions missing',
            result.data.probe || result.data,
            result.data.ok,
        );
    });

    wireActionButton('run-now-btn', function (result) {
        const data = result.data || {};
        const ok = data.status === 'success';
        renderResult(
            'Run ' + (data.status || 'unknown'),
            data,
            ok,
        );
    });

    // ---- IAM policy load + copy ----

    const loadBtn = document.getElementById('load-policy-btn');
    const copyBtn = document.getElementById('copy-policy-btn');
    const policyPre = document.getElementById('policy-json');
    let loadedPolicyText = '';

    if (loadBtn && policyPre) {
        loadBtn.addEventListener('click', function () {
            const url = loadBtn.getAttribute('data-action-url');
            loadBtn.disabled = true;
            loadBtn.textContent = 'Loading\u2026';
            fetch(url, { credentials: 'same-origin' })
                .then(function (resp) { return resp.json(); })
                .then(function (data) {
                    loadedPolicyText = JSON.stringify(data.policy, null, 2);
                    policyPre.textContent = loadedPolicyText;
                    if (copyBtn) copyBtn.disabled = false;
                })
                .catch(function (err) {
                    policyPre.textContent = 'Failed to load policy: ' + String(err);
                })
                .finally(function () {
                    loadBtn.disabled = false;
                    loadBtn.textContent = 'Reload IAM Policy';
                });
        });
    }

    if (copyBtn) {
        copyBtn.addEventListener('click', function () {
            if (!loadedPolicyText) return;
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(loadedPolicyText).then(function () {
                    const original = copyBtn.textContent;
                    copyBtn.textContent = 'Copied!';
                    setTimeout(function () { copyBtn.textContent = original; }, 2000);
                });
            } else {
                // Fallback for very old browsers
                const textarea = document.createElement('textarea');
                textarea.value = loadedPolicyText;
                document.body.appendChild(textarea);
                textarea.select();
                try { document.execCommand('copy'); } catch (e) { /* ignore */ }
                document.body.removeChild(textarea);
            }
        });
    }
})();
