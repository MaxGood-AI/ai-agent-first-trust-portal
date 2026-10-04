/* Trust Portal — client-side JavaScript shared by every page.
 *
 * - Adds the session's CSRF token (from <meta name="csrf-token">) to every
 *   same-origin fetch() that changes state, as the X-CSRF-Token header.
 * - Asks for confirmation on buttons carrying data-confirm="<question>"
 *   (the Content-Security-Policy forbids inline event handlers).
 * - window.trustPortalPollRun(url, onUpdate): polls an asynchronous run
 *   (collector run, git-source sync) every 2 s until it leaves the
 *   queued/running states; resolves with the final JSON.
 */
(function () {
    'use strict';

    var meta = document.querySelector('meta[name="csrf-token"]');
    var token = meta ? meta.getAttribute('content') : null;
    var SAFE = { GET: true, HEAD: true, OPTIONS: true };

    if (token && window.fetch) {
        var originalFetch = window.fetch.bind(window);
        window.fetch = function (input, init) {
            init = init || {};
            var method = (init.method || (input && input.method) || 'GET').toUpperCase();
            var url = typeof input === 'string' ? input : (input && input.url) || '';
            var sameOrigin = url.indexOf('://') === -1 || url.indexOf(window.location.origin) === 0;
            if (!SAFE[method] && sameOrigin) {
                var headers = new Headers(init.headers || {});
                if (!headers.has('X-CSRF-Token')) {
                    headers.set('X-CSRF-Token', token);
                }
                init.headers = headers;
                if (!init.credentials) {
                    init.credentials = 'same-origin';
                }
            }
            return originalFetch(input, init);
        };
    }

    window.trustPortalPollRun = function (url, onUpdate) {
        var deadline = Date.now() + 15 * 60 * 1000;
        return new Promise(function (resolve, reject) {
            function tick() {
                fetch(url, { credentials: 'same-origin' })
                    .then(function (resp) { return resp.json(); })
                    .then(function (data) {
                        var run = data.run || data;
                        if (onUpdate) { onUpdate(run); }
                        if (run.status === 'queued' || run.status === 'running') {
                            if (Date.now() > deadline) {
                                reject(new Error('Still ' + run.status + ' after 15 minutes'));
                                return;
                            }
                            setTimeout(tick, 2000);
                        } else {
                            resolve(data);
                        }
                    })
                    .catch(reject);
            }
            tick();
        });
    };

    document.addEventListener('click', function (event) {
        var target = event.target.closest ? event.target.closest('[data-confirm]') : null;
        if (target && !window.confirm(target.getAttribute('data-confirm'))) {
            event.preventDefault();
        }
    });
}());
