(function () {
    if (window.__authHelpersReady) {
        return;
    }
    window.__authHelpersReady = true;

    if (!window.__nativeFetch) {
        window.__nativeFetch = window.fetch.bind(window);
    }

    if (!window.__fetchWrapped) {
        window.fetch = async (...args) => {
            const response = await window.__nativeFetch(...args);
            if (response.status === 401) {
                window.location.href = '/login';
                // Prevent unhandled rejections while navigation is in progress.
                return new Promise(() => {});
            }
            return response;
        };
        window.__fetchWrapped = true;
    }

    window.logout = async function logout() {
        try {
            await window.__nativeFetch('/api/auth/logout', { method: 'POST' });
        } catch (_) {
            // Best effort.
        }
        window.location.href = '/login';
        return new Promise(() => {});
    };

    async function revalidateAuthenticatedPage() {
        try {
            const response = await window.__nativeFetch('/api/auth/status', { cache: 'no-store' });
            if (!response.ok) {
                window.location.replace('/login');
                return;
            }
            const payload = await response.json();
            if (payload.setup_required) {
                window.location.replace('/setup');
                return;
            }
            if (!payload.authenticated) {
                window.location.replace('/login');
            }
        } catch (_) {
            // Best effort; the next authenticated fetch will redirect on 401.
        }
    }

    window.addEventListener('pageshow', (event) => {
        if (event.persisted) {
            revalidateAuthenticatedPage();
        }
    });
})();
