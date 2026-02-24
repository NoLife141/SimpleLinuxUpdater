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
})();
