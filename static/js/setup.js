const form = document.getElementById('setup-form');
const errorBanner = document.getElementById('error-banner');

function showError(message) {
    if (!errorBanner) return;
    errorBanner.textContent = message;
    errorBanner.style.display = 'block';
}

async function checkSetupState() {
    try {
        const response = await fetch('/api/auth/status', { cache: 'no-store' });
        if (!response.ok) {
            return;
        }
        const payload = await response.json();
        if (!payload.setup_required) {
            if (payload.authenticated) {
                window.location.href = '/';
            } else {
                window.location.href = '/login';
            }
        }
    } catch (_) {
        // Best effort; user can still submit form.
    }
}

if (!form || !errorBanner) {
    console.warn('setup.js: required elements #setup-form or #error-banner were not found.');
} else {
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        errorBanner.style.display = 'none';

        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const passwordConfirm = document.getElementById('password-confirm').value;

        if (password !== passwordConfirm) {
            showError('Passwords do not match.');
            return;
        }

        try {
            const response = await fetch('/api/auth/setup', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password }),
            });
            if (response.status === 409) {
                window.location.href = '/login';
                return;
            }
            if (!response.ok) {
                const payload = await response.json().catch(() => ({}));
                showError(payload.error || 'Setup failed.');
                return;
            }
            window.location.href = '/';
        } catch (error) {
            showError(error?.message || 'Setup failed.');
        }
    });

    checkSetupState();
}
