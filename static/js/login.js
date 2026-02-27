const form = document.getElementById('login-form');
        const errorBanner = document.getElementById('error-banner');

        function showError(message) {
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
                if (payload.setup_required) {
                    window.location.href = '/setup';
                    return;
                }
                if (payload.authenticated) {
                    window.location.href = '/';
                }
            } catch (_) {
                // Best effort; user can still submit form.
            }
        }

        form.addEventListener('submit', async (event) => {
            event.preventDefault();
            errorBanner.style.display = 'none';

            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;
            if (!username) {
                showError('Username is required.');
                return;
            }

            try {
                const response = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password }),
                });
                if (response.status === 409) {
                    window.location.href = '/setup';
                    return;
                }
                if (!response.ok) {
                    const payload = await response.json().catch(() => ({}));
                    showError(payload.error || 'Login failed.');
                    return;
                }
                window.location.href = '/';
            } catch (error) {
                showError(error?.message || 'Login failed.');
            }
        });

        checkSetupState();