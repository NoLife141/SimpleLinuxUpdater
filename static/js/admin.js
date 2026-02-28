function showMetricsTokenOnce(token) {
    const panel = document.getElementById('metrics-token-once');
    const value = document.getElementById('metrics-token-value');
    if (!panel || !value) return;
    if (!token) {
        value.textContent = '';
        panel.style.display = 'none';
        return;
    }
    value.textContent = token;
    panel.style.display = 'block';
}

async function fetchMetricsTokenStatus(resetReveal = true) {
    const status = document.getElementById('metrics-token-status');
    if (!status) return;
    if (resetReveal) {
        showMetricsTokenOnce('');
    }
    try {
        const res = await fetch('/api/metrics/token');
        if (!res.ok) {
            status.textContent = 'Metrics token status: unknown';
            return;
        }
        const data = await res.json().catch(() => ({}));
        status.textContent = data.enabled ? 'Metrics API token: enabled' : 'Metrics API token: disabled';
    } catch (err) {
        console.error('Failed to fetch metrics token status:', err);
        status.textContent = 'Metrics token status: request failed';
    }
}

async function rotateMetricsToken(askConfirm) {
    if (askConfirm && !window.confirm('Rotate metrics token? Existing scrapers using the old token will fail until updated.')) {
        return;
    }
    try {
        const res = await fetch('/api/metrics/token', { method: 'POST' });
        if (!res.ok) {
            alert(await parseErrorResponse(res, 'Failed to rotate metrics token.'));
            return;
        }
        const data = await res.json().catch(() => ({}));
        const token = (data && typeof data.token === 'string') ? data.token : '';
        if (!token) {
            alert('Token rotation succeeded but no token was returned.');
            return;
        }
        showMetricsTokenOnce(token);
        fetchMetricsTokenStatus(false);
    } catch (err) {
        console.error('Failed to rotate metrics token:', err);
        alert('Failed to rotate metrics token.');
    }
}

async function disableMetricsToken() {
    if (!window.confirm('Disable metrics token and hide /metrics now?')) {
        return;
    }
    try {
        const res = await fetch('/api/metrics/token', { method: 'DELETE' });
        if (!res.ok) {
            alert(await parseErrorResponse(res, 'Failed to disable metrics token.'));
            return;
        }
        showMetricsTokenOnce('');
        fetchMetricsTokenStatus();
    } catch (err) {
        console.error('Failed to disable metrics token:', err);
        alert('Failed to disable metrics token.');
    }
}

async function copyMetricsToken() {
    const tokenValue = document.getElementById('metrics-token-value');
    if (!tokenValue) return;
    const token = tokenValue.textContent || '';
    if (!token) {
        alert('No token to copy.');
        return;
    }
    try {
        await navigator.clipboard.writeText(token);
        alert('Metrics token copied.');
    } catch (_) {
        alert('Failed to copy token. Copy it manually from the box.');
    }
}

function deriveDownloadFilename(contentDisposition) {
    if (!contentDisposition) return '';
    const utf8Match = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf8Match && utf8Match[1]) {
        try {
            return decodeURIComponent(utf8Match[1]).replace(/[\r\n]/g, '');
        } catch (_) {
            return utf8Match[1].replace(/[\r\n]/g, '');
        }
    }
    const simpleMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
    if (!simpleMatch || !simpleMatch[1]) return '';
    return simpleMatch[1].replace(/[\r\n]/g, '');
}

async function fetchBackupStatus() {
    const status = document.getElementById('backup-status');
    if (!status) return;
    try {
        const res = await fetch('/api/backup/status');
        if (!res.ok) {
            status.textContent = 'Backup status: unavailable';
            return;
        }
        const data = await res.json().catch(() => ({}));
        const knownHostsState = data.known_hosts_exists ? 'present' : 'missing';
        status.textContent = `Backup paths: DB=${data.db_path || '-'}, config=${data.config_path || '-'}, known_hosts=${data.known_hosts_path || '-'} (${knownHostsState})`;
    } catch (err) {
        console.error('Failed to fetch backup status:', err);
        status.textContent = 'Backup status: request failed';
    }
}

async function exportBackup() {
    const exportPassInput = document.getElementById('backup-export-passphrase');
    const exportPassConfirmInput = document.getElementById('backup-export-passphrase-confirm');
    try {
        const pass = exportPassInput?.value || '';
        const confirmPass = exportPassConfirmInput?.value || '';
        const includeKnownHosts = !!document.getElementById('backup-include-known-hosts')?.checked;
        if (pass.length < 12) {
            alert('Passphrase must be at least 12 characters.');
            return;
        }
        if (pass !== confirmPass) {
            alert('Passphrase confirmation does not match.');
            return;
        }
        const res = await fetch('/api/backup/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ passphrase: pass, include_known_hosts: includeKnownHosts })
        });
        if (!res.ok) {
            alert(await parseErrorResponse(res, 'Failed to export backup.'));
            return;
        }
        const blob = await res.blob();
        const filename = deriveDownloadFilename(res.headers.get('Content-Disposition')) || `simplelinuxupdater-backup-${Date.now()}.slubkp`;
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        alert('Backup exported.');
    } catch (err) {
        console.error('Failed to export backup:', err);
        alert('Failed to export backup.');
    } finally {
        if (exportPassInput) exportPassInput.value = '';
        if (exportPassConfirmInput) exportPassConfirmInput.value = '';
    }
}

async function restoreBackup() {
    const fileInput = document.getElementById('backup-restore-file');
    const restorePassInput = document.getElementById('backup-restore-passphrase');
    try {
        const pass = restorePassInput?.value || '';
        const file = fileInput?.files?.[0];
        if (!file) {
            alert('Choose a backup file first.');
            return;
        }
        if (pass.length < 12) {
            alert('Passphrase must be at least 12 characters.');
            return;
        }
        if (!window.confirm('Restore will fully replace current DB/config/known_hosts. Continue?')) {
            return;
        }
        const form = new FormData();
        form.append('file', file);
        form.append('passphrase', pass);
        const res = await fetch('/api/backup/restore', {
            method: 'POST',
            body: form
        });
        if (!res.ok) {
            alert(await parseErrorResponse(res, 'Failed to restore backup.'));
            return;
        }
        alert('Backup restored successfully.');
        if (fileInput) {
            fileInput.value = '';
            updateFileLabel(fileInput, 'Choose backup file');
        }
        await fetchBackupStatus();
    } catch (err) {
        console.error('Failed to restore backup:', err);
        alert('Failed to restore backup.');
    } finally {
        if (restorePassInput) restorePassInput.value = '';
    }
}

document.addEventListener('change', (e) => {
    if (e.target && e.target.id === 'backup-restore-file') {
        updateFileLabel(e.target, 'Choose backup file');
    }
});

document.getElementById('logout-btn').addEventListener('click', () => window.logout());
document.getElementById('metrics-token-generate').addEventListener('click', () => rotateMetricsToken(false));
document.getElementById('metrics-token-rotate').addEventListener('click', () => rotateMetricsToken(true));
document.getElementById('metrics-token-disable').addEventListener('click', disableMetricsToken);
document.getElementById('metrics-token-copy').addEventListener('click', copyMetricsToken);
document.getElementById('backup-export-btn').addEventListener('click', exportBackup);
document.getElementById('backup-restore-btn').addEventListener('click', restoreBackup);

fetchMetricsTokenStatus();
fetchBackupStatus();
updateFileLabel(document.getElementById('backup-restore-file'), 'Choose backup file');
