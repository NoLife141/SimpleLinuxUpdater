const scheduledPoliciesState = {
    items: [],
    timezone: "Local"
};

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

function normalizeWeekdaysInput(raw) {
    return String(raw || '')
        .split(',')
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean);
}

function parseBlackoutsJSON(raw, label) {
    const trimmed = String(raw || '').trim();
    if (!trimmed) return [];
    try {
        const parsed = JSON.parse(trimmed);
        if (!Array.isArray(parsed)) {
            throw new Error(`${label} must be a JSON array.`);
        }
        return parsed;
    } catch (err) {
        throw new Error(`${label} must be valid JSON.`);
    }
}

function formatCadence(policy) {
    const timeLocal = escapeHtml(policy.time_local || '--:--');
    if (policy.cadence_kind === 'weekly') {
        const weekdays = Array.isArray(policy.weekdays) && policy.weekdays.length
            ? policy.weekdays.join(', ')
            : 'weekly';
        return `${escapeHtml(weekdays)} @ ${timeLocal}`;
    }
    return `daily @ ${timeLocal}`;
}

function renderPolicyMode(policy) {
    const mode = String(policy.execution_mode || '').replace(/_/g, ' ');
    const scope = String(policy.package_scope || '');
    return `${escapeHtml(mode)} / ${escapeHtml(scope)}`;
}

function resetPolicyForm() {
    document.getElementById('policy-id').value = '';
    document.getElementById('policy-name').value = '';
    document.getElementById('policy-target-tag').value = '';
    document.getElementById('policy-time-local').value = '02:00';
    document.getElementById('policy-execution-mode').value = 'scan_only';
    document.getElementById('policy-package-scope').value = 'security';
    document.getElementById('policy-cadence-kind').value = 'daily';
    document.getElementById('policy-weekdays').value = '';
    document.getElementById('policy-approval-timeout').value = '720';
    document.getElementById('policy-enabled').checked = true;
    document.getElementById('policy-blackouts').value = '[]';
    document.getElementById('policy-save-btn').textContent = 'Save Policy';
}

function applyPolicyToForm(policy) {
    document.getElementById('policy-id').value = String(policy.id || '');
    document.getElementById('policy-name').value = policy.name || '';
    document.getElementById('policy-target-tag').value = policy.target_tag || '';
    document.getElementById('policy-time-local').value = policy.time_local || '02:00';
    document.getElementById('policy-execution-mode').value = policy.execution_mode || 'scan_only';
    document.getElementById('policy-package-scope').value = policy.package_scope || 'security';
    document.getElementById('policy-cadence-kind').value = policy.cadence_kind || 'daily';
    document.getElementById('policy-weekdays').value = Array.isArray(policy.weekdays) ? policy.weekdays.join(', ') : '';
    document.getElementById('policy-approval-timeout').value = policy.approval_timeout_minutes || 720;
    document.getElementById('policy-enabled').checked = !!policy.enabled;
    document.getElementById('policy-blackouts').value = JSON.stringify(policy.policy_blackouts || [], null, 2);
    document.getElementById('policy-save-btn').textContent = 'Update Policy';
}

function renderScheduledPolicies() {
    const tbody = document.querySelector('#scheduled-policy-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!scheduledPoliciesState.items.length) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="6" class="subtle">No scheduled update policies yet.</td>';
        tbody.appendChild(row);
        return;
    }
    scheduledPoliciesState.items.forEach((policy) => {
        const row = document.createElement('tr');
        const matched = Array.isArray(policy.matched_servers) && policy.matched_servers.length
            ? policy.matched_servers.map((name) => `<span class="pill">${escapeHtml(name)}</span>`).join(' ')
            : '<span class="pill pill-muted">None</span>';
        row.innerHTML = `
            <td>
                <div>${escapeHtml(policy.name || '')}</div>
                <div class="subtle">${policy.enabled ? 'enabled' : 'disabled'}</div>
            </td>
            <td>${escapeHtml(policy.target_tag || '')}</td>
            <td>${formatCadence(policy)}</td>
            <td>${renderPolicyMode(policy)}</td>
            <td>${matched}</td>
            <td>
                <button class="btn-ghost" type="button" data-action="edit-policy" data-id="${escapeHtml(String(policy.id))}">Edit</button>
                <button class="btn-danger" type="button" data-action="delete-policy" data-id="${escapeHtml(String(policy.id))}">Delete</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function renderScheduledRuns(items) {
    const tbody = document.querySelector('#scheduled-runs-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!Array.isArray(items) || !items.length) {
        const row = document.createElement('tr');
        row.innerHTML = '<td colspan="6" class="subtle">No scheduled runs recorded yet.</td>';
        tbody.appendChild(row);
        return;
    }
    items.forEach((run) => {
        const row = document.createElement('tr');
        const jobValue = run.job_id ? `<code>${escapeHtml(run.job_id)}</code>` : '<span class="subtle">-</span>';
        row.innerHTML = `
            <td>${escapeHtml(run.scheduled_for_utc || '')}</td>
            <td>${escapeHtml(run.policy_name || '')}</td>
            <td>${escapeHtml(run.server_name || '')}</td>
            <td><span class="status-chip status-${escapeHtml(String(run.status || 'unknown').toLowerCase())}">${escapeHtml(run.status || 'unknown')}</span></td>
            <td>${escapeHtml(run.summary || run.reason || '')}</td>
            <td>${jobValue}</td>
        `;
        tbody.appendChild(row);
    });
}

async function fetchScheduledPolicies() {
    const res = await fetch('/api/update-policies');
    if (!res.ok) {
        throw new Error(await parseErrorResponse(res, 'Failed to load scheduled policies.'));
    }
    const data = await res.json().catch(() => ({}));
    scheduledPoliciesState.items = Array.isArray(data.items) ? data.items : [];
    scheduledPoliciesState.timezone = data.timezone || scheduledPoliciesState.timezone;
    renderScheduledPolicies();
}

async function fetchScheduledSettings() {
    const res = await fetch('/api/update-policies/settings');
    if (!res.ok) {
        throw new Error(await parseErrorResponse(res, 'Failed to load scheduled update settings.'));
    }
    const data = await res.json().catch(() => ({}));
    document.getElementById('scheduled-timezone').textContent = data.timezone || scheduledPoliciesState.timezone || 'Local';
    document.getElementById('scheduled-global-blackouts').value = JSON.stringify(data.global_blackouts || [], null, 2);
}

async function fetchScheduledRuns() {
    const res = await fetch('/api/update-policies/runs?limit=50');
    if (!res.ok) {
        throw new Error(await parseErrorResponse(res, 'Failed to load scheduled runs.'));
    }
    const data = await res.json().catch(() => ({}));
    renderScheduledRuns(data.items || []);
}

async function refreshScheduledUpdateViews() {
    try {
        await Promise.all([
            fetchScheduledPolicies(),
            fetchScheduledSettings(),
            fetchScheduledRuns()
        ]);
    } catch (err) {
        console.error('Failed to refresh scheduled update views:', err);
        const status = document.getElementById('update-policy-status');
        if (status) {
            status.textContent = err.message || 'Failed to load scheduled update views.';
        }
    }
}

async function saveScheduledPolicy(event) {
    event.preventDefault();
    const id = document.getElementById('policy-id').value.trim();
    const payload = {
        name: document.getElementById('policy-name').value.trim(),
        enabled: document.getElementById('policy-enabled').checked,
        target_tag: document.getElementById('policy-target-tag').value.trim(),
        package_scope: document.getElementById('policy-package-scope').value,
        execution_mode: document.getElementById('policy-execution-mode').value,
        cadence_kind: document.getElementById('policy-cadence-kind').value,
        time_local: document.getElementById('policy-time-local').value,
        weekdays: normalizeWeekdaysInput(document.getElementById('policy-weekdays').value),
        approval_timeout_minutes: Number(document.getElementById('policy-approval-timeout').value || 0),
        policy_blackouts: parseBlackoutsJSON(document.getElementById('policy-blackouts').value, 'Policy blackout windows')
    };
    const url = id ? `/api/update-policies/${encodeURIComponent(id)}` : '/api/update-policies';
    const method = id ? 'PUT' : 'POST';
    const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    if (!res.ok) {
        alert(await parseErrorResponse(res, 'Failed to save scheduled policy.'));
        return;
    }
    document.getElementById('update-policy-status').textContent = id ? 'Policy updated.' : 'Policy created.';
    resetPolicyForm();
    await refreshScheduledUpdateViews();
}

async function saveScheduledSettings() {
    try {
        const payload = {
            global_blackouts: parseBlackoutsJSON(document.getElementById('scheduled-global-blackouts').value, 'Global blackout windows')
        };
        const res = await fetch('/api/update-policies/settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            alert(await parseErrorResponse(res, 'Failed to save global blackout windows.'));
            return;
        }
        const data = await res.json().catch(() => ({}));
        document.getElementById('scheduled-timezone').textContent = data.timezone || scheduledPoliciesState.timezone || 'Local';
        document.getElementById('scheduled-settings-status').textContent = 'Global blackout windows saved.';
    } catch (err) {
        alert(err.message || 'Failed to save global blackout windows.');
    }
}

async function deleteScheduledPolicy(id) {
    if (!window.confirm('Delete this scheduled update policy?')) {
        return;
    }
    const res = await fetch(`/api/update-policies/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!res.ok) {
        alert(await parseErrorResponse(res, 'Failed to delete scheduled policy.'));
        return;
    }
    if (document.getElementById('policy-id').value === String(id)) {
        resetPolicyForm();
    }
    await refreshScheduledUpdateViews();
}

function handleScheduledPolicyTableClick(event) {
    const button = event.target.closest('button[data-action]');
    if (!button) return;
    const id = String(button.dataset.id || '').trim();
    const policy = scheduledPoliciesState.items.find((item) => String(item.id) === id);
    if (!policy) return;
    if (button.dataset.action === 'edit-policy') {
        applyPolicyToForm(policy);
        return;
    }
    if (button.dataset.action === 'delete-policy') {
        deleteScheduledPolicy(id);
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
document.getElementById('update-policy-form').addEventListener('submit', saveScheduledPolicy);
document.getElementById('policy-reset-btn').addEventListener('click', resetPolicyForm);
document.getElementById('scheduled-settings-save').addEventListener('click', saveScheduledSettings);
document.querySelector('#scheduled-policy-table tbody').addEventListener('click', handleScheduledPolicyTableClick);

resetPolicyForm();
fetchMetricsTokenStatus();
fetchBackupStatus();
refreshScheduledUpdateViews();
updateFileLabel(document.getElementById('backup-restore-file'), 'Choose backup file');
