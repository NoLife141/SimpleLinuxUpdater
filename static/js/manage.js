let serverCache = {};
        let sortKey = "name";
        let sortDir = "asc";
        let manageServers = [];
        let page = 1;
        let editingServerName = null;
        let auditEvents = [];
        let auditPage = 1;
        let auditPageSize = 20;
            let auditTotal = 0;
            let hostKeyModalPromise = null;
            let hostKeyModalResolvers = [];
            let editSaveInProgress = false;
            let editKnownHostState = { host: '', port: 0, checked: false, alreadyTrusted: false, fingerprint: '' };
            let editKnownHostCheckPromise = null;

        function escapeHtml(value) {
            return String(value ?? "")
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        }

        function escapeJsSingleQuoted(value) {
            return String(value ?? "")
                .replace(/\\/g, "\\\\")
                .replace(/'/g, "\\'")
                .replace(/\r/g, "\\r")
                .replace(/\n/g, "\\n")
                .replace(/\u2028/g, "\\u2028")
                .replace(/\u2029/g, "\\u2029");
        }

            function normalizePort(value, fallback = 22) {
                const parsed = Number.parseInt(value, 10);
                if (!Number.isFinite(parsed) || parsed <= 0 || parsed > 65535) return fallback;
                return parsed;
            }

            function resetEditKnownHostState() {
                editKnownHostState = { host: '', port: 0, checked: false, alreadyTrusted: false, fingerprint: '' };
                editKnownHostCheckPromise = null;
            }

            function setEditKnownHostState(host, port, checked, alreadyTrusted, fingerprint) {
                editKnownHostState = {
                    host: String(host || '').trim(),
                    port: normalizePort(port, 22),
                    checked: !!checked,
                    alreadyTrusted: !!alreadyTrusted,
                    fingerprint: String(fingerprint || '').trim()
                };
            }

            function isEditKnownHostTrusted(host, port) {
                const normalizedHost = String(host || '').trim();
                const normalizedPort = normalizePort(port, 22);
                return !!editKnownHostState.checked &&
                    !!editKnownHostState.alreadyTrusted &&
                    editKnownHostState.host === normalizedHost &&
                    editKnownHostState.port === normalizedPort;
            }

        async function scanHostKey(host, port) {
            const res = await fetch('/api/hostkeys/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host, port })
            });
            if (!res.ok) {
                throw new Error(await parseErrorResponse(res, 'Failed to scan host key.'));
            }
            return res.json();
        }

            async function trustHostKey(host, port, fingerprint) {
                const res = await fetch('/api/hostkeys/trust', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ host, port, fingerprint_sha256: fingerprint })
                });
                if (!res.ok) {
                    throw new Error(await parseErrorResponse(res, 'Failed to trust host key.'));
                }
                return res.json();
            }

            async function clearKnownHost(host, port) {
                const res = await fetch('/api/hostkeys/clear', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ host, port })
                });
                if (!res.ok) {
                    throw new Error(await parseErrorResponse(res, 'Failed to clear known host entry.'));
                }
                return res.json();
            }

        function hostKeyPromptText(scanned) {
            return (
                `Host: ${scanned.host}\n` +
                `Port: ${scanned.port}\n` +
                `Algorithm: ${scanned.algorithm}\n` +
                `Fingerprint: ${scanned.fingerprint_sha256}\n\n` +
                `Add this key to known_hosts?`
            );
        }

        function closeHostKeyModal(confirmed) {
            const modal = document.getElementById('hostkey-modal');
            if (modal) {
                modal.classList.remove('active');
            }
            const resolvers = hostKeyModalResolvers;
            hostKeyModalResolvers = [];
            hostKeyModalPromise = null;
            for (const resolver of resolvers) {
                resolver(!!confirmed);
            }
        }

        function confirmHostKeyWithModal(scanned) {
            const modal = document.getElementById('hostkey-modal');
            const details = document.getElementById('hostkey-modal-details');
            if (!modal || !details) {
                return Promise.resolve(confirm(`Verify SSH host key before trusting:\n\n${hostKeyPromptText(scanned)}`));
            }
            if (!hostKeyModalPromise) {
                details.textContent = hostKeyPromptText(scanned);
                modal.classList.add('active');
                hostKeyModalPromise = Promise.resolve(true);
            }
            return new Promise((resolve) => {
                hostKeyModalResolvers.push(resolve);
            });
        }

        async function trustHostKeyFlow(host, port, hooks = {}) {
            if (typeof hooks.onScanning === 'function') {
                hooks.onScanning();
            }
            const scanned = await scanHostKey(host, port);
            if (typeof hooks.onScanned === 'function') {
                hooks.onScanned(scanned);
            }
            if (scanned && scanned.already_trusted) {
                if (typeof hooks.onAlreadyTrusted === 'function') {
                    hooks.onAlreadyTrusted(scanned);
                }
                return { alreadyTrusted: true, scanned };
            }
            const confirmed = await confirmHostKeyWithModal(scanned);
            if (!confirmed) {
                throw new Error('Host key trust cancelled.');
            }
            if (typeof hooks.onTrusting === 'function') {
                hooks.onTrusting(scanned);
            }
            const trusted = await trustHostKey(scanned.host, scanned.port, scanned.fingerprint_sha256);
            return { alreadyTrusted: !!trusted?.already_trusted, scanned, trusted };
        }

        function saveWindowScroll() {
            return { x: window.scrollX, y: window.scrollY };
        }

        function restoreWindowScroll(pos) {
            if (!pos) return;
            window.scrollTo(pos.x, pos.y);
        }

        async function fetchManageServers() {
            const pageScroll = saveWindowScroll();
            try {
                const response = await fetch('/api/servers');
                if (!response.ok) {
                    throw new Error(await parseErrorResponse(response, 'Failed to load servers.'));
                }
                const servers = await response.json();
                if (!Array.isArray(servers)) {
                    throw new Error('Invalid server list response.');
                }
                manageServers = servers;
                const tbody = document.querySelector('#manage-servers-table tbody');
                tbody.innerHTML = '';
                renderTable();
                requestAnimationFrame(() => restoreWindowScroll(pageScroll));
            } catch (error) {
                alert(error?.message || 'Failed to load servers.');
            }
        }

        function sortServers(servers) {
            const dir = sortDir === "asc" ? 1 : -1;
            return servers.slice().sort((a, b) => {
                const aVal = (sortKey === "tags" ? (a.tags || []).join(",") : (a[sortKey] || "")).toString().toLowerCase();
                const bVal = (sortKey === "tags" ? (b.tags || []).join(",") : (b[sortKey] || "")).toString().toLowerCase();
                if (aVal < bVal) return -1 * dir;
                if (aVal > bVal) return 1 * dir;
                return 0;
            });
        }

        function applyFilters(servers) {
            const search = document.getElementById('search').value.trim().toLowerCase();
            const tagFilter = document.getElementById('tag-filter').value.trim().toLowerCase();
            const authFilter = document.getElementById('auth-filter').value;
            return servers.filter(server => {
                if (authFilter === "password" && !server.has_password) return false;
                if (authFilter === "key" && !server.has_key) return false;
                if (tagFilter) {
                    const tags = (server.tags || []).join(" ").toLowerCase();
                    if (!tags.includes(tagFilter)) return false;
                }
                if (!search) return true;
                const haystack = [
                    server.name,
                    server.host,
                    server.user,
                    (server.tags || []).join(" ")
                ].join(" ").toLowerCase();
                return haystack.includes(search);
            });
        }

        function paginate(servers) {
            const size = parseInt(document.getElementById('page-size').value, 10);
            const totalPages = Math.max(1, Math.ceil(servers.length / size));
            page = Math.min(page, totalPages);
            const start = (page - 1) * size;
            const end = start + size;
            document.getElementById('page-info').textContent = `Page ${page} of ${totalPages} (${servers.length} hosts)`;
            return servers.slice(start, end);
        }

        function groupServers(servers) {
            const groupBy = document.getElementById('group-by').value;
            if (!groupBy) return [{ key: "", items: servers }];
            const groups = new Map();
            if (groupBy === "tag") {
                servers.forEach(server => {
                    const tags = server.tags && server.tags.length ? server.tags : ["untagged"];
                    tags.forEach(tag => {
                        if (!groups.has(tag)) groups.set(tag, []);
                        groups.get(tag).push(server);
                    });
                });
            } else if (groupBy === "auth") {
                servers.forEach(server => {
                    const key = server.has_key ? "key" : "no key";
                    const pw = server.has_password ? "password" : "no password";
                    const group = `${key} / ${pw}`;
                    if (!groups.has(group)) groups.set(group, []);
                    groups.get(group).push(server);
                });
            }
            return Array.from(groups.entries()).map(([key, items]) => ({ key, items }));
        }

        function renderTable() {
            const tbody = document.querySelector('#manage-servers-table tbody');
            tbody.innerHTML = '';
            serverCache = {};
            let servers = applyFilters(manageServers);
            servers = sortServers(servers);
            const paged = paginate(servers);
            const groups = groupServers(paged);
            groups.forEach(group => {
                if (group.key) {
                    const groupRow = document.createElement('tr');
                    groupRow.className = 'group-row';
                    groupRow.innerHTML = `<td colspan="6">${escapeHtml(group.key)}</td>`;
                    tbody.appendChild(groupRow);
                }
                group.items.forEach(server => {
                    serverCache[server.name] = server;
                    const row = document.createElement('tr');
                    row.dataset.name = server.name;
                    const safeName = escapeHtml(server.name);
                    const safeHost = escapeHtml(server.host);
                    const safeUser = escapeHtml(server.user);
                    const safeDataName = escapeHtml(server.name);
                    row.innerHTML = `
                        <td>${safeName}</td>
                        <td>${safeHost}</td>
                        <td>${safeUser}</td>
                        <td>${renderTags(server.tags)}</td>
                        <td>${renderAuth(server)}</td>
                        <td>
                            <button type="button" class="btn-ghost" data-action="edit-server" data-name="${safeDataName}">Edit</button>
                            <button type="button" class="btn-danger" data-action="delete-server" data-name="${safeDataName}">Delete</button>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            });
        }

        document.querySelector('#manage-servers-table tbody').addEventListener('click', (e) => {
            const button = e.target.closest('button[data-action]');
            if (!button) return;
            const name = button.dataset.name || "";
            if (!name) return;
            const action = button.dataset.action || "";
            if (action === "edit-server") {
                editServer(name);
                return;
            }
            if (action === "delete-server") {
                deleteServer(name);
            }
        });

        document.querySelectorAll('#manage-servers-table th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const key = th.dataset.sortKey;
                if (sortKey === key) {
                    sortDir = sortDir === "asc" ? "desc" : "asc";
                } else {
                    sortKey = key;
                    sortDir = "asc";
                }
                renderTable();
            });
        });

        document.getElementById('search').addEventListener('input', () => { page = 1; renderTable(); });
        document.getElementById('tag-filter').addEventListener('input', () => { page = 1; renderTable(); });
        document.getElementById('auth-filter').addEventListener('change', () => { page = 1; renderTable(); });
        document.getElementById('group-by').addEventListener('change', () => { page = 1; renderTable(); });
        document.getElementById('page-size').addEventListener('change', () => { page = 1; renderTable(); });

        document.getElementById('prev-page').addEventListener('click', () => {
            page = Math.max(1, page - 1);
            renderTable();
        });
        document.getElementById('next-page').addEventListener('click', () => {
            page += 1;
            renderTable();
        });
        document.getElementById('audit-prev-page').addEventListener('click', async () => {
            auditPage = Math.max(1, auditPage - 1);
            await fetchAuditEvents();
        });
        document.getElementById('audit-next-page').addEventListener('click', async () => {
            auditPage += 1;
            await fetchAuditEvents();
        });
        document.getElementById('audit-target-filter').addEventListener('input', async () => {
            auditPage = 1;
            await fetchAuditEvents();
        });
        document.getElementById('audit-action-filter').addEventListener('input', async () => {
            auditPage = 1;
            await fetchAuditEvents();
        });
        document.getElementById('audit-status-filter').addEventListener('change', async () => {
            auditPage = 1;
            await fetchAuditEvents();
        });
        document.getElementById('audit-refresh').addEventListener('click', fetchAuditEvents);
        document.getElementById('audit-prune').addEventListener('click', async () => {
            const res = await fetch('/api/audit-events/prune', { method: 'POST' });
            if (!res.ok) {
                alert(await parseErrorResponse(res, 'Failed to prune audit events.'));
                return;
            }
            await fetchAuditEvents();
        });

        function renderAuth(server) {
            const bits = [];
            if (server.has_password) {
                bits.push('<span class="pill pill-success">Password</span>');
            } else {
                bits.push('<span class="pill pill-muted">No Password</span>');
            }
            if (server.has_key) {
                bits.push('<span class="pill pill-success">Key</span>');
            } else {
                bits.push('<span class="pill pill-muted">No Key</span>');
            }
            return bits.join(' ');
        }

        function renderTags(tags) {
            if (!tags || tags.length === 0) {
                return '<span class="pill pill-muted">None</span>';
            }
            return tags.map(tag => `<span class="pill">${escapeHtml(tag)}</span>`).join(' ');
        }

        function safeStatusClassToken(status) {
            const normalized = String(status || 'unknown').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
            switch (normalized) {
                case 'success':
                case 'failure':
                case 'started':
                case 'ignored':
                case 'error':
                case 'pending':
                case 'unknown':
                    return normalized;
                default:
                    return 'unknown';
            }
        }

        function renderAuditTable() {
            const tbody = document.querySelector('#audit-table tbody');
            if (!tbody) return;
            tbody.innerHTML = '';
            if (!auditEvents.length) {
                const row = document.createElement('tr');
                row.innerHTML = '<td colspan="6" class="subtle">No activity yet.</td>';
                tbody.appendChild(row);
            } else {
                auditEvents.forEach(evt => {
                    const row = document.createElement('tr');
                    const status = escapeHtml(evt.status || 'unknown');
                    const statusClass = `status-${safeStatusClassToken(evt.status)}`;
                    row.innerHTML = `
                        <td>${escapeHtml(evt.created_at || '')}</td>
                        <td>${escapeHtml(evt.actor || '')}</td>
                        <td>${escapeHtml(evt.action || '')}</td>
                        <td>${escapeHtml(evt.target_type || '')}: ${escapeHtml(evt.target_name || '')}</td>
                        <td><span class="status-badge ${statusClass}">${status}</span></td>
                        <td>${escapeHtml(evt.message || '')}</td>
                    `;
                    tbody.appendChild(row);
                });
            }
            const totalPages = Math.max(1, Math.ceil(auditTotal / auditPageSize));
            const currentPage = Math.min(auditPage, totalPages);
            document.getElementById('audit-page-info').textContent = `Page ${currentPage} of ${totalPages} (${auditTotal} events)`;
        }

        async function fetchAuditEvents() {
            const params = new URLSearchParams({
                page: String(auditPage),
                page_size: String(auditPageSize)
            });
            const targetName = document.getElementById('audit-target-filter').value.trim();
            const action = document.getElementById('audit-action-filter').value.trim();
            const status = document.getElementById('audit-status-filter').value;
            if (targetName) params.set('target_name', targetName);
            if (action) params.set('action', action);
            if (status) params.set('status', status);
            const res = await fetch(`/api/audit-events?${params.toString()}`);
            if (!res.ok) {
                const msg = await parseErrorResponse(res, 'Failed to load audit events.');
                alert(msg);
                return;
            }
            const data = await res.json();
            auditEvents = data.items || [];
            auditTotal = Number(data.total || 0);
            const totalPages = Math.max(1, Math.ceil(auditTotal / auditPageSize));
            if (auditPage > totalPages) {
                auditPage = totalPages;
                await fetchAuditEvents();
                return;
            }
            renderAuditTable();
        }

        document.getElementById('add-server-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const name = document.getElementById('name').value;
            const host = document.getElementById('host').value;
            const portValue = document.getElementById('port').value;
            const port = portValue ? parseInt(portValue, 10) : 0;
            const user = document.getElementById('user').value;
            const pass = document.getElementById('pass').value;
            const tagsRaw = document.getElementById('tags').value;
            const tags = tagsRaw.split(',').map(t => t.trim()).filter(Boolean);
            const keyFileInput = document.getElementById('key_file');
            const trustHostNow = document.getElementById('trust-host-key').checked;
            const trimmedName = name.trim();
            const createRes = await fetch('/api/servers', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, host, port, user, pass, tags })
            });
            if (!createRes.ok) {
                alert(await parseErrorResponse(createRes, 'Failed to add server.'));
                return;
            }
            const created = await createRes.json().catch(() => ({
                name: trimmedName || name,
                host: host.trim(),
                port: normalizePort(port, 22)
            }));
            if (keyFileInput && keyFileInput.files && keyFileInput.files.length > 0) {
                const form = new FormData();
                form.append('key', keyFileInput.files[0]);
                const serverName = created.name || trimmedName || name;
                const res = await fetch(`/api/servers/${encodeURIComponent(serverName)}/key`, { method: 'POST', body: form });
                if (!res.ok) {
                    alert(await parseErrorResponse(res, 'Failed to upload key.'));
                }
            }
            if (trustHostNow) {
                try {
                    await trustHostKeyFlow(created.host || host.trim(), normalizePort(created.port, 22));
                } catch (err) {
                    alert(`Server added, but host key was not trusted: ${err.message || 'unknown error'}`);
                }
            }
            if (keyFileInput) {
                keyFileInput.value = '';
                updateFileLabel(keyFileInput, 'Click to upload key');
            }
            fetchManageServers();
            e.target.reset();
            document.getElementById('trust-host-key').checked = true;
        });

        document.addEventListener('change', (e) => {
            if (e.target && e.target.classList.contains('file-input')) {
                updateFileLabel(e.target, 'Click to upload key');
            }
        });

        async function deleteServer(name) {
            if (confirm('Delete server?')) {
                try {
                    const response = await fetch(`/api/servers/${encodeURIComponent(name)}`, { method: 'DELETE' });
                    if (!response.ok) {
                        throw new Error(await parseErrorResponse(response, 'Failed to delete server.'));
                    }
                    await fetchManageServers();
                } catch (error) {
                    alert(error?.message || 'Failed to delete server.');
                }
            }
        }

            function editServer(name) {
                const current = serverCache[name] || {};
                editSaveInProgress = false;
                editingServerName = name;
                resetEditKnownHostState();
            document.getElementById('edit-name').value = current.name || name;
            document.getElementById('edit-host').value = current.host || '';
            document.getElementById('edit-port').value = current.port || '';
            document.getElementById('edit-user').value = current.user || '';
            document.getElementById('edit-tags').value = (current.tags || []).join(', ');
            document.getElementById('edit-pass').value = '';
            document.getElementById('edit-trust-host-key').checked = true;
            const keyInput = document.getElementById('edit-key');
            if (keyInput) {
                keyInput.value = '';
                updateFileLabel(keyInput, 'Click to upload key');
                }
                setEditHostKeyStatus('');
                clearEditValidationState();
                setEditSaveButtonState(false);
                setEditKnownHostButtonsState(false);
                document.getElementById('edit-modal').classList.add('active');
                checkEditKnownHostStatus();
            }

            function closeEditModal() {
                document.getElementById('edit-modal').classList.remove('active');
                setEditHostKeyStatus('');
                clearEditValidationState();
                setEditSaveButtonState(false);
                setEditKnownHostButtonsState(false);
                editingServerName = null;
                resetEditKnownHostState();
            }

        function setEditHostKeyStatus(message) {
            const el = document.getElementById('edit-hostkey-status');
            if (!el) return;
            el.textContent = String(message || '').trim();
        }

            function setEditValidationError(message) {
                const el = document.getElementById('edit-error');
                if (!el) return;
                el.textContent = String(message || '').trim();
            }

            function setEditFieldInvalidState(fieldId, isInvalid) {
                const input = document.getElementById(fieldId);
                if (!input) return;
                input.classList.toggle('is-invalid', !!isInvalid);
                if (isInvalid) {
                    input.setAttribute('aria-invalid', 'true');
                } else {
                    input.removeAttribute('aria-invalid');
                }
            }

            function maybeClearEditValidationError() {
                const requiredFields = ['edit-name', 'edit-host', 'edit-user'];
                const hasInvalid = requiredFields.some((fieldId) => {
                    const input = document.getElementById(fieldId);
                    return !!input && input.classList.contains('is-invalid');
                });
                if (!hasInvalid) {
                    setEditValidationError('');
                }
            }

            function clearEditValidationState() {
                setEditValidationError('');
                setEditFieldInvalidState('edit-name', false);
                setEditFieldInvalidState('edit-host', false);
                setEditFieldInvalidState('edit-user', false);
            }

            function setEditSaveButtonState(isBusy, label) {
                const saveBtn = document.getElementById('edit-save');
                const cancelBtn = document.getElementById('edit-cancel');
                if (!saveBtn) return;
                saveBtn.disabled = !!isBusy;
                saveBtn.textContent = isBusy ? (label || 'Saving...') : 'Save';
                if (cancelBtn) {
                    cancelBtn.disabled = !!isBusy;
                }
            }

            function setEditKnownHostButtonsState(isBusy, checkLabel, clearLabel) {
                const checkBtn = document.getElementById('edit-check-known-host');
                const clearBtn = document.getElementById('edit-clear-known-host');
                if (checkBtn) {
                    checkBtn.disabled = !!isBusy;
                    checkBtn.textContent = isBusy ? (checkLabel || 'Checking...') : 'Check Known Host';
                }
                if (clearBtn) {
                    clearBtn.disabled = !!isBusy;
                    clearBtn.textContent = isBusy ? (clearLabel || 'Clearing...') : 'Clear Known Host';
                }
            }

            async function checkEditKnownHostStatus() {
                if (!editingServerName) return;
                const host = document.getElementById('edit-host').value.trim();
                const port = normalizePort(document.getElementById('edit-port').value, 22);
                if (!host) {
                    resetEditKnownHostState();
                    setEditHostKeyStatus('Known host status: host is required.');
                    return;
                }
                const currentCheck = (async () => {
                    setEditKnownHostButtonsState(true, 'Checking...', 'Clear Known Host');
                    setEditHostKeyStatus('Checking known_hosts entry...');
                    try {
                        const scanned = await scanHostKey(host, port);
                        const currentHost = document.getElementById('edit-host').value.trim();
                        const currentPort = normalizePort(document.getElementById('edit-port').value, 22);
                        if (currentHost !== host || currentPort !== port) {
                            return;
                        }
                        setEditKnownHostState(host, port, true, !!scanned?.already_trusted, scanned?.fingerprint_sha256 || '');
                        if (scanned?.already_trusted) {
                            setEditHostKeyStatus(`Known host saved for ${host}:${port} (${scanned.fingerprint_sha256}).`);
                        } else {
                            setEditHostKeyStatus(`Known host not saved for ${host}:${port} (${scanned.fingerprint_sha256}).`);
                        }
                    } catch (err) {
                        const currentHost = document.getElementById('edit-host').value.trim();
                        const currentPort = normalizePort(document.getElementById('edit-port').value, 22);
                        if (currentHost !== host || currentPort !== port) {
                            return;
                        }
                        setEditKnownHostState(host, port, false, false, '');
                        setEditHostKeyStatus(`Known host check failed: ${err.message || 'unknown error'}`);
                    } finally {
                        if (editKnownHostCheckPromise === currentCheck) {
                            setEditKnownHostButtonsState(false);
                        }
                    }
                })();
                editKnownHostCheckPromise = currentCheck;
                try {
                    await currentCheck;
                } finally {
                    if (editKnownHostCheckPromise === currentCheck) {
                        editKnownHostCheckPromise = null;
                        setEditKnownHostButtonsState(false);
                    }
                }
            }

            async function clearEditKnownHost() {
                if (!editingServerName) return;
                const host = document.getElementById('edit-host').value.trim();
                const port = normalizePort(document.getElementById('edit-port').value, 22);
                if (!host) {
                    alert('Host is required.');
                    return;
                }
                if (!confirm(`Remove known_hosts entry for ${host}:${port}?`)) {
                    return;
                }
                setEditKnownHostButtonsState(true, 'Check Known Host', 'Clearing...');
                try {
                    const result = await clearKnownHost(host, port);
                    setEditKnownHostState(host, port, true, false, '');
                    if (Number(result?.removed_entries || 0) > 0) {
                        setEditHostKeyStatus(`Known host entry cleared for ${host}:${port}.`);
                    } else {
                        setEditHostKeyStatus(`Known host entry not found for ${host}:${port}.`);
                    }
                } catch (err) {
                    alert(err.message || 'Failed to clear known host entry.');
                } finally {
                    setEditKnownHostButtonsState(false);
                }
            }

        async function saveServerEdit() {
            if (!editingServerName || editSaveInProgress) return;
            const newName = document.getElementById('edit-name').value.trim();
            const newHost = document.getElementById('edit-host').value.trim();
            const portValue = document.getElementById('edit-port').value;
            const newPort = portValue ? parseInt(portValue, 10) : 0;
            const newUser = document.getElementById('edit-user').value.trim();
            const tagsRaw = document.getElementById('edit-tags').value;
            const tags = tagsRaw.split(',').map(t => t.trim()).filter(Boolean);
            const newPass = document.getElementById('edit-pass').value;
            const trustHostNow = document.getElementById('edit-trust-host-key').checked;
            const current = serverCache[editingServerName] || {};
            const currentPort = normalizePort(current.port, 22);
            const targetPort = normalizePort(newPort || currentPort, 22);
                clearEditValidationState();
                const missing = [];
                if (!newName) missing.push({ id: 'edit-name', label: 'Name' });
                if (!newHost) missing.push({ id: 'edit-host', label: 'Host' });
                if (!newUser) missing.push({ id: 'edit-user', label: 'User' });
                if (missing.length > 0) {
                    for (const field of missing) {
                        setEditFieldInvalidState(field.id, true);
                    }
                    const labels = missing.map((field) => field.label).join(', ');
                    const verb = missing.length === 1 ? 'is' : 'are';
                    setEditValidationError(`${labels} ${verb} required.`);
                    const firstInvalid = document.getElementById(missing[0].id);
                    if (firstInvalid) {
                        firstInvalid.focus();
                    }
                    return;
                }
                editSaveInProgress = true;
                setEditSaveButtonState(true, 'Saving...');
                try {
                    const res = await fetch(`/api/servers/${encodeURIComponent(editingServerName)}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: newName, host: newHost, port: newPort, user: newUser, pass: newPass, tags })
                });
                    if (!res.ok) {
                        alert(await parseErrorResponse(res, 'Failed to save server.'));
                        setEditHostKeyStatus('');
                        return;
                    }
                    if (trustHostNow) {
                        if (editKnownHostCheckPromise) {
                            await editKnownHostCheckPromise;
                        }
                        if (isEditKnownHostTrusted(newHost, targetPort)) {
                            setEditHostKeyStatus('Host key already saved in known_hosts.');
                        } else {
                        try {
                            const trustResult = await trustHostKeyFlow(newHost, targetPort, {
                                onScanning: () => {
                                    setEditHostKeyStatus('Checking known_hosts entry...');
                                },
                                onScanned: () => {
                                    setEditHostKeyStatus('Host key scanned. Waiting confirmation...');
                                },
                                onAlreadyTrusted: () => {
                                    setEditHostKeyStatus('Host key already saved in known_hosts.');
                                },
                                onTrusting: () => {
                                    setEditHostKeyStatus('Saving host key to known_hosts...');
                                }
                            });
                            const scannedFp = trustResult?.scanned?.fingerprint_sha256 || trustResult?.trusted?.fingerprint_sha256 || '';
                            setEditKnownHostState(newHost, targetPort, true, true, scannedFp);
                            if (!trustResult?.alreadyTrusted) {
                                setEditHostKeyStatus('Host key trusted.');
                            }
                        } catch (err) {
                            alert(`Server saved, but host key was not trusted: ${err.message || 'unknown error'}`);
                            setEditHostKeyStatus('');
                        }
                        }
                    }
                closeEditModal();
                fetchManageServers();
            } finally {
                editSaveInProgress = false;
                setEditSaveButtonState(false);
            }
        }

        async function uploadServerKey(name) {
            const input = document.getElementById('edit-key');
            if (!input || !input.files || input.files.length === 0) {
                alert('Select a private key file to upload.');
                return;
            }
            const form = new FormData();
            form.append('key', input.files[0]);
            const res = await fetch(`/api/servers/${encodeURIComponent(name)}/key`, { method: 'POST', body: form });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                alert(data.error || 'Failed to upload key.');
                return;
            }
            input.value = '';
            updateFileLabel(input, 'Click to upload key');
            fetchManageServers();
        }

        async function clearServerKey(name) {
            const res = await fetch(`/api/servers/${encodeURIComponent(name)}/key`, { method: 'DELETE' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                alert(data.error || 'Failed to clear key.');
                return;
            }
            fetchManageServers();
        }

        async function clearServerPassword(name) {
            const res = await fetch(`/api/servers/${encodeURIComponent(name)}/password`, { method: 'DELETE' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                alert(data.error || 'Failed to clear password.');
                return;
            }
            fetchManageServers();
        }

        document.getElementById('edit-cancel').addEventListener('click', closeEditModal);
        document.getElementById('edit-save').addEventListener('click', saveServerEdit);
        document.getElementById('edit-upload-key').addEventListener('click', () => {
            if (editingServerName) {
                uploadServerKey(editingServerName);
            }
        });
        document.getElementById('edit-clear-key').addEventListener('click', () => {
            if (editingServerName) {
                clearServerKey(editingServerName);
            }
        });
            document.getElementById('edit-clear-password').addEventListener('click', () => {
                if (editingServerName) {
                    clearServerPassword(editingServerName);
                }
            });
            document.getElementById('edit-name').addEventListener('input', () => {
                setEditFieldInvalidState('edit-name', false);
                maybeClearEditValidationError();
            });
            document.getElementById('edit-host').addEventListener('input', () => {
                setEditFieldInvalidState('edit-host', false);
                maybeClearEditValidationError();
                if (editingServerName) {
                    editKnownHostCheckPromise = null;
                    resetEditKnownHostState();
                    setEditHostKeyStatus('Host/port changed. Click "Check Known Host" to refresh status.');
                }
            });
            document.getElementById('edit-port').addEventListener('input', () => {
                if (editingServerName) {
                    editKnownHostCheckPromise = null;
                    resetEditKnownHostState();
                    setEditHostKeyStatus('Host/port changed. Click "Check Known Host" to refresh status.');
                }
            });
            document.getElementById('edit-user').addEventListener('input', () => {
                setEditFieldInvalidState('edit-user', false);
                maybeClearEditValidationError();
            });
            document.getElementById('edit-check-known-host').addEventListener('click', () => {
                if (editingServerName) {
                    checkEditKnownHostStatus();
                }
            });
            document.getElementById('edit-clear-known-host').addEventListener('click', () => {
                if (editingServerName) {
                    clearEditKnownHost();
                }
            });
            document.getElementById('hostkey-modal-cancel').addEventListener('click', () => closeHostKeyModal(false));
        document.getElementById('hostkey-modal-trust').addEventListener('click', () => closeHostKeyModal(true));
        document.getElementById('hostkey-modal').addEventListener('click', (e) => {
            if (e.target && e.target.id === 'hostkey-modal') {
                closeHostKeyModal(false);
            }
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                const hostKeyModal = document.getElementById('hostkey-modal');
                if (hostKeyModal && hostKeyModal.classList.contains('active')) {
                    closeHostKeyModal(false);
                }
            }
        });

        async function uploadGlobalKey() {
            const input = document.getElementById('global-key-file');
            if (!input || !input.files || input.files.length === 0) {
                alert('Select a private key file to upload.');
                return;
            }
            const form = new FormData();
            form.append('key', input.files[0]);
            const res = await fetch('/api/keys/global', { method: 'POST', body: form });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                alert(data.error || 'Failed to upload global key.');
                return;
            }
            alert('Global key saved.');
            input.value = '';
            updateFileLabel(input, 'Click to upload key');
            fetchGlobalKeyStatus();
        }

        async function clearGlobalKey() {
            const res = await fetch('/api/keys/global', { method: 'DELETE' });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                alert(data.error || 'Failed to clear global key.');
                return;
            }
            alert('Global key cleared.');
            fetchGlobalKeyStatus();
        }

        async function fetchGlobalKeyStatus() {
            const status = document.getElementById('global-key-status');
            if (!status) return;
            const res = await fetch('/api/keys/global');
            if (!res.ok) {
                status.textContent = `Global key status: ${await parseErrorResponse(res, 'unknown')}`;
                return;
            }
            const data = await res.json();
            status.textContent = data.has_key ? 'Global key: saved' : 'Global key: not set';
        }

        document.getElementById('logout-btn').addEventListener('click', () => window.logout());
        document.getElementById('upload-global-key-btn').addEventListener('click', uploadGlobalKey);
        document.getElementById('clear-global-key-btn').addEventListener('click', clearGlobalKey);
        fetchManageServers();
        fetchGlobalKeyStatus();
        fetchAuditEvents();
        setInterval(fetchAuditEvents, 15000);
