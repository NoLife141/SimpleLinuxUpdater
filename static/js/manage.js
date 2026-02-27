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

        async function parseErrorResponse(res, fallbackMessage) {
            const data = await res.json().catch(() => ({}));
            return data.error || fallbackMessage;
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

        async function trustHostKeyFlow(host, port) {
            const scanned = await scanHostKey(host, port);
            const confirmed = confirm(
                `Verify SSH host key before trusting:\n\n` +
                `Host: ${scanned.host}\n` +
                `Port: ${scanned.port}\n` +
                `Algorithm: ${scanned.algorithm}\n` +
                `Fingerprint: ${scanned.fingerprint_sha256}\n\n` +
                `Add this key to known_hosts?`
            );
            if (!confirmed) {
                throw new Error('Host key trust cancelled.');
            }
            await trustHostKey(scanned.host, scanned.port, scanned.fingerprint_sha256);
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
            } catch (error) {
                alert(error?.message || 'Failed to load servers.');
            } finally {
                requestAnimationFrame(() => restoreWindowScroll(pageScroll));
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
                    const statusClass = `status-${String(evt.status || '').toLowerCase()}`;
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
                updateFileLabel(keyFileInput);
            }
            fetchManageServers();
            e.target.reset();
            document.getElementById('trust-host-key').checked = true;
        });

        function updateFileLabel(input) {
            const label = document.querySelector(`label[for="${input.id}"]`);
            if (!label) return;
            const file = input.files && input.files[0];
            label.textContent = file ? file.name : 'Click to upload key';
        }

        document.addEventListener('change', (e) => {
            if (e.target && e.target.classList.contains('file-input')) {
                updateFileLabel(e.target);
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
            editingServerName = name;
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
                updateFileLabel(keyInput);
            }
            document.getElementById('edit-modal').classList.add('active');
        }

        function closeEditModal() {
            document.getElementById('edit-modal').classList.remove('active');
            editingServerName = null;
        }

        async function saveServerEdit() {
            if (!editingServerName) return;
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
            if (newName && newHost && newUser) {
                const res = await fetch(`/api/servers/${encodeURIComponent(editingServerName)}`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: newName, host: newHost, port: newPort, user: newUser, pass: newPass, tags })
                });
                if (!res.ok) {
                    alert(await parseErrorResponse(res, 'Failed to save server.'));
                    return;
                }
                if (trustHostNow) {
                    try {
                        await trustHostKeyFlow(newHost, targetPort);
                    } catch (err) {
                        alert(`Server saved, but host key was not trusted: ${err.message || 'unknown error'}`);
                    }
                }
                closeEditModal();
                fetchManageServers();
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
            updateFileLabel(input);
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
            updateFileLabel(input);
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
                status.textContent = 'Global key status: unknown';
                return;
            }
            const data = await res.json();
            status.textContent = data.has_key ? 'Global key: saved' : 'Global key: not set';
        }

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
            const res = await fetch('/api/metrics/token');
            if (!res.ok) {
                status.textContent = 'Metrics token status: unknown';
                return;
            }
            const data = await res.json();
            status.textContent = data.enabled ? 'Metrics API token: enabled' : 'Metrics API token: disabled';
        }

        async function rotateMetricsToken(askConfirm) {
            if (askConfirm && !window.confirm('Rotate metrics token? Existing scrapers using the old token will fail until updated.')) {
                return;
            }
            const res = await fetch('/api/metrics/token', { method: 'POST' });
            if (!res.ok) {
                alert(await parseErrorResponse(res, 'Failed to rotate metrics token.'));
                return;
            }
            const data = await res.json();
            const token = (data && typeof data.token === 'string') ? data.token : '';
            if (!token) {
                alert('Token rotation succeeded but no token was returned.');
                return;
            }
            showMetricsTokenOnce(token);
            fetchMetricsTokenStatus(false);
        }

        async function disableMetricsToken() {
            if (!window.confirm('Disable metrics token and hide /metrics now?')) {
                return;
            }
            const res = await fetch('/api/metrics/token', { method: 'DELETE' });
            if (!res.ok) {
                alert(await parseErrorResponse(res, 'Failed to disable metrics token.'));
                return;
            }
            showMetricsTokenOnce('');
            fetchMetricsTokenStatus();
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
            } catch (err) {
                alert('Failed to copy token. Copy it manually from the box.');
            }
        }

        document.getElementById('logout-btn').addEventListener('click', () => window.logout());
        document.getElementById('upload-global-key-btn').addEventListener('click', uploadGlobalKey);
        document.getElementById('clear-global-key-btn').addEventListener('click', clearGlobalKey);
        document.getElementById('metrics-token-generate').addEventListener('click', () => rotateMetricsToken(false));
        document.getElementById('metrics-token-rotate').addEventListener('click', () => rotateMetricsToken(true));
        document.getElementById('metrics-token-disable').addEventListener('click', disableMetricsToken);
        document.getElementById('metrics-token-copy').addEventListener('click', copyMetricsToken);
        fetchManageServers();
        fetchGlobalKeyStatus();
        fetchMetricsTokenStatus();
        fetchAuditEvents();
        setInterval(fetchAuditEvents, 15000);
