const LOG_BOTTOM_THRESHOLD = 20;
        let sortKey = "name";
        let sortDir = "asc";
        let allServers = [];
        let page = 1;
        let selectedServers = new Set();
        let hoveredName = null;
        let fetchInFlight = false;
        let fetchQueued = false;
        let queuedForceRender = false;
        let drawerOpen = false;
        let drawerServerName = "";
        let drawerTab = "logs";
        let drawerLogFollow = true;
        let drawerLogScrollTop = 0;
        let passwordResolve = null;
        let passwordReject = null;
        let suppressSortClickUntil = 0;
        const columnResizeStorageKey = "simplelinuxupdater.statusTableColWidths.v5";
        const defaultColumnWidths = Object.freeze({
            name: 220,
            status: 120,
            actions: 500
        });
        const minColumnWidths = Object.freeze({
            name: 140,
            status: 96,
            actions: 420
        });
        const maxColumnWidths = Object.freeze({
            name: 520,
            status: 180,
            actions: 760
        });
        const allowedStatuses = new Set([
            "idle", "updating", "pending_approval", "approved", "cancelled",
            "upgrading", "autoremove", "sudoers", "done", "error"
        ]);

        function safeStatusClass(value) {
            const normalized = String(value ?? "").toLowerCase();
            return allowedStatuses.has(normalized) ? normalized : "error";
        }

        function isNearBottom(el) {
            return (el.scrollHeight - el.scrollTop - el.clientHeight) <= LOG_BOTTOM_THRESHOLD;
        }

        function classifyLogLine(line) {
            const lower = line.toLowerCase();
            const bracketState = String(line || "").match(/\[(PASS|WARN|FAIL)\]/i);
            if (bracketState) {
                const state = bracketState[1].toUpperCase();
                if (state === "FAIL") return "error";
                if (state === "WARN") return "warning";
                if (state === "PASS") return "success";
            }
            if (/(error|failed|fatal|denied|refused|panic|timeout|timed out)/.test(lower)) return "error";
            if (/(warn|warning|retry|deprecated)/.test(lower)) return "warning";
            if (/(done|completed|success|approved|enabled|disabled|cancelled)/.test(lower)) return "success";
            if (/(starting|running|connecting|upgradable|upgrade|apt|ssh|info)/.test(lower)) return "info";
            return "";
        }

        function formatLogsHtml(logText) {
            const text = String(logText || "");
            if (!text) {
                return `<div class="log-line log-line-info">No logs yet.</div>`;
            }
            const lines = text.split(/\r?\n/);
            return lines.map(line => {
                const klass = classifyLogLine(line);
                const classAttr = klass ? ` log-line-${klass}` : "";
                const printable = line.length ? line : " ";
                return `<div class="log-line${classAttr}">${escapeHtml(printable)}</div>`;
            }).join("");
        }

        function pendingStateBadge(state) {
            const normalized = String(state || "").toLowerCase();
            if (normalized === "pending") return `<span class="pending-badge">Scanning CVEs...</span>`;
            if (normalized === "unavailable") return `<span class="pending-badge">CVE lookup unavailable</span>`;
            if (normalized === "skipped") return `<span class="pending-badge">CVE lookup skipped</span>`;
            if (normalized === "ready") return "";
            return `<span class="pending-badge">Unknown state</span>`;
        }

        function hasPendingUpdates(server) {
            if (!server || server.status !== "pending_approval") return false;
            return Array.isArray(server.pending_updates) && server.pending_updates.length > 0;
        }

        function getPendingApprovalCounts(server) {
            const pendingUpdates = Array.isArray(server?.pending_updates) ? server.pending_updates : [];
            const totalFromPending = pendingUpdates.length;
            const securityFromPending = pendingUpdates.filter(update => !!update?.security).length;
            const upgradableFallback = Array.isArray(server?.upgradable) ? server.upgradable.length : 0;
            const total = totalFromPending > 0 ? totalFromPending : upgradableFallback;
            return {
                total,
                security: totalFromPending > 0 ? securityFromPending : null
            };
        }

        function renderPendingUpdatesHtml(server, includeHeading = true) {
            const updates = Array.isArray(server?.pending_updates) ? server.pending_updates : [];
            if (server?.status !== "pending_approval" || updates.length === 0) {
                return `<p class="drawer-empty">No pending update details for this server.</p>`;
            }

            const hasPending = updates.some(update => String(update.cve_state || "").toLowerCase() === "pending");
            const securityCount = updates.filter(update => !!update.security).length;
            const stateCounts = updates.reduce((acc, update) => {
                const state = String(update.cve_state || "").toLowerCase();
                acc[state] = (acc[state] || 0) + 1;
                return acc;
            }, {});

            const rows = updates.map(update => {
                const pkg = escapeHtml(update.package || "unknown");
                const currentVersion = escapeHtml(update.current_version || "?");
                const candidateVersion = escapeHtml(update.candidate_version || "?");
                const source = escapeHtml(update.source || "");
                const state = String(update.cve_state || "").toLowerCase();
                const cves = Array.isArray(update.cves) ? update.cves : [];

                const badges = [];
                if (update.security) badges.push(`<span class="pending-badge pending-badge-security">Security</span>`);
                if (state === "ready") {
                    if (cves.length > 0) {
                        badges.push(`<span class="pending-badge pending-badge-cve">${cves.length} CVE${cves.length > 1 ? "s" : ""}</span>`);
                        cves.slice(0, 3).forEach((cve) => {
                            badges.push(`<span class="pending-badge">${escapeHtml(cve)}</span>`);
                        });
                    } else {
                        badges.push(`<span class="pending-badge">No CVE found</span>`);
                    }
                } else {
                    badges.push(pendingStateBadge(state));
                }

                return `
                    <tr>
                        <td>
                            <div>${pkg}</div>
                            ${source ? `<div class="subtle">${source}</div>` : ""}
                        </td>
                        <td>${currentVersion} &rarr; ${candidateVersion}</td>
                        <td><div class="pending-badges">${badges.join("")}</div></td>
                    </tr>
                `;
            }).join("");

            return `
                <div class="pending-updates">
                    ${includeHeading ? "<h4>Pending updates (security first)</h4>" : ""}
                    <div class="pending-summary">
                        <span class="pending-badge">${updates.length} package${updates.length > 1 ? "s" : ""}</span>
                        <span class="pending-badge pending-badge-security">${securityCount} security</span>
                        <span class="pending-badge">${stateCounts.ready || 0} ready</span>
                        <span class="pending-badge">${stateCounts.pending || 0} scanning</span>
                        <span class="pending-badge">${stateCounts.unavailable || 0} unavailable</span>
                        <span class="pending-badge">${stateCounts.skipped || 0} skipped</span>
                    </div>
                    ${hasPending ? `<p class="pending-note">CVE scan in progress; list will update automatically.</p>` : ""}
                    <div class="table-wrap">
                        <table class="pending-table">
                            <thead>
                                <tr>
                                    <th>Package</th>
                                    <th>Version</th>
                                    <th>Risk</th>
                                </tr>
                            </thead>
                            <tbody>${rows}</tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        function saveWindowScroll() {
            return { x: window.scrollX, y: window.scrollY };
        }

        function restoreWindowScroll(pos) {
            if (!pos) return;
            window.scrollTo(pos.x, pos.y);
        }

        function getTableColByKey(key) {
            return document.querySelector(`#servers-table col[data-col-key="${key}"]`);
        }

        function loadColumnWidths() {
            try {
                const raw = localStorage.getItem(columnResizeStorageKey);
                if (!raw) return {};
                const parsed = JSON.parse(raw);
                return parsed && typeof parsed === "object" ? parsed : {};
            } catch (_) {
                return {};
            }
        }

        function saveColumnWidths(widths) {
            try {
                localStorage.setItem(columnResizeStorageKey, JSON.stringify(widths));
            } catch (_) {
                // Ignore storage failures (private mode, quota, etc.)
            }
        }

        function applyColumnWidths(widths) {
            Object.keys(defaultColumnWidths).forEach((key) => {
                const col = getTableColByKey(key);
                if (!col) return;
                const configured = Number(widths[key]);
                const minWidth = minColumnWidths[key] || 100;
                const maxWidth = maxColumnWidths[key] || 9999;
                const fallback = defaultColumnWidths[key];
                const boundedFallback = Math.min(maxWidth, Math.max(minWidth, fallback));
                const nextWidth = Number.isFinite(configured)
                    ? Math.min(maxWidth, Math.max(minWidth, configured))
                    : boundedFallback;
                col.style.width = `${Math.round(nextWidth)}px`;
            });
        }

        function initColumnResizing() {
            const savedWidths = loadColumnWidths();
            applyColumnWidths(savedWidths);

            document.querySelectorAll('#servers-table .col-resize-handle').forEach((handle) => {
                if (handle.dataset.bound === "1") return;
                handle.dataset.bound = "1";

                handle.addEventListener('pointerdown', (event) => {
                    event.preventDefault();
                    event.stopPropagation();

                    const colKey = handle.dataset.colKey || "";
                    const col = getTableColByKey(colKey);
                    const th = handle.closest('th');
                    if (!col || !th) return;

                    const minWidth = minColumnWidths[colKey] || 100;
                    const maxWidth = maxColumnWidths[colKey] || 9999;
                    const startX = event.clientX;
                    const startWidth = Math.max(minWidth, Math.round(col.getBoundingClientRect().width));

                    const onPointerMove = (moveEvent) => {
                        const delta = moveEvent.clientX - startX;
                        const nextWidth = Math.min(maxWidth, Math.max(minWidth, startWidth + delta));
                        col.style.width = `${Math.round(nextWidth)}px`;
                    };

                    const finishResize = (endEvent, canceled) => {
                        window.removeEventListener('pointermove', onPointerMove);
                        window.removeEventListener('pointerup', onPointerUp);
                        window.removeEventListener('pointercancel', onPointerCancel);
                        document.body.classList.remove('col-resizing');
                        th.classList.remove('resizing');

                        if (canceled) {
                            col.style.width = `${Math.round(startWidth)}px`;
                        } else {
                            const finalWidth = Math.min(maxWidth, Math.max(minWidth, Math.round(col.getBoundingClientRect().width)));
                            const nextWidths = loadColumnWidths();
                            nextWidths[colKey] = finalWidth;
                            saveColumnWidths(nextWidths);
                            suppressSortClickUntil = Date.now() + 250;
                        }

                        if (handle.releasePointerCapture && endEvent.pointerId !== undefined) {
                            try {
                                handle.releasePointerCapture(endEvent.pointerId);
                            } catch (_) {
                                // Ignore pointer release issues.
                            }
                        }
                    };

                    const onPointerUp = (endEvent) => finishResize(endEvent, false);
                    const onPointerCancel = (endEvent) => finishResize(endEvent, true);

                    document.body.classList.add('col-resizing');
                    th.classList.add('resizing');
                    if (handle.setPointerCapture && event.pointerId !== undefined) {
                        try {
                            handle.setPointerCapture(event.pointerId);
                        } catch (_) {
                            // Ignore pointer capture issues.
                        }
                    }

                    window.addEventListener('pointermove', onPointerMove);
                    window.addEventListener('pointerup', onPointerUp);
                    window.addEventListener('pointercancel', onPointerCancel);
                });
            });
        }

        async function fetchServers(forceRender = false) {
            if (fetchInFlight) {
                fetchQueued = true;
                queuedForceRender = queuedForceRender || forceRender;
                return;
            }
            fetchInFlight = true;
            const pageScroll = saveWindowScroll();
            try {
                let parsedServers;
                try {
                    const response = await fetch('/api/servers');
                    if (!response.ok) {
                        throw new Error(`Failed to fetch servers: HTTP ${response.status}`);
                    }
                    parsedServers = await response.json();
                    if (!Array.isArray(parsedServers)) {
                        throw new Error('Invalid servers payload: expected an array');
                    }
                } catch (err) {
                    console.error('Unable to refresh servers list:', err);
                    return;
                }
                allServers = parsedServers;
                renderTable();
                renderDrawer();
                requestAnimationFrame(() => restoreWindowScroll(pageScroll));
            } finally {
                fetchInFlight = false;
                if (fetchQueued) {
                    fetchQueued = false;
                    const nextRender = queuedForceRender;
                    queuedForceRender = false;
                    fetchServers(nextRender);
                }
            }
        }

        function sortServers(servers) {
            const dir = sortDir === "asc" ? 1 : -1;
            return servers.slice().sort((a, b) => {
                const aVal = (a[sortKey] || "").toString().toLowerCase();
                const bVal = (b[sortKey] || "").toString().toLowerCase();
                if (aVal < bVal) return -1 * dir;
                if (aVal > bVal) return 1 * dir;
                return 0;
            });
        }

        function applyFilters(servers) {
            const search = document.getElementById('search').value.trim().toLowerCase();
            const statusFilter = document.getElementById('status-filter').value;
            const authFilter = document.getElementById('auth-filter').value;
            return servers.filter(server => {
                if (statusFilter && server.status !== statusFilter) return false;
                if (authFilter === "password" && !server.has_password) return false;
                if (authFilter === "key" && !server.has_key) return false;
                if (!search) return true;
                const haystack = [
                    server.name,
                    server.host,
                    server.port ? server.port.toString() : "",
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
            if (groupBy === "status") {
                servers.forEach(server => {
                    const key = server.status || "unknown";
                    if (!groups.has(key)) groups.set(key, []);
                    groups.get(key).push(server);
                });
            } else if (groupBy === "tag") {
                servers.forEach(server => {
                    const tags = server.tags && server.tags.length ? server.tags : ["untagged"];
                    tags.forEach(tag => {
                        if (!groups.has(tag)) groups.set(tag, []);
                        groups.get(tag).push(server);
                    });
                });
            }
            return Array.from(groups.entries()).map(([key, items]) => ({ key, items }));
        }

        function openDrawer(name, tab = "logs") {
            const nextTab = tab === "pending" ? "pending" : "logs";
            if (drawerServerName !== name) {
                drawerLogFollow = true;
                drawerLogScrollTop = 0;
            }
            drawerOpen = true;
            drawerServerName = name;
            drawerTab = nextTab;
            renderDrawer();
        }

        function closeDrawer() {
            drawerOpen = false;
            const drawer = document.getElementById('status-drawer');
            const backdrop = document.getElementById('status-drawer-backdrop');
            drawer.classList.remove('open');
            backdrop.classList.remove('open');
            drawer.setAttribute('aria-hidden', 'true');
        }

        function setDrawerTab(tab) {
            if (tab !== "logs" && tab !== "pending") return;
            drawerTab = tab;
            renderDrawer();
        }

        function renderDrawer() {
            const drawer = document.getElementById('status-drawer');
            const backdrop = document.getElementById('status-drawer-backdrop');
            const title = document.getElementById('status-drawer-title');
            const statusContainer = document.getElementById('status-drawer-status');
            const logsTabBtn = document.getElementById('drawer-tab-logs');
            const pendingTabBtn = document.getElementById('drawer-tab-pending');
            const logsPanel = document.getElementById('drawer-panel-logs');
            const pendingPanel = document.getElementById('drawer-panel-pending');
            const logsHint = document.getElementById('drawer-logs-hint');
            const logsEl = document.getElementById('drawer-logs');
            const approvalActions = document.getElementById('status-drawer-approval-actions');
            const drawerApproveAllBtn = document.getElementById('drawer-approve-all');
            const drawerApproveSecurityBtn = document.getElementById('drawer-approve-security');

            if (!drawerOpen) {
                drawer.classList.remove('open');
                backdrop.classList.remove('open');
                drawer.setAttribute('aria-hidden', 'true');
                return;
            }

            const server = getServerByName(drawerServerName);
            if (!server) {
                closeDrawer();
                return;
            }

            const safeStatus = safeStatusClass(server.status);
            const safeStatusText = escapeHtml(server.status || "unknown");
            const isPendingApproval = server.status === "pending_approval";
            const hasPending = hasPendingUpdates(server);
            const approvalCounts = getPendingApprovalCounts(server);
            const securityApprovalLabel = approvalCounts.security === null
                ? "Approve security only (unknown)"
                : `Approve security only (${approvalCounts.security})`;
            if (drawerTab === "pending" && !hasPending) {
                drawerTab = "logs";
            }

            title.textContent = server.name || "Server details";
            statusContainer.innerHTML = `<span class="status-pill status-${safeStatus}">${safeStatusText}</span>`;
            approvalActions.classList.toggle('hidden', !isPendingApproval);
            drawerApproveAllBtn.textContent = `Approve all (${approvalCounts.total})`;
            drawerApproveSecurityBtn.textContent = securityApprovalLabel;

            pendingTabBtn.disabled = !hasPending;
            pendingTabBtn.classList.toggle('active', drawerTab === "pending");
            logsTabBtn.classList.toggle('active', drawerTab === "logs");

            logsPanel.classList.toggle('active', drawerTab === "logs");
            pendingPanel.classList.toggle('active', drawerTab === "pending");

            if (drawerTab === "logs") {
                logsEl.innerHTML = formatLogsHtml(server.logs || "");
                if (drawerLogFollow) {
                    logsEl.scrollTop = logsEl.scrollHeight;
                } else {
                    logsEl.scrollTop = drawerLogScrollTop;
                }
                logsHint.textContent = drawerLogFollow ? "Live auto-scroll" : "Auto-scroll paused";
            }

            if (drawerTab === "pending") {
                pendingPanel.innerHTML = renderPendingUpdatesHtml(server, true);
            } else {
                pendingPanel.innerHTML = "";
            }

            drawer.classList.add('open');
            backdrop.classList.add('open');
            drawer.setAttribute('aria-hidden', 'false');
        }

        function renderTable() {
            const tbody = document.querySelector('#servers-table tbody');
            tbody.innerHTML = '';
            let servers = applyFilters(allServers);
            servers = sortServers(servers);
            const paged = paginate(servers);
            const groups = groupServers(paged);
            groups.forEach(group => {
                if (group.key) {
                    const groupRow = document.createElement('tr');
                    groupRow.className = 'group-row';
                    groupRow.innerHTML = `<td colspan="4">${escapeHtml(group.key)}</td>`;
                    tbody.appendChild(groupRow);
                }
                group.items.forEach(server => {
                    const row = document.createElement('tr');
                    row.dataset.name = server.name;
                    if (hoveredName === server.name) {
                        row.classList.add('row-hover');
                    }
                    const isBusy = server.status === 'updating' || server.status === 'upgrading' || server.status === 'autoremove' || server.status === 'sudoers';
                    const safeNameHtml = escapeHtml(server.name);
                    const safeStatusText = escapeHtml(server.status || "unknown");
                    const safeStatus = safeStatusClass(server.status);
                    const safeDataName = escapeHtml(server.name);
                    const approvalCounts = getPendingApprovalCounts(server);
                    const securityApprovalLabel = approvalCounts.security === null
                        ? "Approve security only (unknown)"
                        : `Approve security only (${approvalCounts.security})`;
                    const actionButtons = server.status === 'pending_approval'
                        ? `
                            <div class="actions-grid">
                                <button type="button" data-action="approve-all" data-name="${safeDataName}" title="Approve all updates">Approve all (${approvalCounts.total})</button>
                                <button type="button" class="btn-security" data-action="approve-security" data-name="${safeDataName}" title="Approve only security updates">${securityApprovalLabel}</button>
                                <button type="button" class="btn-ghost" data-action="open-drawer" data-name="${safeDataName}" data-tab="logs">Logs</button>
                                <button type="button" class="btn-danger" data-action="cancel-upgrade" data-name="${safeDataName}">Cancel</button>
                                <button type="button" class="btn-ghost" data-action="open-drawer" data-name="${safeDataName}" data-tab="pending">Pending updates</button>
                            </div>
                          `
                        : `
                            <div class="actions-grid">
                                <button type="button" data-action="update-server" data-name="${safeDataName}" ${isBusy ? 'disabled' : ''}>Update</button>
                                <button type="button" data-action="run-autoremove" data-name="${safeDataName}" ${isBusy ? 'disabled' : ''} title="Run apt autoremove">Autoremove</button>
                                <button type="button" class="btn-ghost" data-action="open-drawer" data-name="${safeDataName}" data-tab="logs">Logs</button>
                                <button type="button" data-action="enable-apt" data-name="${safeDataName}" ${isBusy ? 'disabled' : ''} title="Enable passwordless apt">Enable apt</button>
                                <button type="button" data-action="disable-apt" data-name="${safeDataName}" ${isBusy ? 'disabled' : ''} title="Disable passwordless apt">Disable apt</button>
                            </div>
                          `;
                    row.innerHTML = `
                        <td class="select-col"><input type="checkbox" class="row-select" data-name="${safeDataName}" ${selectedServers.has(server.name) ? "checked" : ""}></td>
                        <td class="name-cell" title="${safeNameHtml}">${safeNameHtml}</td>
                        <td class="status-col"><span class="status-pill status-${safeStatus}">${safeStatusText}</span></td>
                        <td class="actions-col">${actionButtons}</td>
                    `;
                    tbody.appendChild(row);
                });
            });
            applyHoverClass();
            tbody.querySelectorAll('.row-select').forEach(cb => {
                cb.addEventListener('change', (e) => {
                    const name = e.target.dataset.name;
                    if (e.target.checked) {
                        selectedServers.add(name);
                    } else {
                        selectedServers.delete(name);
                    }
                });
            });
            document.getElementById('select-all').checked = paged.length > 0 && paged.every(s => selectedServers.has(s.name));
        }

        function getServerByName(name) {
            return allServers.find(server => server.name === name);
        }

        async function copyLogs(name = drawerServerName) {
            const server = getServerByName(name);
            const logs = String(server?.logs || "");
            try {
                await navigator.clipboard.writeText(logs);
            } catch (_) {
                const tmp = document.createElement('textarea');
                tmp.value = logs;
                document.body.appendChild(tmp);
                tmp.select();
                document.execCommand('copy');
                tmp.remove();
            }
        }

        function downloadLogs(name = drawerServerName) {
            const server = getServerByName(name);
            const logs = String(server?.logs || "");
            const blob = new Blob([logs], { type: 'text/plain;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            const safeName = String(name || "server").replace(/[^a-zA-Z0-9._-]/g, '_');
            link.href = url;
            link.download = `${safeName}-logs.txt`;
            document.body.appendChild(link);
            link.click();
            link.remove();
            URL.revokeObjectURL(url);
        }

        function applyHoverClass() {
            const tbody = document.querySelector('#servers-table tbody');
            tbody.querySelectorAll('tr').forEach(tr => tr.classList.remove('row-hover'));
            if (!hoveredName) return;
            const row = tbody.querySelector(`tr[data-name="${CSS.escape(hoveredName)}"]`);
            if (row) {
                row.classList.add('row-hover');
            }
        }

        const tbodyHover = document.querySelector('#servers-table tbody');
        tbodyHover.addEventListener('click', (e) => {
            const button = e.target.closest('button[data-action]');
            if (!button) return;
            const action = button.dataset.action || "";
            const name = button.dataset.name || "";
            if (!name) return;
            if (action === "open-drawer") {
                openDrawer(name, button.dataset.tab || "logs");
                return;
            }
            if (action === "approve-all") {
                approveAllUpdates(name);
                return;
            }
            if (action === "approve-security") {
                approveSecurityUpdates(name);
                return;
            }
            if (action === "cancel-upgrade") {
                cancelUpgrade(name);
                return;
            }
            if (action === "update-server") {
                updateServer(name);
                return;
            }
            if (action === "run-autoremove") {
                runAutoremove(name);
                return;
            }
            if (action === "enable-apt") {
                enablePasswordlessApt(name);
                return;
            }
            if (action === "disable-apt") {
                disablePasswordlessApt(name);
            }
        });
        tbodyHover.addEventListener('mouseover', (e) => {
            const row = e.target.closest('tr[data-name]');
            if (!row) return;
            hoveredName = row.dataset.name || null;
            applyHoverClass();
        });
        tbodyHover.addEventListener('mouseleave', () => {
            hoveredName = null;
            applyHoverClass();
        });

        document.querySelectorAll('#servers-table th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                if (Date.now() < suppressSortClickUntil) {
                    return;
                }
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
        document.getElementById('status-filter').addEventListener('change', () => { page = 1; renderTable(); });
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

        document.getElementById('select-all').addEventListener('change', (e) => {
            const checked = e.target.checked;
            const filtered = sortServers(applyFilters(allServers));
            const paged = paginate(filtered);
            paged.forEach(server => {
                if (checked) {
                    selectedServers.add(server.name);
                } else {
                    selectedServers.delete(server.name);
                }
            });
            renderTable();
        });

        async function runBulkAction(actionPath, actionLabel) {
            const names = Array.from(selectedServers);
            if (names.length === 0) {
                await fetchServers();
                return;
            }

            const jobs = names.map(async (name) => {
                const response = await fetch(`/api/${actionPath}/${encodeURIComponent(name)}`, { method: 'POST' });
                if (!response.ok) {
                    const payload = await response.json().catch(() => ({}));
                    const detail = typeof payload.error === 'string' && payload.error.trim()
                        ? payload.error.trim()
                        : `${response.status} ${response.statusText}`.trim();
                    throw new Error(detail || 'Request failed');
                }
            });

            const results = await Promise.allSettled(jobs);
            const failures = [];
            results.forEach((result, index) => {
                if (result.status === 'rejected') {
                    failures.push(`${names[index]}: ${result.reason?.message || 'Request failed'}`);
                }
            });

            if (failures.length > 0) {
                console.error(`Bulk ${actionLabel} failures:`, failures);
                alert(`Bulk ${actionLabel} completed with ${failures.length} failure(s): ${failures.join(', ')}`);
            }

            await fetchServers();
        }

        document.getElementById('bulk-update').addEventListener('click', async () => {
            await runBulkAction('update', 'update');
        });
        document.getElementById('bulk-approve').addEventListener('click', async () => {
            await runBulkAction('approve', 'approve');
        });
        document.getElementById('bulk-cancel').addEventListener('click', async () => {
            await runBulkAction('cancel', 'cancel');
        });
        document.getElementById('bulk-autoremove').addEventListener('click', async () => {
            await runBulkAction('autoremove', 'apt autoremove');
        });

        async function updateServer(name) {
            await fetch(`/api/update/${encodeURIComponent(name)}`, { method: 'POST' });
            fetchServers();
        }

        async function runAutoremove(name) {
            await fetch(`/api/autoremove/${encodeURIComponent(name)}`, { method: 'POST' });
            fetchServers();
        }

        async function enablePasswordlessApt(name) {
            const password = await promptPassword(`Enter sudo password for ${name}`);
            if (!password) return;
            await fetch(`/api/sudoers/${encodeURIComponent(name)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            fetchServers();
        }

        async function disablePasswordlessApt(name) {
            const password = await promptPassword(`Enter sudo password to disable for ${name}`);
            if (!password) return;
            await fetch(`/api/sudoers/disable/${encodeURIComponent(name)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            fetchServers();
        }

        function promptPassword(message) {
            const backdrop = document.getElementById('password-modal');
            const input = document.getElementById('password-modal-input');
            const msg = document.getElementById('password-modal-message');
            msg.textContent = message;
            input.value = '';
            backdrop.classList.add('active');
            input.focus();
            return new Promise((resolve, reject) => {
                passwordResolve = resolve;
                passwordReject = reject;
            });
        }

        function closePasswordModal() {
            const backdrop = document.getElementById('password-modal');
            backdrop.classList.remove('active');
        }

        document.getElementById('password-modal-cancel').addEventListener('click', () => {
            if (passwordResolve) {
                passwordResolve('');
            }
            closePasswordModal();
        });

        document.getElementById('password-modal-submit').addEventListener('click', () => {
            const input = document.getElementById('password-modal-input');
            if (passwordResolve) {
                passwordResolve(input.value);
            }
            closePasswordModal();
        });

        document.getElementById('password-modal-input').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                document.getElementById('password-modal-submit').click();
            }
            if (e.key === 'Escape') {
                e.preventDefault();
                document.getElementById('password-modal-cancel').click();
            }
        });

        document.getElementById('status-drawer-close').addEventListener('click', closeDrawer);
        document.getElementById('status-drawer-backdrop').addEventListener('click', closeDrawer);
        document.getElementById('drawer-tab-logs').addEventListener('click', () => setDrawerTab('logs'));
        document.getElementById('drawer-tab-pending').addEventListener('click', () => setDrawerTab('pending'));
        document.getElementById('drawer-copy-logs').addEventListener('click', () => copyLogs());
        document.getElementById('drawer-download-logs').addEventListener('click', () => downloadLogs());
        document.getElementById('drawer-approve-all').addEventListener('click', () => {
            if (!drawerServerName) return;
            approveAllUpdates(drawerServerName);
        });
        document.getElementById('drawer-approve-security').addEventListener('click', () => {
            if (!drawerServerName) return;
            approveSecurityUpdates(drawerServerName);
        });

        const drawerLogsElement = document.getElementById('drawer-logs');
        drawerLogsElement.addEventListener('scroll', () => {
            drawerLogScrollTop = drawerLogsElement.scrollTop;
            drawerLogFollow = isNearBottom(drawerLogsElement);
            document.getElementById('drawer-logs-hint').textContent = drawerLogFollow ? "Live auto-scroll" : "Auto-scroll paused";
        });

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && drawerOpen) {
                e.preventDefault();
                closeDrawer();
            }
        });

        async function approveAllUpdates(name) {
            await fetch(`/api/approve/${encodeURIComponent(name)}`, { method: 'POST' });
            fetchServers();
        }

        async function approveSecurityUpdates(name) {
            await fetch(`/api/approve-security/${encodeURIComponent(name)}`, { method: 'POST' });
            fetchServers();
        }

        async function cancelUpgrade(name) {
            await fetch(`/api/cancel/${encodeURIComponent(name)}`, { method: 'POST' });
            fetchServers();
        }

        document.getElementById('logout-btn').addEventListener('click', () => window.logout());
        initColumnResizing();
        setInterval(fetchServers, 2000);
        fetchServers();
