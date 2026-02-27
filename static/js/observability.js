const windowSelect = document.getElementById('window-select');
        const refreshBtn = document.getElementById('refresh-btn');
        const errorBanner = document.getElementById('error-banner');
        const rangeLabel = document.getElementById('range-label');
        let refreshIntervalId = null;

        function showError(message) {
            errorBanner.style.display = 'block';
            errorBanner.textContent = message;
        }

        function clearError() {
            errorBanner.style.display = 'none';
            errorBanner.textContent = '';
        }

        function formatDuration(avgMs) {
            if (!Number.isFinite(avgMs) || avgMs <= 0) return '0 ms';
            if (avgMs >= 1000) {
                return `${(avgMs / 1000).toFixed(2)} s`;
            }
            return `${avgMs.toFixed(0)} ms`;
        }

        function appendCell(tr, text, className = '') {
            const td = document.createElement('td');
            td.textContent = text;
            if (className) {
                td.className = className;
            }
            tr.appendChild(td);
        }

        function renderTableRows(body, rows, emptyText, rowMapper) {
            body.innerHTML = '';
            if (!Array.isArray(rows) || rows.length === 0) {
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                td.colSpan = 2;
                td.className = 'subtle';
                td.textContent = emptyText;
                tr.appendChild(td);
                body.appendChild(tr);
                return;
            }
            rows.forEach(row => {
                const tr = document.createElement('tr');
                rowMapper(tr, row);
                body.appendChild(tr);
            });
        }

        function describeFailureCause(cause) {
            const raw = String(cause || 'unknown').trim();
            if (!raw || raw === 'unknown') return 'Unknown failure cause';
            if (raw === 'retry_exhausted') return 'Retries exhausted before recovery';
            if (raw === 'error_class:permanent') return 'Permanent error (not retryable)';
            if (raw === 'error_class:transient') return 'Transient error (temporary issue)';
            if (raw.startsWith('error_class:')) {
                return `Error class: ${raw.slice('error_class:'.length)}`;
            }
            if (raw.startsWith('precheck:')) {
                return `Pre-check failed: ${raw.slice('precheck:'.length)}`;
            }
            if (raw.startsWith('postcheck:')) {
                return `Post-check failed: ${raw.slice('postcheck:'.length)}`;
            }
            return raw;
        }

        async function fetchObservabilitySummary() {
            const selectedWindow = windowSelect.value || '7d';
            try {
                const res = await fetch(`/api/observability/summary?window=${encodeURIComponent(selectedWindow)}`);
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                const data = await res.json();
                clearError();
                renderSummary(data);
            } catch (err) {
                showError(`Unable to refresh observability data: ${err.message}`);
            }
        }

        function renderSummary(summary) {
            const totals = summary?.totals || {};
            const duration = summary?.duration || {};
            const successRate = Number(totals.success_rate_pct || 0);
            const totalRuns = Number(totals.updates_total || 0);
            const avgMs = Number(duration.avg_ms || 0);
            const withDuration = Number(duration.samples_with_duration || 0);
            const withoutDuration = Number(duration.samples_without_duration || 0);

            document.getElementById('kpi-success-rate').textContent = `${successRate.toFixed(2)}%`;
            document.getElementById('kpi-total').textContent = String(totalRuns);
            document.getElementById('kpi-duration').textContent = formatDuration(avgMs);
            document.getElementById('kpi-duration-samples').textContent =
                `Duration samples: ${withDuration} with data, ${withoutDuration} without data`;
            rangeLabel.textContent = `Range: ${summary?.from || '-'} to ${summary?.to || '-'}`;

            renderTableRows(
                document.getElementById('failure-causes-body'),
                summary?.failure_causes,
                'No failure data in selected window.',
                (tr, row) => {
                    const causeCell = document.createElement('td');
                    const rawCause = String(row?.cause || 'unknown');
                    causeCell.textContent = describeFailureCause(rawCause);
                    causeCell.title = `Raw cause: ${rawCause}`;
                    tr.appendChild(causeCell);
                    appendCell(tr, String(row?.count || 0), 'bad');
                }
            );
            renderTableRows(
                document.getElementById('status-breakdown-body'),
                summary?.status_breakdown,
                'No status data in selected window.',
                (tr, row) => {
                    const statusRaw = row?.status || 'unknown';
                    const status = String(statusRaw).toLowerCase();
                    const css = status === 'success' ? 'ok' : (status === 'failure' ? 'bad' : '');
                    appendCell(tr, statusRaw);
                    appendCell(tr, String(row?.count || 0), css);
                }
            );
        }

        function startAutoRefresh() {
            if (refreshIntervalId !== null) {
                return;
            }
            refreshIntervalId = setInterval(fetchObservabilitySummary, 15000);
        }

        function stopAutoRefresh() {
            if (refreshIntervalId === null) {
                return;
            }
            clearInterval(refreshIntervalId);
            refreshIntervalId = null;
        }

        refreshBtn.addEventListener('click', fetchObservabilitySummary);
        windowSelect.addEventListener('change', fetchObservabilitySummary);
        document.getElementById('logout-btn').addEventListener('click', () => window.logout());
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                stopAutoRefresh();
                return;
            }
            fetchObservabilitySummary();
            startAutoRefresh();
        });

        if (!document.hidden) {
            fetchObservabilitySummary();
            startAutoRefresh();
        }