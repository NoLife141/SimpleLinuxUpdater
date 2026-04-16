const scheduledPoliciesState = {
    items: [],
    runs: [],
    editableTimezone: "",
    timezone: "UTC"
};

const weekdayOptions = [
    { value: "mon", label: "Mon", fullLabel: "Monday" },
    { value: "tue", label: "Tue", fullLabel: "Tuesday" },
    { value: "wed", label: "Wed", fullLabel: "Wednesday" },
    { value: "thu", label: "Thu", fullLabel: "Thursday" },
    { value: "fri", label: "Fri", fullLabel: "Friday" },
    { value: "sat", label: "Sat", fullLabel: "Saturday" },
    { value: "sun", label: "Sun", fullLabel: "Sunday" }
];

const blackoutEditors = {
    policy: {
        rows: [],
        rowsId: "policy-blackout-rows",
        textareaId: "policy-blackouts-json",
        jsonStatusId: "policy-blackouts-json-status"
    },
    global: {
        rows: [],
        rowsId: "global-blackout-rows",
        textareaId: "scheduled-global-blackouts-json",
        jsonStatusId: "scheduled-global-blackouts-json-status"
    }
};

const policyFormState = {
    weekdays: []
};

function applyScheduledTimezone(payload) {
    const timezoneState = window.setAppTimezoneCache
        ? window.setAppTimezoneCache(payload)
        : { timezone: String(payload || "").trim() || scheduledPoliciesState.timezone || "UTC" };
    scheduledPoliciesState.timezone = timezoneState.timezone || "UTC";
    if (timezoneState && typeof timezoneState === "object") {
        if (Object.prototype.hasOwnProperty.call(timezoneState, "editable_timezone")) {
            scheduledPoliciesState.editableTimezone = String(timezoneState.editable_timezone ?? "").trim();
        } else if (Object.prototype.hasOwnProperty.call(timezoneState, "editableTimezone")) {
            scheduledPoliciesState.editableTimezone = String(timezoneState.editableTimezone ?? "").trim();
        }
    }
    const timezoneLabel = document.getElementById("scheduled-timezone");
    if (timezoneLabel) {
        timezoneLabel.textContent = scheduledPoliciesState.timezone;
    }
    const timezoneInput = document.getElementById("app-timezone-input");
    if (timezoneInput && document.activeElement !== timezoneInput) {
        timezoneInput.value = scheduledPoliciesState.editableTimezone;
    }
    updatePolicySummary();
    renderScheduledPolicies();
    renderScheduledRuns(scheduledPoliciesState.runs);
}

function setAppTimezoneFeedback(successMessage, errorMessage) {
    const success = document.getElementById("app-timezone-status");
    const error = document.getElementById("app-timezone-error");
    if (success) success.textContent = successMessage || "";
    if (error) error.textContent = errorMessage || "";
}

async function fetchAppTimezoneSettings(force = false) {
    const timezonePayload = window.ensureAppTimezoneLoaded
        ? await window.ensureAppTimezoneLoaded(force)
        : scheduledPoliciesState.timezone;
    applyScheduledTimezone(timezonePayload);
}

async function saveAppTimezoneSettings() {
    try {
        setAppTimezoneFeedback("", "");
        const input = document.getElementById("app-timezone-input");
        const button = document.getElementById("app-timezone-save");
        const timezone = input ? input.value.trim() : "";
        if (button) button.disabled = true;
        const res = await fetch("/api/app-settings/timezone", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ timezone })
        });
        if (!res.ok) {
            setAppTimezoneFeedback("", await parseErrorResponse(res, "Failed to save app timezone."));
            return;
        }
        const data = await res.json().catch(() => ({}));
        applyScheduledTimezone(data);
        setAppTimezoneFeedback("App timezone saved.", "");
    } catch (err) {
        setAppTimezoneFeedback("", err.message || "Failed to save app timezone.");
    } finally {
        const button = document.getElementById("app-timezone-save");
        if (button) button.disabled = false;
    }
}

function showMetricsTokenOnce(token) {
    const panel = document.getElementById("metrics-token-once");
    const value = document.getElementById("metrics-token-value");
    if (!panel || !value) return;
    if (!token) {
        value.textContent = "";
        panel.style.display = "none";
        return;
    }
    value.textContent = token;
    panel.style.display = "block";
}

async function fetchMetricsTokenStatus(resetReveal = true) {
    const status = document.getElementById("metrics-token-status");
    if (!status) return;
    if (resetReveal) {
        showMetricsTokenOnce("");
    }
    try {
        const res = await fetch("/api/metrics/token");
        if (!res.ok) {
            status.textContent = "Metrics token status: unknown";
            return;
        }
        const data = await res.json().catch(() => ({}));
        status.textContent = data.enabled ? "Metrics API token: enabled" : "Metrics API token: disabled";
    } catch (err) {
        console.error("Failed to fetch metrics token status:", err);
        status.textContent = "Metrics token status: request failed";
    }
}

async function rotateMetricsToken(askConfirm) {
    if (askConfirm && !window.confirm("Rotate metrics token? Existing scrapers using the old token will fail until updated.")) {
        return;
    }
    try {
        const res = await fetch("/api/metrics/token", { method: "POST" });
        if (!res.ok) {
            alert(await parseErrorResponse(res, "Failed to rotate metrics token."));
            return;
        }
        const data = await res.json().catch(() => ({}));
        const token = (data && typeof data.token === "string") ? data.token : "";
        if (!token) {
            alert("Token rotation succeeded but no token was returned.");
            return;
        }
        showMetricsTokenOnce(token);
        fetchMetricsTokenStatus(false);
    } catch (err) {
        console.error("Failed to rotate metrics token:", err);
        alert("Failed to rotate metrics token.");
    }
}

async function disableMetricsToken() {
    if (!window.confirm("Disable metrics token and hide /metrics now?")) {
        return;
    }
    try {
        const res = await fetch("/api/metrics/token", { method: "DELETE" });
        if (!res.ok) {
            alert(await parseErrorResponse(res, "Failed to disable metrics token."));
            return;
        }
        showMetricsTokenOnce("");
        fetchMetricsTokenStatus();
    } catch (err) {
        console.error("Failed to disable metrics token:", err);
        alert("Failed to disable metrics token.");
    }
}

async function copyMetricsToken() {
    const tokenValue = document.getElementById("metrics-token-value");
    if (!tokenValue) return;
    const token = tokenValue.textContent || "";
    if (!token) {
        alert("No token to copy.");
        return;
    }
    try {
        await navigator.clipboard.writeText(token);
        alert("Metrics token copied.");
    } catch (_) {
        alert("Failed to copy token. Copy it manually from the box.");
    }
}

function deriveDownloadFilename(contentDisposition) {
    if (!contentDisposition) return "";
    const utf8Match = contentDisposition.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf8Match && utf8Match[1]) {
        try {
            return decodeURIComponent(utf8Match[1]).replace(/[\r\n]/g, "");
        } catch (_) {
            return utf8Match[1].replace(/[\r\n]/g, "");
        }
    }
    const simpleMatch = contentDisposition.match(/filename="?([^";]+)"?/i);
    if (!simpleMatch || !simpleMatch[1]) return "";
    return simpleMatch[1].replace(/[\r\n]/g, "");
}

async function fetchBackupStatus() {
    const status = document.getElementById("backup-status");
    if (!status) return;
    try {
        const res = await fetch("/api/backup/status");
        if (!res.ok) {
            status.textContent = "Backup status: unavailable";
            return;
        }
        const data = await res.json().catch(() => ({}));
        const knownHostsState = data.known_hosts_exists ? "present" : "missing";
        status.textContent = `Backup paths: DB=${data.db_path || "-"}, config=${data.config_path || "-"}, known_hosts=${data.known_hosts_path || "-"} (${knownHostsState})`;
    } catch (err) {
        console.error("Failed to fetch backup status:", err);
        status.textContent = "Backup status: request failed";
    }
}

async function exportBackup() {
    const exportPassInput = document.getElementById("backup-export-passphrase");
    const exportPassConfirmInput = document.getElementById("backup-export-passphrase-confirm");
    try {
        const pass = exportPassInput?.value || "";
        const confirmPass = exportPassConfirmInput?.value || "";
        const includeKnownHosts = !!document.getElementById("backup-include-known-hosts")?.checked;
        if (pass.length < 12) {
            alert("Passphrase must be at least 12 characters.");
            return;
        }
        if (pass !== confirmPass) {
            alert("Passphrase confirmation does not match.");
            return;
        }
        const res = await fetch("/api/backup/export", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ passphrase: pass, include_known_hosts: includeKnownHosts })
        });
        if (!res.ok) {
            alert(await parseErrorResponse(res, "Failed to export backup."));
            return;
        }
        const blob = await res.blob();
        const filename = deriveDownloadFilename(res.headers.get("Content-Disposition")) || `simplelinuxupdater-backup-${Date.now()}.slubkp`;
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(url);
        alert("Backup exported.");
    } catch (err) {
        console.error("Failed to export backup:", err);
        alert("Failed to export backup.");
    } finally {
        if (exportPassInput) exportPassInput.value = "";
        if (exportPassConfirmInput) exportPassConfirmInput.value = "";
    }
}

async function restoreBackup() {
    const fileInput = document.getElementById("backup-restore-file");
    const restorePassInput = document.getElementById("backup-restore-passphrase");
    try {
        const pass = restorePassInput?.value || "";
        const file = fileInput?.files?.[0];
        if (!file) {
            alert("Choose a backup file first.");
            return;
        }
        if (pass.length < 12) {
            alert("Passphrase must be at least 12 characters.");
            return;
        }
        if (!window.confirm("Restore will fully replace current DB/config/known_hosts. Continue?")) {
            return;
        }
        const form = new FormData();
        form.append("file", file);
        form.append("passphrase", pass);
        const res = await fetch("/api/backup/restore", {
            method: "POST",
            body: form
        });
        if (!res.ok) {
            alert(await parseErrorResponse(res, "Failed to restore backup."));
            return;
        }
        alert("Backup restored successfully.");
        if (fileInput) {
            fileInput.value = "";
            updateFileLabel(fileInput, "Choose backup file");
        }
        await fetchBackupStatus();
    } catch (err) {
        console.error("Failed to restore backup:", err);
        alert("Failed to restore backup.");
    } finally {
        if (restorePassInput) restorePassInput.value = "";
    }
}

function weekdayOrder(token) {
    return weekdayOptions.findIndex((item) => item.value === token);
}

function normalizeWeekdayToken(raw) {
    switch (String(raw || "").trim().toLowerCase()) {
        case "mon":
        case "monday":
            return "mon";
        case "tue":
        case "tues":
        case "tuesday":
            return "tue";
        case "wed":
        case "wednesday":
            return "wed";
        case "thu":
        case "thur":
        case "thurs":
        case "thursday":
            return "thu";
        case "fri":
        case "friday":
            return "fri";
        case "sat":
        case "saturday":
            return "sat";
        case "sun":
        case "sunday":
            return "sun";
        default:
            return "";
    }
}

function normalizeWeekdaysInput(raw) {
    return normalizeWeekdays(String(raw || "").split(","));
}

function normalizeWeekdays(values) {
    const seen = new Set();
    return (Array.isArray(values) ? values : [])
        .map((value) => normalizeWeekdayToken(value))
        .filter(Boolean)
        .filter((value) => {
            if (seen.has(value)) return false;
            seen.add(value);
            return true;
        })
        .sort((a, b) => weekdayOrder(a) - weekdayOrder(b));
}

function formatWeekdayLabel(token) {
    const match = weekdayOptions.find((item) => item.value === token);
    return match ? match.label : token;
}

function formatWeekdayList(weekdays) {
    const normalized = normalizeWeekdays(weekdays);
    return normalized.length ? normalized.map(formatWeekdayLabel).join(", ") : "No weekdays selected";
}

function normalizeTimeInput(raw, fallback) {
    const value = String(raw || "").trim();
    return /^\d{2}:\d{2}$/.test(value) ? value : fallback;
}

function humanizeExecutionMode(mode) {
    switch (String(mode || "").trim()) {
        case "scan_only":
            return "Scan only";
        case "approval_required":
            return "Approval required";
        case "auto_apply":
            return "Auto apply";
        default:
            return "Unknown mode";
    }
}

function humanizePackageScope(scope) {
    switch (String(scope || "").trim()) {
        case "security":
            return "Security updates";
        case "full":
            return "Full updates";
        default:
            return "Unknown scope";
    }
}

function pluralize(count, singular, plural) {
    return `${count} ${count === 1 ? singular : plural}`;
}

function parseBlackoutsJSON(raw, label) {
    const trimmed = String(raw || "").trim();
    if (!trimmed) return [];
    let parsed;
    try {
        parsed = JSON.parse(trimmed);
    } catch (_) {
        throw new Error(`${label} must be valid JSON.`);
    }
    if (!Array.isArray(parsed)) {
        throw new Error(`${label} must be a JSON array.`);
    }
    return parsed;
}

function normalizeBlackoutRow(row) {
    return {
        weekdays: normalizeWeekdays(Array.isArray(row?.weekdays) ? row.weekdays : []),
        start_time: normalizeTimeInput(row?.start_time, "00:00"),
        end_time: normalizeTimeInput(row?.end_time, "06:00")
    };
}

function parseStrictBlackoutTime(value, label, index, field) {
    const raw = String(value ?? "").trim();
    const match = raw.match(/^(\d{2}):(\d{2})$/);
    if (!match) {
        throw new Error(`${label} ${index + 1}: ${field} must use HH:MM.`);
    }
    const hours = Number(match[1]);
    const minutes = Number(match[2]);
    if (!Number.isInteger(hours) || !Number.isInteger(minutes) || hours < 0 || hours > 23 || minutes < 0 || minutes > 59) {
        throw new Error(`${label} ${index + 1}: ${field} must be a real 24-hour time.`);
    }
    return raw;
}

function parseStrictBlackoutWeekdays(values, label, index) {
    if (!Array.isArray(values)) {
        throw new Error(`${label} ${index + 1}: weekdays must be an array.`);
    }
    const normalized = values.map((value) => {
        const token = normalizeWeekdayToken(value);
        if (!token) {
            throw new Error(`${label} ${index + 1}: invalid weekday "${String(value ?? "").trim()}".`);
        }
        return token;
    });
    const unique = normalizeWeekdays(normalized);
    if (!unique.length) {
        throw new Error(`${label} ${index + 1}: choose at least one weekday.`);
    }
    return unique;
}

function parseStrictBlackoutRow(row, label, index) {
    if (!row || typeof row !== "object" || Array.isArray(row)) {
        throw new Error(`${label} ${index + 1}: each item must be an object.`);
    }
    const normalized = {
        weekdays: parseStrictBlackoutWeekdays(row.weekdays, label, index),
        start_time: parseStrictBlackoutTime(row.start_time, label, index, "start_time"),
        end_time: parseStrictBlackoutTime(row.end_time, label, index, "end_time")
    };
    if (normalized.start_time >= normalized.end_time) {
        throw new Error(`${label} ${index + 1}: start_time must be before end_time.`);
    }
    return normalized;
}

function createEmptyBlackoutRow() {
    return {
        weekdays: [],
        start_time: "00:00",
        end_time: "06:00"
    };
}

function getBlackoutEditor(kind) {
    return blackoutEditors[kind];
}

function setBlackoutJsonStatus(kind, message, isError = false) {
    const editor = getBlackoutEditor(kind);
    const node = editor ? document.getElementById(editor.jsonStatusId) : null;
    if (!node) return;
    node.textContent = String(message || "").trim();
    node.classList.toggle("form-feedback-error", !!message && isError);
    node.classList.toggle("form-feedback-success", !!message && !isError);
}

function syncBlackoutTextarea(kind) {
    const editor = getBlackoutEditor(kind);
    const textarea = editor ? document.getElementById(editor.textareaId) : null;
    if (!textarea) return;
    textarea.value = JSON.stringify(editor.rows, null, 2);
}

function setBlackoutEditorRows(kind, rows) {
    const editor = getBlackoutEditor(kind);
    if (!editor) return;
    editor.rows = (Array.isArray(rows) ? rows : []).map(normalizeBlackoutRow);
    renderBlackoutEditor(kind);
}

function buildBlackoutWeekdayButtons(kind, row, index) {
    return weekdayOptions.map((day) => {
        const isActive = row.weekdays.includes(day.value);
        const active = isActive ? " active" : "";
        return `<button class="day-chip${active}" type="button" aria-pressed="${isActive ? "true" : "false"}" aria-label="${escapeHtml(day.fullLabel)}" data-blackout-kind="${escapeHtml(kind)}" data-blackout-action="toggle-day" data-index="${escapeHtml(String(index))}" data-day="${escapeHtml(day.value)}">${escapeHtml(day.label)}</button>`;
    }).join("");
}

function blackoutRowSummaryText(row) {
    const weekdays = normalizeWeekdays(Array.isArray(row?.weekdays) ? row.weekdays : []);
    const startTime = String(row?.start_time || "").trim() || "--:--";
    const endTime = String(row?.end_time || "").trim() || "--:--";
    return `${formatWeekdayList(weekdays)} · ${startTime} to ${endTime}`;
}

function updateBlackoutRowSummary(kind, index) {
    const editor = getBlackoutEditor(kind);
    const row = editor ? editor.rows[index] : null;
    const summary = editor
        ? document.querySelector(`#${editor.rowsId} [data-blackout-row-index="${String(index)}"] [data-blackout-summary]`)
        : null;
    if (!row || !summary) return;
    summary.textContent = blackoutRowSummaryText(row);
}

function renderBlackoutEditor(kind) {
    const editor = getBlackoutEditor(kind);
    const container = editor ? document.getElementById(editor.rowsId) : null;
    if (!editor || !container) return;
    if (!editor.rows.length) {
        container.innerHTML = '<div class="empty-editor-state subtle">No no-run windows yet.</div>';
        syncBlackoutTextarea(kind);
        if (kind === "policy") updatePolicySummary();
        return;
    }
    container.innerHTML = editor.rows.map((row, index) => `
        <div class="blackout-row" data-blackout-row-index="${escapeHtml(String(index))}">
            <div class="blackout-row-top">
                <span class="pill pill-muted">${escapeHtml(`Window ${index + 1}`)}</span>
                <button class="btn-danger inline-btn small-btn" type="button" data-blackout-kind="${escapeHtml(kind)}" data-blackout-action="remove-window" data-index="${escapeHtml(String(index))}">Remove</button>
            </div>
            <div>
                <label class="form-label">Days</label>
                <div class="weekday-picker blackout-weekday-picker" role="group" aria-label="No-run window days">
                    ${buildBlackoutWeekdayButtons(kind, row, index)}
                </div>
            </div>
            <div class="table-secondary" data-blackout-summary>${escapeHtml(blackoutRowSummaryText(row))}</div>
            <div class="blackout-time-grid">
                <div>
                    <label class="form-label" for="${escapeHtml(`${kind}-blackout-start-${index}`)}">Start</label>
                    <input type="time" id="${escapeHtml(`${kind}-blackout-start-${index}`)}" value="${escapeHtml(row.start_time)}" data-blackout-kind="${escapeHtml(kind)}" data-blackout-field="start_time" data-index="${escapeHtml(String(index))}">
                </div>
                <div>
                    <label class="form-label" for="${escapeHtml(`${kind}-blackout-end-${index}`)}">End</label>
                    <input type="time" id="${escapeHtml(`${kind}-blackout-end-${index}`)}" value="${escapeHtml(row.end_time)}" data-blackout-kind="${escapeHtml(kind)}" data-blackout-field="end_time" data-index="${escapeHtml(String(index))}">
                </div>
            </div>
        </div>
    `).join("");
    syncBlackoutTextarea(kind);
    if (kind === "policy") updatePolicySummary();
}

function addBlackoutRow(kind) {
    const editor = getBlackoutEditor(kind);
    if (!editor) return;
    editor.rows.push(createEmptyBlackoutRow());
    setBlackoutJsonStatus(kind, "");
    renderBlackoutEditor(kind);
}

function validateBlackoutRows(rows, label) {
    return rows.map((row, index) => parseStrictBlackoutRow(row, label, index));
}

function setPolicyFeedback(status, error = "") {
    const statusNode = document.getElementById("update-policy-status");
    const errorNode = document.getElementById("update-policy-error");
    if (statusNode) statusNode.textContent = String(status || "").trim();
    if (errorNode) errorNode.textContent = String(error || "").trim();
}

function setScheduledSettingsFeedback(status, error = "") {
    const statusNode = document.getElementById("scheduled-settings-status");
    const errorNode = document.getElementById("scheduled-settings-error");
    if (statusNode) statusNode.textContent = String(status || "").trim();
    if (errorNode) errorNode.textContent = String(error || "").trim();
}

function setPolicyFieldInvalid(fieldId, isInvalid) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    input.classList.toggle("is-invalid", !!isInvalid);
    if (isInvalid) {
        input.setAttribute("aria-invalid", "true");
    } else {
        input.removeAttribute("aria-invalid");
    }
}

function clearPolicyFieldErrors() {
    setPolicyFieldInvalid("policy-name", false);
    setPolicyFieldInvalid("policy-target-tag", false);
}

function setPolicyWeekdays(weekdays) {
    policyFormState.weekdays = normalizeWeekdays(weekdays);
    document.querySelectorAll("#policy-weekdays-picker .day-chip").forEach((button) => {
        const day = button.dataset.weekday || "";
        const isActive = policyFormState.weekdays.includes(day);
        button.classList.toggle("active", isActive);
        button.setAttribute("aria-pressed", isActive ? "true" : "false");
    });
    updatePolicySummary();
}

function togglePolicyWeekday(day) {
    const normalized = normalizeWeekdayToken(day);
    if (!normalized) return;
    if (policyFormState.weekdays.includes(normalized)) {
        setPolicyWeekdays(policyFormState.weekdays.filter((item) => item !== normalized));
        return;
    }
    setPolicyWeekdays([...policyFormState.weekdays, normalized]);
}

function setPolicyEditorModeLabel(text) {
    const label = document.getElementById("policy-editor-mode");
    if (!label) return;
    label.textContent = text;
}

function refreshPolicyFormVisibility() {
    const cadence = document.getElementById("policy-cadence-kind").value;
    const executionMode = document.getElementById("policy-execution-mode").value;
    const weekdaySection = document.getElementById("policy-weekday-section");
    const approvalWrap = document.getElementById("policy-approval-timeout-wrap");
    if (weekdaySection) {
        weekdaySection.classList.toggle("is-hidden", cadence !== "weekly");
    }
    if (approvalWrap) {
        approvalWrap.classList.toggle("is-hidden", executionMode !== "approval_required");
    }
    if (executionMode === "approval_required") {
        const timeoutInput = document.getElementById("policy-approval-timeout");
        if (timeoutInput && !String(timeoutInput.value || "").trim()) {
            timeoutInput.value = "720";
        }
    }
}

function updatePolicySummary() {
    const summary = document.getElementById("policy-summary");
    if (!summary) return;
    const name = document.getElementById("policy-name").value.trim() || "Unnamed policy";
    const targetTag = document.getElementById("policy-target-tag").value.trim() || "unset tag";
    const cadence = document.getElementById("policy-cadence-kind").value;
    const timeLocal = document.getElementById("policy-time-local").value || "--:--";
    const executionMode = document.getElementById("policy-execution-mode").value;
    const packageScope = document.getElementById("policy-package-scope").value;
    const timezone = scheduledPoliciesState.timezone || "UTC";
    const noRunCount = getBlackoutEditor("policy").rows.length;
    const scheduleText = cadence === "weekly"
        ? `Every ${formatWeekdayList(policyFormState.weekdays)} at ${timeLocal}`
        : `Daily at ${timeLocal}`;
    const executionText = humanizeExecutionMode(executionMode);
    const scopeText = humanizePackageScope(packageScope);
    const timeoutInput = document.getElementById("policy-approval-timeout");
    const timeoutText = executionMode === "approval_required"
        ? `, ${Number(timeoutInput?.value || 720)} minute approval window`
        : "";
    const noRunText = noRunCount
        ? `${pluralize(noRunCount, "no-run window", "no-run windows")} configured`
        : "No policy no-run windows";
    summary.innerHTML = `
        <div class="summary-title">${escapeHtml(name)}</div>
        <div class="summary-body">${escapeHtml(`${scheduleText} (${timezone}), ${executionText}, ${scopeText}${timeoutText}, tag=${targetTag}. ${noRunText}.`)}</div>
    `;
}

function formatCadence(policy) {
    const timeLocal = policy.time_local || "--:--";
    if (policy.cadence_kind === "weekly") {
        return `Every ${formatWeekdayList(policy.weekdays)} at ${timeLocal}`;
    }
    return `Daily at ${timeLocal}`;
}

function renderPolicyExecution(policy) {
    const mode = humanizeExecutionMode(policy.execution_mode);
    const scope = humanizePackageScope(policy.package_scope);
    const timeout = policy.execution_mode === "approval_required"
        ? ` · ${policy.approval_timeout_minutes || 720} minute approval window`
        : "";
    return `
        <div>${escapeHtml(mode)}</div>
        <div class="table-secondary">${escapeHtml(scope + timeout)}</div>
    `;
}

function renderPolicySchedule(policy) {
    const noRunCount = Array.isArray(policy.policy_blackouts) ? policy.policy_blackouts.length : 0;
    const noRunText = noRunCount
        ? `${pluralize(noRunCount, "policy no-run window", "policy no-run windows")}`
        : "No policy no-run windows";
    const timezoneText = scheduledPoliciesState.timezone
        ? `App timezone: ${scheduledPoliciesState.timezone}`
        : "";
    const detailText = [noRunText, timezoneText].filter(Boolean).join(" · ");
    return `
        <div>${escapeHtml(formatCadence(policy))}</div>
        <div class="table-secondary">${escapeHtml(detailText)}</div>
    `;
}

function renderMatchedServers(policy) {
    const matchedServers = Array.isArray(policy.matched_servers) ? policy.matched_servers : [];
    if (!matchedServers.length) {
        return `
            <div><span class="pill pill-muted">0 matched</span></div>
            <div class="table-secondary">No current server matches this tag.</div>
        `;
    }
    return `
        <div><span class="pill">${escapeHtml(pluralize(matchedServers.length, "matched server", "matched servers"))}</span></div>
        <div class="table-secondary">${escapeHtml(matchedServers.join(", "))}</div>
    `;
}

function safeRunStatusClassToken(status) {
    const normalized = String(status || "unknown").toLowerCase().replace(/[^a-z0-9_-]/g, "-");
    switch (normalized) {
        case "queued":
        case "running":
        case "waiting_approval":
        case "succeeded":
        case "failed":
        case "skipped":
        case "cancelled":
        case "interrupted":
            return normalized;
        default:
            return "unknown";
    }
}

function resetPolicyForm() {
    document.getElementById("policy-id").value = "";
    document.getElementById("policy-name").value = "";
    document.getElementById("policy-target-tag").value = "";
    document.getElementById("policy-time-local").value = "02:00";
    document.getElementById("policy-execution-mode").value = "scan_only";
    document.getElementById("policy-package-scope").value = "security";
    document.getElementById("policy-cadence-kind").value = "daily";
    document.getElementById("policy-approval-timeout").value = "720";
    document.getElementById("policy-enabled").checked = true;
    clearPolicyFieldErrors();
    setPolicyFeedback("", "");
    setPolicyEditorModeLabel("Create new policy");
    document.getElementById("policy-save-btn").textContent = "Create Policy";
    setPolicyWeekdays([]);
    setBlackoutEditorRows("policy", []);
    setBlackoutJsonStatus("policy", "");
    refreshPolicyFormVisibility();
    updatePolicySummary();
}

function applyPolicyToForm(policy) {
    document.getElementById("policy-id").value = String(policy.id || "");
    document.getElementById("policy-name").value = policy.name || "";
    document.getElementById("policy-target-tag").value = policy.target_tag || "";
    document.getElementById("policy-time-local").value = policy.time_local || "02:00";
    document.getElementById("policy-execution-mode").value = policy.execution_mode || "scan_only";
    document.getElementById("policy-package-scope").value = policy.package_scope || "security";
    document.getElementById("policy-cadence-kind").value = policy.cadence_kind || "daily";
    document.getElementById("policy-approval-timeout").value = policy.approval_timeout_minutes || 720;
    document.getElementById("policy-enabled").checked = !!policy.enabled;
    clearPolicyFieldErrors();
    setPolicyFeedback("", "");
    setPolicyWeekdays(policy.weekdays || []);
    setBlackoutEditorRows("policy", policy.policy_blackouts || []);
    setBlackoutJsonStatus("policy", "");
    setPolicyEditorModeLabel(`Editing #${policy.id}`);
    document.getElementById("policy-save-btn").textContent = "Update Policy";
    refreshPolicyFormVisibility();
    updatePolicySummary();
}

function renderScheduledPolicies() {
    const tbody = document.querySelector("#scheduled-policy-table tbody");
    if (!tbody) return;
    tbody.innerHTML = "";
    if (!scheduledPoliciesState.items.length) {
        const row = document.createElement("tr");
        row.innerHTML = '<td colspan="5" class="subtle">No scheduled update policies yet.</td>';
        tbody.appendChild(row);
        return;
    }
    scheduledPoliciesState.items.forEach((policy) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>
                <div class="table-title-row">
                    <div>${escapeHtml(policy.name || "")}</div>
                    <span class="pill ${policy.enabled ? "" : "pill-muted"}">${policy.enabled ? "Enabled" : "Disabled"}</span>
                </div>
                <div class="table-secondary">Target tag: ${escapeHtml(policy.target_tag || "")}</div>
            </td>
            <td>${renderPolicySchedule(policy)}</td>
            <td>${renderPolicyExecution(policy)}</td>
            <td>${renderMatchedServers(policy)}</td>
            <td>
                <div class="table-actions">
                    <button class="btn-ghost" type="button" data-action="edit-policy" data-id="${escapeHtml(String(policy.id))}">Edit</button>
                    <button class="btn-danger" type="button" data-action="delete-policy" data-id="${escapeHtml(String(policy.id))}">Delete</button>
                </div>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function renderScheduledRuns(items) {
    const tbody = document.querySelector("#scheduled-runs-table tbody");
    if (!tbody) return;
    scheduledPoliciesState.runs = Array.isArray(items) ? items : [];
    tbody.innerHTML = "";
    if (!scheduledPoliciesState.runs.length) {
        const row = document.createElement("tr");
        row.innerHTML = '<td colspan="6" class="subtle">No scheduled runs recorded yet.</td>';
        tbody.appendChild(row);
        return;
    }
    scheduledPoliciesState.runs.forEach((run) => {
        const row = document.createElement("tr");
        const jobValue = run.job_id ? `<code>${escapeHtml(run.job_id)}</code>` : '<span class="subtle">-</span>';
        const statusToken = safeRunStatusClassToken(run.status);
        const resolvedTimezone = window.getAppTimezoneResolved ? window.getAppTimezoneResolved() : "";
        const scheduledOptions = { includeUTC: true };
        if (!resolvedTimezone && String(run.scheduled_for_display || "").trim()) {
            scheduledOptions.preformattedPrimary = run.scheduled_for_display;
        }
        const scheduled = window.formatAppTimestamp
            ? window.formatAppTimestamp(run.scheduled_for_utc, scheduledOptions)
            : { primary: run.scheduled_for_utc || "", secondary: "", title: run.scheduled_for_utc || "" };
        row.innerHTML = `
            <td title="${escapeHtml(scheduled.title || "")}">
                <div>${escapeHtml(scheduled.primary || "")}</div>
                ${scheduled.secondary ? `<div class="table-secondary">${escapeHtml(scheduled.secondary)}</div>` : ""}
            </td>
            <td>${escapeHtml(run.policy_name || "")}</td>
            <td>${escapeHtml(run.server_name || "")}</td>
            <td><span class="status-chip status-${statusToken}">${escapeHtml(run.status || "unknown")}</span></td>
            <td>${escapeHtml(run.summary || run.reason || "")}</td>
            <td>${jobValue}</td>
        `;
        tbody.appendChild(row);
    });
}

async function fetchScheduledPolicies() {
    const res = await fetch("/api/update-policies");
    if (!res.ok) {
        throw new Error(await parseErrorResponse(res, "Failed to load scheduled policies."));
    }
    const data = await res.json().catch(() => ({}));
    scheduledPoliciesState.items = Array.isArray(data.items) ? data.items : [];
    if (data.timezone) {
        applyScheduledTimezone(data);
    }
    renderScheduledPolicies();
}

async function fetchScheduledSettings() {
    const res = await fetch("/api/update-policies/settings");
    if (!res.ok) {
        throw new Error(await parseErrorResponse(res, "Failed to load scheduled update settings."));
    }
    const data = await res.json().catch(() => ({}));
    applyScheduledTimezone(data.timezone ? data : scheduledPoliciesState.timezone || "UTC");
    setBlackoutEditorRows("global", data.global_blackouts || []);
    setBlackoutJsonStatus("global", "");
}

async function fetchScheduledRuns() {
    const res = await fetch("/api/update-policies/runs?limit=50");
    if (!res.ok) {
        throw new Error(await parseErrorResponse(res, "Failed to load scheduled runs."));
    }
    const data = await res.json().catch(() => ({}));
    if (data.timezone) {
        applyScheduledTimezone(data);
    }
    renderScheduledRuns(data.items || []);
}

async function refreshScheduledUpdateViews() {
    try {
        await Promise.all([
            fetchAppTimezoneSettings(true),
            fetchScheduledPolicies(),
            fetchScheduledSettings(),
            fetchScheduledRuns()
        ]);
    } catch (err) {
        console.error("Failed to refresh scheduled update views:", err);
        setPolicyFeedback("", err.message || "Failed to load scheduled update views.");
    }
}

function collectPolicyPayload() {
    clearPolicyFieldErrors();
    setPolicyFeedback("", "");
    const name = document.getElementById("policy-name").value.trim();
    const targetTag = document.getElementById("policy-target-tag").value.trim();
    const cadenceKind = document.getElementById("policy-cadence-kind").value;
    const executionMode = document.getElementById("policy-execution-mode").value;
    const packageScope = document.getElementById("policy-package-scope").value;
    const timeLocal = document.getElementById("policy-time-local").value;
    const weekdays = cadenceKind === "weekly" ? normalizeWeekdays(policyFormState.weekdays) : [];
    const approvalTimeoutValue = Number(document.getElementById("policy-approval-timeout").value || 0);
    let firstInvalidId = "";
    if (!name) {
        setPolicyFieldInvalid("policy-name", true);
        firstInvalidId = firstInvalidId || "policy-name";
    }
    if (!targetTag) {
        setPolicyFieldInvalid("policy-target-tag", true);
        firstInvalidId = firstInvalidId || "policy-target-tag";
    }
    if (firstInvalidId) {
        document.getElementById(firstInvalidId)?.focus();
        throw new Error("Policy name and target tag are required.");
    }
    if (cadenceKind === "weekly" && !weekdays.length) {
        throw new Error("Weekly policies require at least one weekday.");
    }
    const policyBlackouts = validateBlackoutRows(getBlackoutEditor("policy").rows, "Policy no-run window");
    return {
        name,
        enabled: document.getElementById("policy-enabled").checked,
        target_tag: targetTag,
        package_scope: packageScope,
        execution_mode: executionMode,
        cadence_kind: cadenceKind,
        time_local: timeLocal,
        weekdays,
        approval_timeout_minutes: executionMode === "approval_required" ? (approvalTimeoutValue || 720) : 0,
        policy_blackouts: policyBlackouts
    };
}

async function saveScheduledPolicy(event) {
    event.preventDefault();
    try {
        const id = document.getElementById("policy-id").value.trim();
        const payload = collectPolicyPayload();
        const url = id ? `/api/update-policies/${encodeURIComponent(id)}` : "/api/update-policies";
        const method = id ? "PUT" : "POST";
        const saveBtn = document.getElementById("policy-save-btn");
        if (saveBtn) saveBtn.disabled = true;
        const res = await fetch(url, {
            method,
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            setPolicyFeedback("", await parseErrorResponse(res, "Failed to save scheduled policy."));
            return;
        }
        const successMessage = id ? "Policy updated." : "Policy created.";
        resetPolicyForm();
        await refreshScheduledUpdateViews();
        setPolicyFeedback(successMessage, "");
    } catch (err) {
        setPolicyFeedback("", err.message || "Failed to save scheduled policy.");
    } finally {
        const saveBtn = document.getElementById("policy-save-btn");
        if (saveBtn) saveBtn.disabled = false;
    }
}

async function saveScheduledSettings() {
    try {
        setScheduledSettingsFeedback("", "");
        const payload = {
            global_blackouts: validateBlackoutRows(getBlackoutEditor("global").rows, "Global no-run window")
        };
        const button = document.getElementById("scheduled-settings-save");
        if (button) button.disabled = true;
        const res = await fetch("/api/update-policies/settings", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        if (!res.ok) {
            setScheduledSettingsFeedback("", await parseErrorResponse(res, "Failed to save global no-run windows."));
            return;
        }
        const data = await res.json().catch(() => ({}));
        applyScheduledTimezone(data.timezone ? data : scheduledPoliciesState.timezone || "UTC");
        setScheduledSettingsFeedback("Global no-run windows saved.", "");
    } catch (err) {
        setScheduledSettingsFeedback("", err.message || "Failed to save global no-run windows.");
    } finally {
        const button = document.getElementById("scheduled-settings-save");
        if (button) button.disabled = false;
    }
}

async function deleteScheduledPolicy(id) {
    if (!window.confirm("Delete this scheduled update policy?")) {
        return;
    }
    try {
        const res = await fetch(`/api/update-policies/${encodeURIComponent(id)}`, { method: "DELETE" });
        if (!res.ok) {
            setPolicyFeedback("", await parseErrorResponse(res, "Failed to delete scheduled policy."));
            return;
        }
        if (document.getElementById("policy-id").value === String(id)) {
            resetPolicyForm();
        }
        setPolicyFeedback("Policy deleted.", "");
        await refreshScheduledUpdateViews();
    } catch (err) {
        setPolicyFeedback("", err?.message || "Failed to delete scheduled policy.");
    }
}

function handleScheduledPolicyTableClick(event) {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    const id = String(button.dataset.id || "").trim();
    const policy = scheduledPoliciesState.items.find((item) => String(item.id) === id);
    if (!policy) return;
    if (button.dataset.action === "edit-policy") {
        applyPolicyToForm(policy);
        document.getElementById("update-policy-form")?.scrollIntoView({ behavior: "smooth", block: "start" });
        return;
    }
    if (button.dataset.action === "delete-policy") {
        deleteScheduledPolicy(id);
    }
}

function updateBlackoutRowField(kind, index, field, value) {
    const editor = getBlackoutEditor(kind);
    if (!editor || !editor.rows[index]) return;
    editor.rows[index][field] = value;
    syncBlackoutTextarea(kind);
    updateBlackoutRowSummary(kind, index);
    if (kind === "policy") updatePolicySummary();
}

function handleBlackoutEditorClick(event) {
    const button = event.target.closest("[data-blackout-action]");
    if (!button) return;
    const kind = button.dataset.blackoutKind;
    const action = button.dataset.blackoutAction;
    const index = Number(button.dataset.index || -1);
    const editor = getBlackoutEditor(kind);
    if (!editor) return;
    setBlackoutJsonStatus(kind, "");
    if (action === "remove-window") {
        if (index >= 0) {
            editor.rows.splice(index, 1);
            renderBlackoutEditor(kind);
        }
        return;
    }
    if (action === "toggle-day" && index >= 0) {
        const day = normalizeWeekdayToken(button.dataset.day);
        if (!day || !editor.rows[index]) return;
        const nextDays = editor.rows[index].weekdays.includes(day)
            ? editor.rows[index].weekdays.filter((item) => item !== day)
            : [...editor.rows[index].weekdays, day];
        editor.rows[index].weekdays = normalizeWeekdays(nextDays);
        const isActive = editor.rows[index].weekdays.includes(day);
        button.classList.toggle("active", isActive);
        button.setAttribute("aria-pressed", isActive ? "true" : "false");
        syncBlackoutTextarea(kind);
        updateBlackoutRowSummary(kind, index);
        if (kind === "policy") updatePolicySummary();
    }
}

function handleBlackoutEditorInput(event) {
    const input = event.target.closest("[data-blackout-field]");
    if (!input) return;
    const kind = input.dataset.blackoutKind;
    const field = input.dataset.blackoutField;
    const index = Number(input.dataset.index || -1);
    if (index < 0 || !field) return;
    setBlackoutJsonStatus(kind, "");
    updateBlackoutRowField(kind, index, field, input.value);
}

function applyBlackoutJson(kind, label) {
    const editor = getBlackoutEditor(kind);
    const textarea = editor ? document.getElementById(editor.textareaId) : null;
    if (!editor || !textarea) return;
    try {
        const rows = parseBlackoutsJSON(textarea.value, label).map((row, index) => parseStrictBlackoutRow(row, label, index));
        setBlackoutEditorRows(kind, rows);
        setBlackoutJsonStatus(kind, `${label} JSON applied to the editor.`, false);
        if (kind === "global") {
            setScheduledSettingsFeedback("", "");
        }
    } catch (err) {
        setBlackoutJsonStatus(kind, err.message || `Failed to apply ${label.toLowerCase()}.`, true);
    }
}

function bindPolicyFormInteractions() {
    const summaryFields = [
        "policy-name",
        "policy-target-tag",
        "policy-time-local",
        "policy-execution-mode",
        "policy-package-scope",
        "policy-cadence-kind",
        "policy-approval-timeout"
    ];
    summaryFields.forEach((fieldId) => {
        document.getElementById(fieldId)?.addEventListener("input", () => {
            if (fieldId === "policy-name") setPolicyFieldInvalid("policy-name", false);
            if (fieldId === "policy-target-tag") setPolicyFieldInvalid("policy-target-tag", false);
            refreshPolicyFormVisibility();
            updatePolicySummary();
        });
        document.getElementById(fieldId)?.addEventListener("change", () => {
            if (fieldId === "policy-name") setPolicyFieldInvalid("policy-name", false);
            if (fieldId === "policy-target-tag") setPolicyFieldInvalid("policy-target-tag", false);
            refreshPolicyFormVisibility();
            updatePolicySummary();
        });
    });

    document.getElementById("policy-weekdays-picker")?.addEventListener("click", (event) => {
        const button = event.target.closest("[data-weekday]");
        if (!button) return;
        togglePolicyWeekday(button.dataset.weekday);
    });

    document.getElementById("policy-weekdays-clear")?.addEventListener("click", () => {
        setPolicyWeekdays([]);
    });
}

document.addEventListener("change", (event) => {
    if (event.target && event.target.id === "backup-restore-file") {
        updateFileLabel(event.target, "Choose backup file");
    }
});

document.getElementById("logout-btn").addEventListener("click", () => window.logout());
document.getElementById("metrics-token-generate").addEventListener("click", () => rotateMetricsToken(false));
document.getElementById("metrics-token-rotate").addEventListener("click", () => rotateMetricsToken(true));
document.getElementById("metrics-token-disable").addEventListener("click", disableMetricsToken);
document.getElementById("metrics-token-copy").addEventListener("click", copyMetricsToken);
document.getElementById("backup-export-btn").addEventListener("click", exportBackup);
document.getElementById("backup-restore-btn").addEventListener("click", restoreBackup);
document.getElementById("app-timezone-save").addEventListener("click", saveAppTimezoneSettings);
document.getElementById("app-timezone-input").addEventListener("input", () => setAppTimezoneFeedback("", ""));
document.getElementById("update-policy-form").addEventListener("submit", saveScheduledPolicy);
document.getElementById("policy-reset-btn").addEventListener("click", resetPolicyForm);
document.getElementById("scheduled-settings-save").addEventListener("click", saveScheduledSettings);
document.querySelector("#scheduled-policy-table tbody").addEventListener("click", handleScheduledPolicyTableClick);
document.getElementById("policy-blackout-add").addEventListener("click", () => addBlackoutRow("policy"));
document.getElementById("global-blackout-add").addEventListener("click", () => addBlackoutRow("global"));
document.getElementById("policy-blackouts-json-apply").addEventListener("click", () => applyBlackoutJson("policy", "Policy no-run windows"));
document.getElementById("scheduled-global-blackouts-json-apply").addEventListener("click", () => applyBlackoutJson("global", "Global no-run windows"));
document.getElementById("policy-blackout-rows").addEventListener("click", handleBlackoutEditorClick);
document.getElementById("global-blackout-rows").addEventListener("click", handleBlackoutEditorClick);
document.getElementById("policy-blackout-rows").addEventListener("input", handleBlackoutEditorInput);
document.getElementById("global-blackout-rows").addEventListener("input", handleBlackoutEditorInput);

bindPolicyFormInteractions();
resetPolicyForm();
fetchMetricsTokenStatus();
fetchBackupStatus();
refreshScheduledUpdateViews();
updateFileLabel(document.getElementById("backup-restore-file"), "Choose backup file");
