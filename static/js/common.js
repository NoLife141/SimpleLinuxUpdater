(function () {
    if (window.__commonHelpersReady) return;
    window.__commonHelpersReady = true;
    const appTimezoneState = window.__appTimezoneState || {
        value: "UTC",
        resolved: "UTC",
        loaded: false,
        loadingPromise: null
    };
    window.__appTimezoneState = appTimezoneState;

    function normalizeAppTimezone(value) {
        const raw = String(value ?? "").trim();
        return raw || "UTC";
    }

    function normalizeResolvedTimezone(value) {
        return String(value ?? "").trim();
    }

    function timezoneForIntl(timezone) {
        return normalizeResolvedTimezone(timezone);
    }

    function buildTimestampFormatter(timeZone) {
        return new Intl.DateTimeFormat(undefined, {
            timeZone,
            year: "numeric",
            month: "short",
            day: "2-digit",
            hour: "2-digit",
            minute: "2-digit",
            hourCycle: "h23",
            timeZoneName: "short"
        });
    }

    function parseTimestamp(value) {
        const raw = String(value ?? "").trim();
        if (!raw) return null;
        const parsed = new Date(raw);
        return Number.isNaN(parsed.getTime()) ? null : parsed;
    }

    window.escapeHtml = window.escapeHtml || function escapeHtml(value) {
        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/\"/g, "&quot;")
            .replace(/'/g, "&#39;");
    };

    window.escapeJsSingleQuoted = window.escapeJsSingleQuoted || function escapeJsSingleQuoted(value) {
        return String(value ?? "")
            .replace(/\\/g, "\\\\")
            .replace(/'/g, "\\'")
            .replace(/\r/g, "\\r")
            .replace(/\n/g, "\\n")
            .replace(/\u2028/g, "\\u2028")
            .replace(/\u2029/g, "\\u2029");
    };

    window.parseErrorResponse = window.parseErrorResponse || async function parseErrorResponse(res, fallbackMessage) {
        const data = await res.json().catch(() => ({}));
        return data.error || fallbackMessage;
    };

    window.updateFileLabel = window.updateFileLabel || function updateFileLabel(input, emptyLabel = "Choose file") {
        if (!input) return;
        const label = document.querySelector(`label[for="${input.id}"]`);
        if (!label) return;
        const file = input.files && input.files[0];
        label.textContent = file ? file.name : emptyLabel;
    };

    window.setAppTimezoneCache = window.setAppTimezoneCache || function setAppTimezoneCache(payload) {
        if (payload && typeof payload === "object" && !Array.isArray(payload)) {
            appTimezoneState.value = normalizeAppTimezone(payload.timezone);
            if (Object.prototype.hasOwnProperty.call(payload, "resolved_timezone")) {
                appTimezoneState.resolved = normalizeResolvedTimezone(payload.resolved_timezone);
            } else {
                appTimezoneState.resolved = normalizeResolvedTimezone(payload.timezone);
            }
        } else {
            const timezone = normalizeAppTimezone(payload);
            appTimezoneState.value = timezone;
            appTimezoneState.resolved = normalizeResolvedTimezone(timezone);
        }
        appTimezoneState.loaded = true;
        return {
            timezone: appTimezoneState.value,
            resolvedTimezone: appTimezoneState.resolved
        };
    };

    window.getAppTimezoneLabel = window.getAppTimezoneLabel || function getAppTimezoneLabel() {
        return normalizeAppTimezone(appTimezoneState.value);
    };

    window.getAppTimezoneResolved = window.getAppTimezoneResolved || function getAppTimezoneResolved() {
        return normalizeResolvedTimezone(appTimezoneState.resolved);
    };

    window.ensureAppTimezoneLoaded = window.ensureAppTimezoneLoaded || async function ensureAppTimezoneLoaded(force = false) {
        if (appTimezoneState.loaded && !force) {
            return {
                timezone: appTimezoneState.value,
                resolvedTimezone: appTimezoneState.resolved
            };
        }
        if (appTimezoneState.loadingPromise && !force) {
            return appTimezoneState.loadingPromise;
        }
        appTimezoneState.loadingPromise = (async () => {
            try {
                const res = await fetch("/api/app-settings/timezone", { cache: "no-store" });
                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }
                const data = await res.json().catch(() => ({}));
                return window.setAppTimezoneCache(data);
            } catch (err) {
                console.error("Failed to load app timezone:", err);
                if (!appTimezoneState.loaded) {
                    appTimezoneState.value = normalizeAppTimezone(appTimezoneState.value || "UTC");
                    appTimezoneState.resolved = normalizeResolvedTimezone(appTimezoneState.resolved || appTimezoneState.value);
                    appTimezoneState.loaded = true;
                }
                return {
                    timezone: appTimezoneState.value,
                    resolvedTimezone: appTimezoneState.resolved
                };
            } finally {
                appTimezoneState.loadingPromise = null;
            }
        })();
        return appTimezoneState.loadingPromise;
    };

    window.formatAppTimestamp = window.formatAppTimestamp || function formatAppTimestamp(value, options = {}) {
        const fallback = String(value ?? "").trim();
        const parsed = parseTimestamp(value);
        const timezone = window.getAppTimezoneLabel();
        const resolvedTimezone = window.getAppTimezoneResolved ? window.getAppTimezoneResolved() : timezone;
        if (!parsed) {
            return {
                primary: options.preformattedPrimary || fallback || "-",
                secondary: "",
                title: options.preformattedTitle || fallback || "",
                timezone
            };
        }

        let primary = options.preformattedPrimary || fallback || parsed.toISOString();
        let utcValue = parsed.toISOString();
        if (!options.preformattedPrimary && resolvedTimezone) {
            try {
                primary = buildTimestampFormatter(timezoneForIntl(resolvedTimezone)).format(parsed);
            } catch (err) {
                console.error("Failed to format timestamp in app timezone:", err);
            }
        }
        try {
            utcValue = buildTimestampFormatter("UTC").format(parsed);
        } catch (_) {
            utcValue = parsed.toISOString();
        }
        return {
            primary,
            secondary: options.preformattedSecondary || (options.includeUTC ? `UTC: ${utcValue}` : ""),
            title: options.preformattedTitle || (options.includeUTC || options.titleUTC ? `UTC: ${utcValue}` : utcValue),
            timezone
        };
    };
}());
