(function () {
    if (window.__commonHelpersReady) return;
    window.__commonHelpersReady = true;

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
}());
