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
}());
