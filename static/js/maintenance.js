(function pollMaintenanceState() {
    fetch('/api/maintenance', { credentials: 'same-origin', cache: 'no-store' })
        .then(function (response) {
            return response.json();
        })
        .then(function (data) {
            if (!data || !data.active) {
                window.location.reload();
                return;
            }
            window.setTimeout(pollMaintenanceState, 1500);
        })
        .catch(function () {
            window.setTimeout(pollMaintenanceState, 2000);
        });
})();
