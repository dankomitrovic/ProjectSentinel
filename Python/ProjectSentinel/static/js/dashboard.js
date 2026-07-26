const searchInput =
        document.getElementById("deviceSearch");

    const tableRows =
        document.querySelectorAll(
            "#deviceTable tbody tr"
        );

    const scanButton =
        document.getElementById("scanButton");

    const scanMessage =
        document.getElementById("scanMessage");

    const scanStatusBadge =
        document.getElementById("scanStatusBadge");

    const progressTrack =
        document.getElementById("progressTrack");

    let scanPollTimer = null;
    let reloadScheduled = false;
    let scanStartedFromThisPage = false;


    function formatTimestamp(timestamp) {
        if (!timestamp) {
            return "Not available";
        }

        const parsedDate = new Date(timestamp);

        if (Number.isNaN(parsedDate.getTime())) {
            return timestamp;
        }

        return parsedDate.toLocaleString();
    }


    function setScanPresentation(scan) {
        const status = scan.status || "idle";

        scanStatusBadge.className =
            "scan-status-badge";

        if (
            status === "starting" ||
            status === "scanning"
        ) {
            scanStatusBadge.classList.add(
                "scan-running"
            );

            scanStatusBadge.textContent =
                "Scanning";

            scanButton.disabled = true;
            scanButton.textContent =
                "Scanning...";

            progressTrack.classList.add(
                "visible"
            );

            scanMessage.textContent =
                scan.message ||
                "Sentinel is scanning the network.";

            return;
        }

        progressTrack.classList.remove(
            "visible"
        );

        scanButton.disabled = false;
        scanButton.textContent =
            "Run Network Scan";

        if (status === "completed") {
            scanStatusBadge.classList.add(
                "scan-completed"
            );

            scanStatusBadge.textContent =
                "Complete";

            scanMessage.textContent =
                scan.message ||
                "Network scan completed successfully.";

            if (
                scan.device_count !== null &&
                scan.device_count !== undefined
            ) {
                document.getElementById(
                    "visibleDeviceCount"
                ).textContent = scan.device_count;
            }

            if (scan.completed_at) {
                document.getElementById(
                    "lastScanTime"
                ).textContent =
                    formatTimestamp(
                        scan.completed_at
                    );
            }

            return;
        }

        if (status === "failed") {
            scanStatusBadge.classList.add(
                "scan-failed"
            );

            scanStatusBadge.textContent =
                "Failed";

            scanMessage.textContent =
                scan.error ||
                scan.message ||
                "The network scan failed.";

            return;
        }

        scanStatusBadge.classList.add(
            "scan-idle"
        );

        scanStatusBadge.textContent =
            "Idle";

        scanMessage.textContent =
            scan.message ||
            "Sentinel is ready to scan the active network.";
    }


    async function getScanStatus() {
        try {
            const response = await fetch(
                "/scan/status",
                {
                    cache: "no-store"
                }
            );

            if (!response.ok) {
                throw new Error(
                    "Unable to retrieve scan status."
                );
            }

            const result = await response.json();
            const scan = result.scan || {};

            setScanPresentation(scan);

            if (
                scan.status === "starting" ||
                scan.status === "scanning"
            ) {
                return;
            }

            stopStatusPolling();

            if (
                scan.status === "completed" &&
                scanStartedFromThisPage &&
                !reloadScheduled
            ) {
                reloadScheduled = true;

                scanMessage.textContent =
                    "Scan complete. Refreshing dashboard...";

                window.setTimeout(
                    function () {
                        window.location.reload();
                    },
                    1200
                );
            }
        } catch (error) {
            stopStatusPolling();

            scanButton.disabled = false;
            scanButton.textContent =
                "Run Network Scan";

            progressTrack.classList.remove(
                "visible"
            );

            scanStatusBadge.className =
                "scan-status-badge scan-failed";

            scanStatusBadge.textContent =
                "Error";

            scanMessage.textContent =
                error.message;
        }
    }


    function startStatusPolling() {
        stopStatusPolling();

        getScanStatus();

        scanPollTimer = window.setInterval(
            getScanStatus,
            1000
        );
    }


    function stopStatusPolling() {
        if (scanPollTimer !== null) {
            window.clearInterval(
                scanPollTimer
            );

            scanPollTimer = null;
        }
    }


    async function startNetworkScan() {
        reloadScheduled = false;
        scanStartedFromThisPage = true;

        scanButton.disabled = true;
        scanButton.textContent = "Starting...";

        progressTrack.classList.add(
            "visible"
        );

        scanStatusBadge.className =
            "scan-status-badge scan-running";

        scanStatusBadge.textContent =
            "Starting";

        scanMessage.textContent =
            "Preparing Sentinel network scan.";

        try {
            const response = await fetch(
                "/scan",
                {
                    method: "POST",
                    headers: {
                        "Accept": "application/json"
                    }
                }
            );

            const result = await response.json();

            if (response.status === 409) {
                scanMessage.textContent =
                    result.message;

                startStatusPolling();
                return;
            }

            if (!response.ok) {
                throw new Error(
                    result.message ||
                    "Unable to start network scan."
                );
            }

            setScanPresentation(
                result.scan || {
                    status: "starting",
                    message: result.message
                }
            );

            startStatusPolling();

        } catch (error) {
            scanStartedFromThisPage = false;

            scanButton.disabled = false;
            scanButton.textContent =
                "Run Network Scan";

            progressTrack.classList.remove(
                "visible"
            );

            scanStatusBadge.className =
                "scan-status-badge scan-failed";

            scanStatusBadge.textContent =
                "Error";

            scanMessage.textContent =
                error.message;
        }
    }


    searchInput.addEventListener(
        "input",
        function () {
            const searchValue =
                searchInput.value
                    .toLowerCase()
                    .trim();

            tableRows.forEach(
                function (row) {
                    const rowText =
                        row.textContent
                            .toLowerCase();

                    if (
                        rowText.includes(
                            searchValue
                        )
                    ) {
                        row.style.display = "";
                    } else {
                        row.style.display = "none";
                    }
                }
            );
        }
    );


    tableRows.forEach(
        function (row) {
            row.addEventListener(
                "click",
                function () {
                    window.location.href =
                        row.dataset.deviceUrl;
                }
            );

            row.addEventListener(
                "keydown",
                function (event) {
                    if (
                        event.key === "Enter" ||
                        event.key === " "
                    ) {
                        event.preventDefault();

                        window.location.href =
                            row.dataset.deviceUrl;
                    }
                }
            );
        }
    );


    scanButton.addEventListener(
        "click",
        startNetworkScan
    );


    getScanStatus().then(
        function () {
            fetch(
                "/scan/status",
                {
                    cache: "no-store"
                }
            )
                .then(
                    function (response) {
                        return response.json();
                    }
                )
                .then(
                    function (result) {
                        const status =
                            result.scan.status;

                        if (
                            status === "starting" ||
                            status === "scanning"
                        ) {
                            startStatusPolling();
                        }
                    }
                );
        }
    );


    const monitorToggleButton = document.getElementById("monitorToggleButton");
    const monitorStatusBadge = document.getElementById("monitorStatusBadge");
    const monitorMessage = document.getElementById("monitorMessage");
    const monitorCycles = document.getElementById("monitorCycles");
    const monitorLastCycle = document.getElementById("monitorLastCycle");
    const monitorInterval = document.getElementById("monitorInterval");
    const monitorIntervalSelect = document.getElementById("monitorIntervalSelect");
    let monitorPollTimer = null;
    let knownMonitorCycle = Number(monitorCycles ? monitorCycles.textContent : 0);

    function presentMonitor(monitor) {
        if (!monitorToggleButton) { return; }
        const enabled = Boolean(monitor.enabled);
        monitorToggleButton.dataset.enabled = String(enabled);
        monitorToggleButton.textContent = enabled ? "Stop Live Monitoring" : "Start Live Monitoring";
        monitorToggleButton.disabled = monitor.status === "starting" || monitor.status === "stopping";
        monitorStatusBadge.className = "monitor-status monitor-" + (monitor.status || "stopped");
        monitorStatusBadge.textContent = String(monitor.status || "stopped").toUpperCase();
        monitorMessage.textContent = monitor.message || "Live monitoring status unavailable.";
        monitorCycles.textContent = monitor.cycles_completed || 0;
        monitorInterval.textContent = (monitor.interval_seconds || 60) + " seconds";
        monitorLastCycle.textContent = formatTimestamp(monitor.last_cycle_at);
        const cycles = Number(monitor.cycles_completed || 0);
        if (cycles > knownMonitorCycle) {
            knownMonitorCycle = cycles;
            window.setTimeout(function () { window.location.reload(); }, 900);
        }
    }

    async function getMonitorStatus() {
        if (!monitorToggleButton) { return; }
        try {
            const response = await fetch("/monitor/status", {cache: "no-store"});
            if (!response.ok) { throw new Error("Unable to retrieve live-monitoring status."); }
            const result = await response.json();
            presentMonitor(result.monitor || {});
        } catch (error) {
            monitorMessage.textContent = error.message;
            monitorStatusBadge.className = "monitor-status monitor-error";
            monitorStatusBadge.textContent = "ERROR";
        }
    }

    async function toggleMonitor() {
        const enabled = monitorToggleButton.dataset.enabled === "true";
        const endpoint = enabled ? "/monitor/stop" : "/monitor/start";
        const options = {method: "POST", headers: {"Content-Type": "application/json"}};
        if (!enabled) { options.body = JSON.stringify({interval_seconds: Number(monitorIntervalSelect.value)}); }
        monitorToggleButton.disabled = true;
        try {
            const response = await fetch(endpoint, options);
            if (!response.ok) { throw new Error("Unable to change live-monitoring state."); }
            const result = await response.json();
            presentMonitor(result.monitor || {});
        } catch (error) {
            monitorToggleButton.disabled = false;
            monitorMessage.textContent = error.message;
        }
    }

    if (monitorToggleButton) {
        monitorToggleButton.addEventListener("click", toggleMonitor);
        getMonitorStatus();
        monitorPollTimer = window.setInterval(getMonitorStatus, 3000);
    }
