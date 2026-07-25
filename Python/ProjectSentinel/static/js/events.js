(() => {
    "use strict";

    const config = window.SENTINEL_EVENTS_CONFIG || {};
    const tableBody = document.getElementById("eventTableBody");
    const searchInput = document.getElementById("eventSearch");
    const severityFilter = document.getElementById("severityFilter");
    const typeFilter = document.getElementById("typeFilter");
    const refreshButton = document.getElementById("refreshEventsButton");
    const refreshState = document.getElementById("eventsRefreshState");
    const lastUpdated = document.getElementById("eventsLastUpdated");
    const visibleCount = document.getElementById("visibleEventCount");
    const emptyState = document.getElementById("emptyEventsState");
    const errorBox = document.getElementById("eventsError");

    let events = Array.isArray(config.initialEvents) ? config.initialEvents : [];
    let refreshTimer = null;

    const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

    function escapeHtml(value) {
        return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");
    }

    function formatEventType(value) {
        return String(value || "UNKNOWN")
            .replaceAll("_", " ")
            .toLowerCase()
            .replace(/\b\w/g, character => character.toUpperCase());
    }

    function eventInitial(value) {
        return formatEventType(value).charAt(0).toUpperCase() || "E";
    }

    function formatTimestamp(value) {
        if (!value) return "Unknown";
        const timestamp = new Date(value);
        if (Number.isNaN(timestamp.getTime())) return value;

        return timestamp.toLocaleString([], {
            year: "numeric",
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
    }

    function deviceDisplayName(device) {
        return device.friendly_name || device.hostname || device.ip_address || "Unknown device";
    }

    function deviceSubline(device) {
        return device.ip_address || device.mac_address || "";
    }

    function deviceUrl(macAddress) {
        if (!macAddress || !config.deviceUrlTemplate) return "";
        return config.deviceUrlTemplate.replace("__MAC__", encodeURIComponent(macAddress));
    }

    function eventSearchText(event) {
        const device = event.device || {};
        return [
            event.message, event.type, event.severity,
            device.friendly_name, device.hostname,
            device.ip_address, device.mac_address
        ].join(" ").toLowerCase();
    }

    function updateSeverityCounts() {
        const counts = Object.fromEntries(severityOrder.map(severity => [severity, 0]));

        events.forEach(event => {
            const severity = String(event.severity || "INFO").toUpperCase();
            if (Object.prototype.hasOwnProperty.call(counts, severity)) counts[severity] += 1;
        });

        severityOrder.forEach(severity => {
            const target = document.getElementById(`${severity.toLowerCase()}Count`);
            if (target) target.textContent = counts[severity];
        });
    }

    function rebuildTypeFilter() {
        const selectedType = typeFilter.value;
        const types = [...new Set(events.map(event => String(event.type || "UNKNOWN").toUpperCase()))].sort();

        typeFilter.innerHTML = '<option value="">All event types</option>';
        types.forEach(type => {
            const option = document.createElement("option");
            option.value = type;
            option.textContent = formatEventType(type);
            typeFilter.appendChild(option);
        });

        if (types.includes(selectedType)) typeFilter.value = selectedType;
    }

    function filteredEvents() {
        const query = searchInput.value.trim().toLowerCase();
        const severity = severityFilter.value;
        const type = typeFilter.value;

        return events.filter(event => {
            const eventSeverity = String(event.severity || "INFO").toUpperCase();
            const eventType = String(event.type || "UNKNOWN").toUpperCase();
            return (!query || eventSearchText(event).includes(query))
                && (!severity || eventSeverity === severity)
                && (!type || eventType === type);
        });
    }

    function renderEvents() {
        const visibleEvents = filteredEvents();

        tableBody.innerHTML = visibleEvents.map(event => {
            const device = event.device || {};
            const severity = String(event.severity || "INFO").toUpperCase();
            const macAddress = device.mac_address || "";
            const url = deviceUrl(macAddress);
            const deviceMarkup = macAddress && url
                ? `<a class="event-device-link" href="${escapeHtml(url)}">${escapeHtml(deviceDisplayName(device))}</a><small>${escapeHtml(deviceSubline(device))}</small>`
                : '<span class="system-event">System</span>';

            return `
                <tr class="event-row">
                    <td class="event-time">${escapeHtml(formatTimestamp(event.timestamp))}</td>
                    <td><span class="severity-badge severity-${escapeHtml(severity.toLowerCase())}">${escapeHtml(severity)}</span></td>
                    <td><span class="event-type-mark" aria-hidden="true">${escapeHtml(eventInitial(event.type))}</span><span class="event-type">${escapeHtml(formatEventType(event.type))}</span></td>
                    <td>${deviceMarkup}</td>
                    <td class="event-message">${escapeHtml(event.message)}</td>
                </tr>`;
        }).join("");

        visibleCount.textContent = visibleEvents.length;
        emptyState.hidden = visibleEvents.length !== 0;
    }

    function showError(message) {
        errorBox.textContent = message;
        errorBox.hidden = false;
    }

    function clearError() {
        errorBox.hidden = true;
        errorBox.textContent = "";
    }

    async function refreshEvents({ manual = false } = {}) {
        if (!config.eventsUrl) {
            showError("Events endpoint is not configured.");
            return;
        }

        if (manual) refreshButton.disabled = true;
        refreshState.textContent = "Refreshing event feed…";

        try {
            const response = await fetch(`${config.eventsUrl}?limit=100`, {
                headers: { "Accept": "application/json" },
                cache: "no-store"
            });

            if (!response.ok) throw new Error(`Events request failed with status ${response.status}.`);

            const payload = await response.json();
            events = Array.isArray(payload.events) ? payload.events : [];

            clearError();
            updateSeverityCounts();
            rebuildTypeFilter();
            renderEvents();
            refreshState.textContent = "Live feed active";
            lastUpdated.textContent = `Last updated ${new Date().toLocaleTimeString()}`;
        } catch (error) {
            showError(error.message || "Unable to refresh Sentinel events.");
            refreshState.textContent = "Live feed unavailable";
            lastUpdated.textContent = "Automatic refresh will retry";
        } finally {
            refreshButton.disabled = false;
        }
    }

    function scheduleRefresh() {
        window.clearInterval(refreshTimer);
        refreshTimer = window.setInterval(() => refreshEvents(), 15000);
    }

    [searchInput, severityFilter, typeFilter].forEach(control => {
        control.addEventListener("input", renderEvents);
        control.addEventListener("change", renderEvents);
    });

    refreshButton.addEventListener("click", () => refreshEvents({ manual: true }));
    document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshEvents(); });

    document.querySelectorAll(".event-time[data-timestamp]").forEach(cell => {
        cell.textContent = formatTimestamp(cell.dataset.timestamp);
    });

    updateSeverityCounts();
    renderEvents();
    scheduleRefresh();
    lastUpdated.textContent = `Loaded ${new Date().toLocaleTimeString()}`;
})();
