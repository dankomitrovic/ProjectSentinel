"use strict";

const refreshButton = document.getElementById("refreshSensors");
const refreshStatus = document.getElementById("liveRefreshStatus");

function setText(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
}

function formatValue(value, suffix, decimals = 1) {
    return value === null || value === undefined ? "—" : `${Number(value).toFixed(decimals)}${suffix}`;
}

function formatDuration(seconds) {
    if (seconds === null || seconds === undefined) return "No motion recorded";
    if (seconds < 60) return `Active for ${seconds} sec`;
    const minutes = Math.floor(seconds / 60);
    return `Active for ${minutes} min`;
}

function updateSeverity(element, severity, prefix = "sensor-level-text-") {
    if (!element) return;
    [...element.classList].filter(name => name.startsWith(prefix)).forEach(name => element.classList.remove(name));
    element.classList.add(`${prefix}${severity}`);
}

function updateAgent(agent) {
    const card = document.querySelector(`[data-agent-id="${CSS.escape(agent.agent_id)}"]`);
    if (!card) {
        window.location.reload();
        return;
    }

    card.classList.toggle("sensor-online", Boolean(agent.online));
    card.classList.toggle("sensor-offline", !agent.online);
    card.querySelector('[data-field="state"]').textContent = agent.online ? "ONLINE" : "OFFLINE";

    const intelligence = agent.intelligence;
    const health = card.querySelector('[data-field="health"]');
    health.textContent = `${intelligence.health_score}/100 · ${intelligence.health_label}`;
    updateSeverity(health, intelligence.health_severity, "sensor-level-");

    card.querySelector('[data-field="temperature"]').textContent = formatValue(agent.latest.temperature, "°C");
    card.querySelector('[data-field="humidity"]').textContent = formatValue(agent.latest.humidity, "%");
    card.querySelector('[data-field="motion"]').textContent = agent.latest.motion ? "Detected" : "Clear";
    card.querySelector('[data-field="rssi"]').textContent = agent.latest.rssi == null ? "—" : `${Math.round(agent.latest.rssi)} dBm`;
    card.querySelector('[data-field="uptime"]').textContent = agent.latest.uptime_seconds == null ? "—" : `${Math.floor(agent.latest.uptime_seconds / 60)} min`;
    card.querySelector('[data-field="firmware"]').textContent = agent.firmware || "Unknown";
    card.querySelector('[data-field="heartbeat"]').textContent = agent.heartbeat_label;

    const temperatureStatus = card.querySelector('[data-field="temperature-status"]');
    temperatureStatus.textContent = intelligence.temperature.label;
    updateSeverity(temperatureStatus, intelligence.temperature.severity);

    const humidityStatus = card.querySelector('[data-field="humidity-status"]');
    humidityStatus.textContent = intelligence.humidity.label;
    updateSeverity(humidityStatus, intelligence.humidity.severity);

    const rssiStatus = card.querySelector('[data-field="rssi-status"]');
    rssiStatus.textContent = intelligence.rssi.label;
    updateSeverity(rssiStatus, intelligence.rssi.severity);

    const motionContext = card.querySelector('[data-field="motion-context"]');
    motionContext.textContent = intelligence.motion.active ? formatDuration(intelligence.motion.active_seconds) : (intelligence.motion.last_motion ? `Last motion ${intelligence.motion.last_motion}` : "No motion recorded");
}

async function refreshSensorOperations() {
    try {
        if (refreshStatus) refreshStatus.textContent = "Updating…";
        const response = await fetch("/api/sensors/operations", { cache: "no-store" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        const summary = data.summary;
        const intelligence = data.intelligence;

        setText("summaryRegistered", summary.total_agents);
        setText("summaryOnline", summary.online_agents);
        setText("summaryFleetScore", intelligence.fleet_score);
        setText("summarySamples", intelligence.telemetry_samples);
        setText("summaryTemperature", summary.average_temperature == null ? "—" : `${summary.average_temperature.toFixed(1)}°C`);
        setText("summaryMotion", summary.motion_agents);
        setText("fleetHealthScore", `${intelligence.fleet_score}/100`);
        setText("fleetHealthPosture", `${intelligence.posture} · ${summary.online_agents}/${summary.total_agents} nodes online`);
        setText("fleetOperationLabel", `${summary.online_agents}/${summary.total_agents} online`);
        setText("lastTelemetryOperation", intelligence.operations.last_telemetry || "No telemetry");
        setText("lastMotionOperation", intelligence.operations.last_motion || "No motion recorded");

        intelligence.agents.forEach(updateAgent);
        if (refreshStatus) refreshStatus.textContent = "Connected · every 10 sec";
    } catch (error) {
        if (refreshStatus) refreshStatus.textContent = `Update failed · ${error.message}`;
    }
}

if (refreshButton) refreshButton.addEventListener("click", refreshSensorOperations);
refreshSensorOperations();
window.setInterval(refreshSensorOperations, 10000);
