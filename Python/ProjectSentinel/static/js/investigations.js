(() => {
  "use strict";

  const workspace = document.getElementById("live-investigation");
  if (!workspace) return;

  const endpoint = workspace.dataset.endpoint;
  const POLL_MS = 5000;
  let lastSignature = "";

  const $ = (id) => document.getElementById(id);
  const escapeHtml = (value) => String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");

  function friendlyTime(value) {
    if (!value) return "Unavailable";
    const moment = new Date(value);
    if (Number.isNaN(moment.getTime())) return String(value);
    const now = new Date();
    const sameDay = moment.toDateString() === now.toDateString();
    const yesterday = new Date(now); yesterday.setDate(now.getDate() - 1);
    const time = moment.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", hour12: false});
    if (sameDay) return `Today ${time}`;
    if (moment.toDateString() === yesterday.toDateString()) return `Yesterday ${time}`;
    return moment.toLocaleDateString([], {day: "2-digit", month: "short", year: "numeric"}) + ` ${time}`;
  }

  function titleCase(value) {
    return String(value || "").replaceAll("_", " ").toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
  }

  function evidenceValue(key, value) {
    if (value === null || value === undefined || value === "") return "Unavailable";
    if (key === "temperature") return `${value} °C`;
    if (key === "humidity") return `${value} %`;
    if (key === "rssi") return `${value} dBm`;
    if (key === "uptime_seconds") return `${value} sec`;
    if (key === "motion") return value ? "DETECTED" : "CLEAR";
    return String(value);
  }

  function eventIcon(type) {
    const value = String(type || "").toUpperCase();
    if (value.includes("NOTE")) return "✎";
    if (value.includes("STATUS")) return "↻";
    if (value.includes("CORRELATED")) return "⌁";
    if (value.includes("CREATED")) return "+";
    return "•";
  }

  function render(data) {
    const inv = data.investigation;
    const signature = JSON.stringify([inv.updated_at, inv.status, inv.confidence, inv.detections?.length, inv.timeline?.length, inv.notes?.length, inv.evidence]);
    const changed = lastSignature && signature !== lastSignature;
    lastSignature = signature;

    $("case-title").textContent = inv.title;
    $("case-description").textContent = inv.description;
    $("case-severity").textContent = inv.severity;
    $("case-updated").textContent = friendlyTime(inv.updated_at);
    $("case-confidence").textContent = inv.confidence;
    $("confidence-bar").style.width = `${inv.confidence}%`;
    $("case-detection-count").textContent = inv.detections.length;
    $("related-detection-count").textContent = inv.detections.length;
    $("case-agent-name").textContent = inv.agent_name;
    $("fact-agent-name").textContent = inv.agent_name;
    $("fact-location").textContent = inv.location;

    const status = $("case-status");
    status.textContent = titleCase(inv.status);
    status.className = `case-status case-status-${String(inv.status).toLowerCase()}`;

    document.querySelectorAll("[data-evidence-key]").forEach(card => {
      const key = card.dataset.evidenceKey;
      card.querySelector("strong").textContent = evidenceValue(key, inv.evidence?.[key]);
      card.classList.toggle("evidence-alert", key === "motion" && inv.evidence?.[key] === true);
    });

    $("related-detections").innerHTML = (inv.detections || []).map(d => `
      <article><span class="severity-chip severity-chip-${escapeHtml(String(d.severity).toLowerCase())}">${escapeHtml(d.severity)}</span>
      <div><strong>${escapeHtml(d.title)}</strong><p>${escapeHtml(d.message)}</p><small>${escapeHtml(friendlyTime(d.timestamp))} · ${escapeHtml(titleCase(d.type))}</small></div></article>`).join("");

    $("case-timeline").innerHTML = [...(inv.timeline || [])].reverse().map(e => `
      <article data-event-type="${escapeHtml(e.type)}"><span class="timeline-icon">${eventIcon(e.type)}</span><div><strong>${escapeHtml(titleCase(e.type))}</strong><p>${escapeHtml(e.message)}</p><small>${escapeHtml(friendlyTime(e.timestamp))} · ${escapeHtml(e.actor)}</small></div></article>`).join("");

    const notes = [...(inv.notes || [])].reverse();
    $("case-notes-list").innerHTML = notes.length ? notes.map(n => `<article><p>${escapeHtml(n.note)}</p><small>${escapeHtml(friendlyTime(n.timestamp))} · ${escapeHtml(n.author)}</small></article>`).join("") : '<p class="muted">No analyst notes yet.</p>';

    $("live-connection-label").textContent = changed ? "Investigation updated" : "Live case monitoring";
    $("live-refresh-label").textContent = `Last checked ${new Date().toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", second: "2-digit"})}`;
    workspace.classList.toggle("case-just-updated", Boolean(changed));
    if (changed) setTimeout(() => workspace.classList.remove("case-just-updated"), 1400);
  }

  async function poll() {
    try {
      const response = await fetch(endpoint, {headers: {"Accept": "application/json"}, cache: "no-store"});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      render(await response.json());
      document.body.classList.remove("case-live-offline");
    } catch (error) {
      document.body.classList.add("case-live-offline");
      $("live-connection-label").textContent = "Live monitoring interrupted";
      $("live-refresh-label").textContent = "Retrying automatically";
    }
  }

  poll();
  window.setInterval(poll, POLL_MS);
})();
