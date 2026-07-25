"use strict";

document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".js-local-time").forEach(function (element) {
        const value = element.dataset.timestamp;
        if (!value) return;
        const parsed = new Date(value);
        if (!Number.isNaN(parsed.getTime())) {
            element.textContent = parsed.toLocaleString();
            element.title = value;
        }
    });

    const timeline = document.getElementById("device-timeline");
    const toggle = document.getElementById("timeline-toggle");
    if (!timeline || !toggle || !timeline.querySelector(".timeline-extra")) {
        if (toggle) toggle.hidden = true;
        return;
    }

    toggle.addEventListener("click", function () {
        const expanded = timeline.classList.toggle("expanded");
        toggle.textContent = expanded ? "Show recent" : "Show all";
    });
});
