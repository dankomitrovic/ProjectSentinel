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
    if (timeline && toggle && timeline.querySelector(".timeline-extra")) {
        toggle.addEventListener("click", function () {
            const expanded = timeline.classList.toggle("expanded");
            toggle.textContent = expanded ? "Show recent" : "Show all";
        });
    } else if (toggle) {
        toggle.hidden = true;
    }

    const copyButton = document.getElementById("copy-device-identifiers");
    const macElement = document.getElementById("device-mac-value");
    if (!copyButton || !macElement) return;

    copyButton.addEventListener("click", function () {
        const heading = document.querySelector(".investigation-title-block h1");
        const summary = document.querySelector(".investigation-title-block > p");
        const text = [
            heading ? heading.textContent.trim() : "Device",
            summary ? summary.textContent.trim() : macElement.textContent.trim()
        ].join("\n");

        navigator.clipboard.writeText(text).then(function () {
            copyButton.textContent = "Copied";
            copyButton.classList.add("copy-success");
            window.setTimeout(function () {
                copyButton.textContent = "Copy identifiers";
                copyButton.classList.remove("copy-success");
            }, 1800);
        }).catch(function () {
            copyButton.textContent = "Copy unavailable";
        });
    });
});
