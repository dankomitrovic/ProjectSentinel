"use strict";

document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".asset-health-track i[data-width]").forEach(function (element) {
        const width = Number(element.dataset.width);
        const safeWidth = Math.max(0, Math.min(100, Number.isFinite(width) ? width : 0));
        element.style.width = safeWidth + "%";
    });

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
    if (copyButton && macElement) {
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
    }

    const removeTrustButton = document.querySelector("[data-confirm-remove-trust]");
    const removeTrustForm = removeTrustButton ? removeTrustButton.closest("form") : null;

    if (removeTrustButton && removeTrustForm) {
        removeTrustForm.addEventListener("submit", function (event) {
            const confirmed = window.confirm(
                "Remove this device from the trusted inventory?\n\n" +
                "It will return to pending review. This does not block or disconnect it from the network."
            );

            if (!confirmed) {
                event.preventDefault();
                return;
            }

            removeTrustButton.disabled = true;
            removeTrustButton.textContent = "Removing Trust...";
        });
    }
});
