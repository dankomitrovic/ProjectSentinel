"use strict";

const refreshButton = document.getElementById("refreshSensors");
if (refreshButton) {
    refreshButton.addEventListener("click", () => window.location.reload());
}
window.setTimeout(() => window.location.reload(), 30000);
