document.addEventListener("DOMContentLoaded", () => {
    const searchInput = document.getElementById("asset-search");
    const statusFilter = document.getElementById("asset-status-filter");
    const trustFilter = document.getElementById("asset-trust-filter");
    const clearButton = document.getElementById("asset-clear-filters");
    const resultsCount = document.getElementById("asset-results-count");
    const emptyState = document.getElementById("asset-empty-filter");

    const assetCards = Array.from(
        document.querySelectorAll(".asset-card")
    );

    if (
        !searchInput ||
        !statusFilter ||
        !trustFilter ||
        !clearButton ||
        !resultsCount
    ) {
        console.error("Project Sentinel asset filter controls were not found.");
        return;
    }

    function normaliseValue(value) {
        return String(value || "")
            .trim()
            .toLowerCase();
    }

    function updateAssetVisibility() {
        const searchValue = normaliseValue(searchInput.value);
        const selectedStatus = normaliseValue(statusFilter.value);
        const selectedTrust = normaliseValue(trustFilter.value);

        let visibleCount = 0;

        assetCards.forEach((card) => {
            const searchableText = normaliseValue(
                card.dataset.search || card.textContent
            );

            const networkStatus = normaliseValue(
                card.dataset.networkStatus
            );

            const trustStatus = normaliseValue(
                card.dataset.trustStatus
            );

            const matchesSearch =
                !searchValue ||
                searchableText.includes(searchValue);

            const matchesStatus =
                selectedStatus === "all" ||
                networkStatus === selectedStatus;

            const matchesTrust =
                selectedTrust === "all" ||
                trustStatus === selectedTrust;

            const shouldShow =
                matchesSearch &&
                matchesStatus &&
                matchesTrust;

            card.hidden = !shouldShow;

            if (shouldShow) {
                visibleCount += 1;
            }
        });

        resultsCount.textContent =
            `${visibleCount} ${visibleCount === 1 ? "asset" : "assets"} shown`;

        if (emptyState) {
            emptyState.hidden = visibleCount !== 0;
        }
    }

    function clearFilters() {
        searchInput.value = "";
        statusFilter.value = "all";
        trustFilter.value = "all";

        updateAssetVisibility();
        searchInput.focus();
    }

    searchInput.addEventListener(
        "input",
        updateAssetVisibility
    );

    statusFilter.addEventListener(
        "change",
        updateAssetVisibility
    );

    trustFilter.addEventListener(
        "change",
        updateAssetVisibility
    );

    clearButton.addEventListener(
        "click",
        clearFilters
    );

    updateAssetVisibility();
});