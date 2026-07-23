"""
Project Sentinel main application.

This module coordinates one complete Sentinel monitoring cycle.

Processing pipeline:

Initialise application
    ↓
Prepare data storage
    ↓
Load previous state
    ↓
Scan network
    ↓
Enrich discovered devices
    ↓
Discover and validate TCP services
    ↓
Load trusted and pending inventories
    ↓
Classify visible devices
    ↓
Add unknown devices to pending review
    ↓
Load permanent device registry
    ↓
Compare current services with established baselines
    ↓
Update permanent device registry
    ↓
Detect network changes
    ↓
Display security findings
    ↓
Save current state and history
"""

from behaviour_analyzer import analyse_device_behaviours

from detection import compare_scans

from device_intelligence import enrich_devices

from inventory import (
    classify_devices,
    load_pending_mac_addresses,
    load_trusted_devices,
    save_unknown_devices_to_pending
)

from logger import initialise_logger, log_info

from registry import (
    load_device_registry,
    save_device_registry,
    update_device_registry
)

from reporting import (
    display_banner,
    display_changes,
    display_devices,
    display_pending_result,
    display_security_summary
)

from scanner import discover_devices
from service_scanner import scan_devices

from storage import (
    ensure_data_files,
    load_latest_scan,
    save_latest_scan,
    save_scan_history
)


def main():
    """
    Run one complete Project Sentinel monitoring cycle.
    """

    # Prepare persistent logging before other application work begins.
    initialise_logger()

    # Display Sentinel's application identity.
    display_banner()

    log_info("Initialising Project Sentinel")

    # Ensure all required folders and CSV files exist.
    ensure_data_files()

    # Load the previous network state before replacing it.
    previous_devices = load_latest_scan()

    # Discover devices currently visible on the network.
    discovered_devices = discover_devices()

    # Add device-intelligence information such as vendor,
    # hostname and basic device-type fingerprinting.
    enriched_devices = enrich_devices(discovered_devices)

    # Discover and validate selected TCP services on each local device.
    current_devices = scan_devices(enriched_devices)

    # Load approved and pending device inventories.
    trusted_devices = load_trusted_devices()
    pending_mac_addresses = load_pending_mac_addresses()

    # Classify each currently visible device.
    classified_devices = classify_devices(
        current_devices,
        trusted_devices,
        pending_mac_addresses
    )

    # Place genuinely unknown devices into pending review.
    # Sentinel never trusts a device automatically.
    added_count = save_unknown_devices_to_pending(
        classified_devices,
        pending_mac_addresses
    )

    # Load Sentinel's permanent device memory before behavioural analysis.
    #
    # Behavioural comparison must occur before the registry is updated.
    # Otherwise Sentinel could overwrite or establish a baseline before
    # comparing the current services against the previously known state.
    device_registry = load_device_registry()

    # Compare current service exposure against each device's established
    # service baseline. Results are added to the classified device records.
    analysed_devices = analyse_device_behaviours(
        classified_devices,
        device_registry
    )

    # Update Sentinel's permanent memory only after behavioural comparison.
    #
    # Existing service baselines remain unchanged. Devices without a
    # baseline receive their initial baseline during this update.
    updated_registry = update_device_registry(
        analysed_devices,
        device_registry
    )

    save_device_registry(updated_registry)

    # Compare previous and current network-presence states.
    new_devices, missing_devices = compare_scans(
        previous_devices,
        current_devices
    )

    # Present the high-level security position first.
    display_security_summary(
        analysed_devices,
        updated_registry,
        new_devices,
        missing_devices
    )

    # Present detailed findings after the summary.
    display_devices(analysed_devices)
    display_changes(new_devices, missing_devices)
    display_pending_result(added_count)

    # Save the enriched current state only after comparisons are complete.
    save_latest_scan(current_devices)
    save_scan_history(current_devices)

    log_info("Sentinel monitoring cycle completed")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()