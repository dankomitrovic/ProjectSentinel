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
Load trusted and pending inventories
    ↓
Classify visible devices
    ↓
Add unknown devices to pending review
    ↓
Update permanent device registry
    ↓
Detect network changes
    ↓
Display security findings
    ↓
Save current state and history
"""

from detection import compare_scans

from inventory import (
    classify_devices,
    load_pending_mac_addresses,
    load_trusted_devices,
    save_unknown_devices_to_pending
)

from logger import (
    initialise_logger,
    log_debug,
    log_info,
    log_warning
)

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
    log_info("Verifying application data storage")
    ensure_data_files()
    log_debug("Required data folders and CSV files verified")

    # Load the previous network state before replacing it.
    log_info("Loading previous network state")
    previous_devices = load_latest_scan()
    log_debug(
        f"Previous network state loaded with "
        f"{len(previous_devices)} device record(s)"
    )

    # Discover devices currently visible on the network.
    log_info("Starting network discovery scan")
    current_devices = discover_devices()

    if current_devices:
        log_info(
            f"Network scan completed with "
            f"{len(current_devices)} visible device(s)"
        )
    else:
        log_warning("Network scan completed with no visible devices")

    # Load approved and pending device inventories.
    log_info("Loading device inventories")
    trusted_devices = load_trusted_devices()
    pending_mac_addresses = load_pending_mac_addresses()

    log_debug(
        f"Loaded {len(trusted_devices)} trusted device record(s)"
    )
    log_debug(
        f"Loaded {len(pending_mac_addresses)} pending MAC address(es)"
    )

    # Classify each currently visible device.
    classified_devices = classify_devices(
        current_devices,
        trusted_devices,
        pending_mac_addresses
    )

    log_debug(
        f"Classified {len(classified_devices)} visible device(s)"
    )

    # Place genuinely unknown devices into pending review.
    # Sentinel never trusts a device automatically.
    added_count = save_unknown_devices_to_pending(
        classified_devices,
        pending_mac_addresses
    )

    if added_count > 0:
        log_warning(
            f"{added_count} unknown device(s) added to pending review"
        )
    else:
        log_debug("No unknown devices required addition to pending review")

    # Load Sentinel's permanent device memory.
    log_info("Updating permanent device registry")
    device_registry = load_device_registry()

    log_debug(
        f"Loaded {len(device_registry)} permanent registry record(s)"
    )

    # Update registry timestamps, status, risk and observation counts.
    updated_registry = update_device_registry(
        classified_devices,
        device_registry
    )

    save_device_registry(updated_registry)

    log_debug(
        f"Saved {len(updated_registry)} permanent registry record(s)"
    )

    # Compare previous and current network states.
    log_info("Checking for network changes")

    new_devices, missing_devices = compare_scans(
        previous_devices,
        current_devices
    )

    log_debug(
        f"Detected {len(new_devices)} newly visible device(s)"
    )
    log_debug(
        f"Detected {len(missing_devices)} device(s) no longer visible"
    )

    if new_devices or missing_devices:
        log_warning(
            f"Network changes detected: "
            f"{len(new_devices)} new and "
            f"{len(missing_devices)} missing device(s)"
        )
    else:
        log_info("No network changes detected")

    # Present the high-level security position first.
    display_security_summary(
        classified_devices,
        updated_registry,
        new_devices,
        missing_devices
    )

    # Present detailed findings after the summary.
    display_devices(classified_devices)
    display_changes(new_devices, missing_devices)
    display_pending_result(added_count)

    # Save the current state only after all comparisons are complete.
    log_info("Saving current network state")
    save_latest_scan(current_devices)
    save_scan_history(current_devices)

    log_debug("Latest scan and historical scan records saved")
    log_info("Sentinel monitoring cycle completed")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()