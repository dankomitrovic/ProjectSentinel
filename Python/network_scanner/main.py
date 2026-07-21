"""
Project Sentinel main application.

This file coordinates the Sentinel modules.

Processing pipeline:

Prepare files
    ↓
Load previous state
    ↓
Scan network
    ↓
Load trusted and pending inventories
    ↓
Classify devices
    ↓
Add unknown devices to pending review
    ↓
Update permanent device registry
    ↓
Detect network changes
    ↓
Calculate security summary
    ↓
Display detailed results
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

    display_banner()

    # Ensure all required folders and CSV files exist.
    ensure_data_files()

    # Load the previous network state before replacing it.
    previous_devices = load_latest_scan()

    print()
    print("Scanning network...")

    # Discover devices currently visible on the network.
    current_devices = discover_devices()

    # Load approved and pending device inventories.
    trusted_devices = load_trusted_devices()
    pending_mac_addresses = load_pending_mac_addresses()

    # Classify each visible device.
    classified_devices = classify_devices(
        current_devices,
        trusted_devices,
        pending_mac_addresses
    )

    # Place genuinely unknown devices into pending review.
    # Nothing is trusted automatically.
    added_count = save_unknown_devices_to_pending(
        classified_devices,
        pending_mac_addresses
    )

    # Load Sentinel's permanent device memory.
    device_registry = load_device_registry()

    # Update registry timestamps, status, risk and observation counts.
    updated_registry = update_device_registry(
        classified_devices,
        device_registry
    )

    # Save the updated registry.
    save_device_registry(updated_registry)

    # Compare the previous and current network states.
    new_devices, missing_devices = compare_scans(
        previous_devices,
        current_devices
    )

    # Display the high-level security position first.
    display_security_summary(
        classified_devices,
        updated_registry,
        new_devices,
        missing_devices
    )

    # Display detailed findings after the summary.
    display_devices(classified_devices)
    display_changes(new_devices, missing_devices)
    display_pending_result(added_count)

    # Save the current state after all comparisons are complete.
    save_latest_scan(current_devices)
    save_scan_history(current_devices)

    print()
    print("=" * 60)
    print("Sentinel monitoring cycle complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()