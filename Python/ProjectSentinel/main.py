"""
Project Sentinel main monitoring workflow.
"""

from behaviour_analyzer import analyse_device_behaviours
from config import LATEST_SNAPSHOT_FILE
from detection import compare_scans
from device_intelligence import enrich_devices
from events import record_event
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
from snapshot import save_snapshot
from storage import (
    ensure_data_files,
    load_latest_scan,
    save_latest_scan,
    save_scan_history
)


def normalise_mac_address(mac_address):
    """Return a consistently formatted lowercase MAC address."""

    return str(mac_address).strip().lower()


def build_event_device(device, registry_record=None):
    """Build a complete device record for an event."""

    event_device = dict(device)

    if registry_record is None:
        return event_device

    event_device["friendly_name"] = registry_record.get(
        "friendly_name",
        event_device.get("friendly_name", "")
    )
    event_device["ip_address"] = registry_record.get(
        "current_ip",
        event_device.get("ip_address", "")
    )
    event_device["status"] = registry_record.get(
        "status",
        event_device.get("status", "UNKNOWN")
    )
    event_device["owner"] = registry_record.get(
        "owner",
        event_device.get("owner", "")
    )
    event_device["device_type"] = registry_record.get(
        "device_type",
        event_device.get("device_type", "")
    )
    event_device["risk_score"] = registry_record.get(
        "risk_score",
        event_device.get("risk_score", 0)
    )
    event_device["risk_reasons"] = registry_record.get(
        "risk_reasons",
        event_device.get("risk_reasons", "")
    )
    event_device["notes"] = registry_record.get(
        "notes",
        event_device.get("notes", "")
    )

    return event_device


def record_monitoring_events(
    analysed_devices,
    previous_registry,
    updated_registry,
    new_devices,
    missing_devices
):
    """Convert important monitoring results into persistent events."""

    analysed_by_mac = {
        normalise_mac_address(device.get("mac_address", "")): device
        for device in analysed_devices
    }

    for device in new_devices:
        mac_address = normalise_mac_address(
            device.get("mac_address", "")
        )

        analysed_device = analysed_by_mac.get(
            mac_address,
            device
        )

        current_registry_record = updated_registry.get(
            mac_address
        )

        event_device = build_event_device(
            analysed_device,
            current_registry_record
        )

        record_event(
            event_type="DEVICE_DISCOVERED",
            severity="MEDIUM",
            message="Device became visible on the monitored network.",
            device=event_device,
            metadata={
                "status": event_device.get(
                    "status",
                    "UNKNOWN"
                ),
                "vendor": event_device.get(
                    "vendor",
                    "Unknown"
                ),
                "detected_device_type": event_device.get(
                    "detected_device_type",
                    "Unknown"
                ),
                "risk_score": event_device.get(
                    "risk_score",
                    0
                )
            }
        )

    for device in missing_devices:
        mac_address = normalise_mac_address(
            device.get("mac_address", "")
        )

        previous_registry_record = previous_registry.get(
            mac_address
        )

        event_device = build_event_device(
            device,
            previous_registry_record
        )

        record_event(
            event_type="DEVICE_MISSING",
            severity="LOW",
            message=(
                "Device is no longer visible on the monitored network."
            ),
            device=event_device,
            metadata={
                "previous_ip": device.get(
                    "ip_address",
                    device.get("current_ip", "")
                )
            }
        )

    for device in analysed_devices:
        mac_address = normalise_mac_address(
            device.get("mac_address", "")
        )

        current_registry_record = updated_registry.get(
            mac_address
        )

        event_device = build_event_device(
            device,
            current_registry_record
        )

        behaviour = device.get(
            "behaviour_analysis",
            {}
        )

        behaviour_status = behaviour.get(
            "behaviour_status",
            ""
        )

        if behaviour_status not in {
            "",
            "UNCHANGED",
            "NO_REGISTRY_RECORD",
            "UNAVAILABLE"
        }:
            record_event(
                event_type="BEHAVIOUR_CHANGED",
                severity="HIGH",
                message=(
                    "Device service behaviour changed from its baseline."
                ),
                device=event_device,
                metadata={
                    "behaviour_status": behaviour_status,
                    "new_services": behaviour.get(
                        "new_services",
                        []
                    ),
                    "missing_services": behaviour.get(
                        "missing_services",
                        []
                    ),
                    "change_count": behaviour.get(
                        "change_count",
                        0
                    )
                }
            )

        new_services = behaviour.get(
            "new_services",
            []
        )

        missing_services = behaviour.get(
            "missing_services",
            []
        )

        if new_services or missing_services:
            record_event(
                event_type="SERVICE_CHANGED",
                severity=(
                    "HIGH"
                    if new_services
                    else "MEDIUM"
                ),
                message=(
                    "Detected a change in the device's exposed services."
                ),
                device=event_device,
                metadata={
                    "new_services": new_services,
                    "missing_services": missing_services
                }
            )

        previous_registry_record = previous_registry.get(
            mac_address
        )

        if (
            previous_registry_record is not None
            and current_registry_record is not None
        ):
            previous_risk = int(
                previous_registry_record.get(
                    "risk_score",
                    0
                )
            )

            current_risk = int(
                current_registry_record.get(
                    "risk_score",
                    previous_risk
                )
            )

            if previous_risk != current_risk:
                risk_change = current_risk - previous_risk
                severity = "MEDIUM"

                if current_risk >= 70 or risk_change >= 20:
                    severity = "HIGH"

                elif risk_change < 0:
                    severity = "LOW"

                record_event(
                    event_type="RISK_CHANGED",
                    severity=severity,
                    message=(
                        f"Device risk score changed from "
                        f"{previous_risk} to {current_risk}."
                    ),
                    device=event_device,
                    metadata={
                        "previous_risk_score": previous_risk,
                        "current_risk_score": current_risk,
                        "change": risk_change
                    }
                )


def main():
    """Run one complete Project Sentinel monitoring cycle."""

    initialise_logger()
    display_banner()
    log_info("Initialising Project Sentinel")

    ensure_data_files()

    record_event(
        event_type="SCAN_STARTED",
        severity="INFO",
        message="Sentinel monitoring cycle started."
    )

    previous_devices = load_latest_scan()

    discovered_devices = discover_devices()

    enriched_devices = enrich_devices(
        discovered_devices
    )

    current_devices = scan_devices(
        enriched_devices
    )

    trusted_devices = load_trusted_devices()
    pending_mac_addresses = load_pending_mac_addresses()

    classified_devices = classify_devices(
        current_devices,
        trusted_devices,
        pending_mac_addresses
    )

    added_count = save_unknown_devices_to_pending(
        classified_devices,
        pending_mac_addresses
    )

    device_registry = load_device_registry()

    analysed_devices = analyse_device_behaviours(
        classified_devices,
        device_registry
    )

    updated_registry = update_device_registry(
        analysed_devices,
        device_registry
    )

    save_device_registry(
        updated_registry
    )

    new_devices, missing_devices = compare_scans(
        previous_devices,
        current_devices
    )

    record_monitoring_events(
        analysed_devices,
        device_registry,
        updated_registry,
        new_devices,
        missing_devices
    )

    display_security_summary(
        analysed_devices,
        updated_registry,
        new_devices,
        missing_devices
    )

    display_devices(
        analysed_devices
    )

    display_changes(
        new_devices,
        missing_devices
    )

    display_pending_result(
        added_count
    )

    save_snapshot(
        analysed_devices,
        updated_registry,
        new_devices,
        missing_devices,
        LATEST_SNAPSHOT_FILE
    )

    save_latest_scan(
        current_devices
    )

    save_scan_history(
        current_devices
    )

    record_event(
        event_type="SCAN_COMPLETED",
        severity="INFO",
        message="Sentinel monitoring cycle completed successfully.",
        metadata={
            "devices_visible": len(analysed_devices),
            "new_devices": len(new_devices),
            "missing_devices": len(missing_devices),
            "pending_devices_added": added_count
        }
    )

    log_info(
        "Sentinel monitoring cycle completed"
    )

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()