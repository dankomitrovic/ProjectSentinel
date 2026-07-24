"""
Project Sentinel JSON snapshot engine.

This module creates a structured snapshot of the latest completed
monitoring cycle.

The snapshot becomes the shared data source for the REST API,
dashboard, reports and future integrations.
"""

import json
import os
from datetime import datetime

from logger import log_debug, log_info
from reporting import (
    count_behaviour_results,
    count_service_statuses,
    determine_overall_risk
)


def build_security_summary(
    devices,
    updated_registry,
    new_devices,
    missing_devices
):
    """
    Build the structured security summary for one monitoring cycle.
    """

    trusted_count = 0
    pending_count = 0
    unknown_count = 0

    for device in devices:
        status = device.get(
            "status",
            "UNKNOWN"
        )

        if status == "TRUSTED":
            trusted_count += 1

        elif status == "PENDING":
            pending_count += 1

        else:
            unknown_count += 1

    service_counts = count_service_statuses(
        devices
    )

    behaviour_counts = count_behaviour_results(
        devices
    )

    candidate_service_count = (
        service_counts["OPEN"]
        + service_counts["PROBABLE"]
        + service_counts["UNVERIFIED"]
    )

    highest_device_risk = 0

    for device in devices:
        mac_address = device.get(
            "mac_address",
            ""
        ).lower()

        registry_record = updated_registry.get(
            mac_address,
            {}
        )

        risk_score = registry_record.get(
            "risk_score",
            0
        )

        if risk_score > highest_device_risk:
            highest_device_risk = risk_score

    overall_risk = determine_overall_risk(
        pending_count,
        unknown_count,
        len(new_devices),
        len(missing_devices),
        highest_device_risk,
        behaviour_counts["CHANGED"]
    )

    return {
        "devices_visible": len(devices),
        "trusted_devices": trusted_count,
        "pending_devices": pending_count,
        "unknown_devices": unknown_count,
        "candidate_services": candidate_service_count,
        "confirmed_open_services": service_counts["OPEN"],
        "probable_services": service_counts["PROBABLE"],
        "unverified_services": service_counts["UNVERIFIED"],
        "behaviour_changed": behaviour_counts["CHANGED"],
        "behaviour_unchanged": behaviour_counts["UNCHANGED"],
        "comparison_unavailable": behaviour_counts["UNAVAILABLE"],
        "new_services": behaviour_counts["NEW_SERVICES"],
        "missing_services": behaviour_counts["MISSING_SERVICES"],
        "changed_services": behaviour_counts["CHANGED_SERVICES"],
        "total_service_changes": behaviour_counts["TOTAL_CHANGES"],
        "newly_visible_devices": len(new_devices),
        "no_longer_visible_devices": len(missing_devices),
        "highest_device_risk": highest_device_risk,
        "overall_risk": overall_risk
    }


def attach_registry_risk(devices, updated_registry):
    """
    Copy each device's registry risk information into its snapshot record.

    New dictionaries are returned so the monitoring-cycle records are
    not modified solely for snapshot generation.
    """

    snapshot_devices = []

    for device in devices:
        snapshot_device = dict(device)

        mac_address = str(
            device.get("mac_address", "")
        ).lower()

        registry_record = updated_registry.get(
            mac_address,
            {}
        )

        snapshot_device["risk_score"] = (
            registry_record.get(
                "risk_score",
                0
            )
        )

        snapshot_device["risk_reasons"] = (
            registry_record.get(
                "risk_reasons",
                []
            )
        )

        snapshot_devices.append(
            snapshot_device
        )

    return snapshot_devices


def create_snapshot(
    devices,
    updated_registry,
    new_devices,
    missing_devices
):
    """
    Create a complete structured monitoring-cycle snapshot.
    """

    timestamp = datetime.now().astimezone().isoformat(
        timespec="seconds"
    )

    summary = build_security_summary(
        devices,
        updated_registry,
        new_devices,
        missing_devices
    )

    snapshot_devices = attach_registry_risk(
        devices,
        updated_registry
    )

    return {
        "generated_at": timestamp,
        "application": {
            "name": "Project Sentinel",
            "snapshot_version": 1
        },
        "summary": summary,
        "devices": snapshot_devices,
        "network_changes": {
            "new_devices": new_devices,
            "missing_devices": missing_devices
        }
    }


def save_snapshot(
    devices,
    updated_registry,
    new_devices,
    missing_devices,
    file_path
):
    """
    Save the latest monitoring-cycle snapshot as formatted JSON.

    The temporary-file replacement prevents the API from reading a
    partially written snapshot.
    """

    snapshot = create_snapshot(
        devices,
        updated_registry,
        new_devices,
        missing_devices
    )

    directory = os.path.dirname(
        file_path
    )

    if directory:
        os.makedirs(
            directory,
            exist_ok=True
        )

    temporary_path = f"{file_path}.tmp"

    with open(
        temporary_path,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            snapshot,
            file,
            indent=4,
            ensure_ascii=False
        )

    os.replace(
        temporary_path,
        file_path
    )

    log_info(
        f"Saved latest Sentinel snapshot to {file_path}"
    )

    log_debug(
        f"Snapshot contains "
        f"{len(snapshot['devices'])} device record(s)"
    )

    return snapshot
