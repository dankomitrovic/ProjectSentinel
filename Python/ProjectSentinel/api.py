import json
import os
from datetime import datetime
from threading import Event, Lock, Thread

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    url_for
)

from config import LATEST_SNAPSHOT_FILE
from events import get_device_events, get_recent_events, record_event
from exposure_intelligence import build_exposure_intelligence
from change_intelligence import build_change_intelligence
from inventory import (
    approve_device as approve_inventory_device,
    remove_trusted_device as remove_inventory_trust
)
from main import main as run_monitoring_cycle
from registry import load_device_registry
from sensor_intelligence import build_sensor_intelligence
from sensor_store import (
    list_agents,
    recent_telemetry,
    record_checkin,
    register_agent,
    sensor_summary
)


app = Flask(__name__)

scan_lock = Lock()
scan_state_lock = Lock()
snapshot_write_lock = Lock()

scan_state = {
    "status": "idle",
    "message": "Sentinel is ready.",
    "started_at": None,
    "completed_at": None,
    "device_count": None,
    "error": None
}

monitor_state_lock = Lock()
monitor_stop_event = Event()
monitor_thread = None
monitor_state = {
    "enabled": False,
    "status": "stopped",
    "message": "Live monitoring is stopped.",
    "interval_seconds": 60,
    "started_at": None,
    "last_cycle_at": None,
    "next_cycle_at": None,
    "cycles_completed": 0,
    "last_error": None
}


def current_timestamp():
    """
    Return the current time in ISO 8601 format.
    """

    return datetime.now().astimezone().isoformat(
        timespec="seconds"
    )


def normalise_mac_address(mac_address):
    """
    Return a consistently formatted lowercase MAC address.
    """

    return str(mac_address).strip().lower()




def parse_event_timestamp(value):
    """Return a datetime for an event timestamp when possible."""

    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return None


def normalise_risk_reasons(value):
    """Return risk reasons as a clean list for the device page."""

    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]

    if isinstance(value, str):
        normalised_value = value.replace(";", "\n")
        return [
            item.strip(" -•\t")
            for item in normalised_value.splitlines()
            if item.strip(" -•\t")
        ]

    if value:
        return [str(value)]

    return []


def build_device_intelligence(device, device_events):
    """Build presentation-ready intelligence from snapshot and events."""

    chronological_events = sorted(
        device_events,
        key=lambda event: event.get("timestamp", "")
    )

    timestamps = [
        parse_event_timestamp(event.get("timestamp"))
        for event in chronological_events
    ]
    timestamps = [value for value in timestamps if value is not None]

    first_seen = timestamps[0].isoformat(timespec="seconds") if timestamps else None
    last_seen = timestamps[-1].isoformat(timespec="seconds") if timestamps else None

    sighting_types = {
        "DEVICE_DISCOVERED",
        "DEVICE_RETURNED",
        "DEVICE_SEEN",
        "DEVICE_ONLINE"
    }
    sightings = sum(
        1
        for event in chronological_events
        if str(event.get("type", "")).upper() in sighting_types
    )

    if sightings == 0 and device_events:
        sightings = 1

    behaviour = device.get("behaviour_analysis", {}) or {}
    current_services = device.get("open_ports", []) or []
    new_services = behaviour.get("new_services", []) or []
    missing_services = behaviour.get("missing_services", []) or []

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for event in device_events:
        severity = str(event.get("severity", "INFO")).upper()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    return {
        "first_seen": first_seen,
        "last_seen": last_seen,
        "sightings": sightings,
        "event_count": len(device_events),
        "current_service_count": len(current_services),
        "new_service_count": len(new_services),
        "missing_service_count": len(missing_services),
        "risk_reasons": normalise_risk_reasons(
            device.get("risk_reasons", [])
        ),
        "severity_counts": severity_counts
    }



def build_asset_intelligence(device, device_events, intelligence):
    """Build a practical v1.1.0 asset profile from saved Sentinel data."""

    device_type = str(
        device.get("device_type")
        or device.get("detected_device_type")
        or "Unknown"
    ).strip()
    vendor = str(device.get("vendor") or "Unknown").strip()
    hostname = str(device.get("hostname") or "Unknown").strip()
    status = str(device.get("status") or "UNKNOWN").upper()
    behaviour = device.get("behaviour_analysis", {}) or {}
    behaviour_status = str(
        behaviour.get("behaviour_status") or "UNKNOWN"
    ).upper()
    risk_score = max(0, min(100, int(device.get("risk_score", 0) or 0)))
    ports = {
        int(service.get("port", 0) or 0)
        for service in (device.get("open_ports", []) or [])
        if str(service.get("port", "")).isdigit()
    }

    profile_text = " ".join([device_type, vendor, hostname]).lower()
    if any(term in profile_text for term in ("iphone", "ipad", "apple mobile")):
        operating_system = "Apple iOS / iPadOS"
        os_confidence = "Medium"
    elif any(term in profile_text for term in ("android", "samsung", "pixel", "galaxy")):
        operating_system = "Android"
        os_confidence = "Medium"
    elif any(term in profile_text for term in ("windows", "microsoft", "desktop", "workstation", "pc-")) or 3389 in ports:
        operating_system = "Microsoft Windows"
        os_confidence = "Medium"
    elif any(term in profile_text for term in ("macbook", "imac", "mac os", "macos")):
        operating_system = "Apple macOS"
        os_confidence = "Medium"
    elif any(term in profile_text for term in ("linux", "ubuntu", "raspberry", "debian")) or 22 in ports:
        operating_system = "Linux or Unix-like"
        os_confidence = "Low"
    elif device_type.lower() in {"infrastructure", "router", "switch", "access point"}:
        operating_system = "Embedded network operating system"
        os_confidence = "Medium"
    elif device_type.lower() in {"smart tv", "camera", "printer", "iot"}:
        operating_system = "Embedded device firmware"
        os_confidence = "Medium"
    else:
        operating_system = "Not identified"
        os_confidence = "Low"

    role_map = {
        "infrastructure": "Network infrastructure",
        "router": "Network gateway",
        "switch": "Network infrastructure",
        "access point": "Wireless infrastructure",
        "printer": "Shared peripheral",
        "camera": "Security / surveillance",
        "smart tv": "Media and entertainment",
        "phone": "Personal mobile device",
        "mobile phone": "Personal mobile device",
        "computer": "User endpoint",
        "laptop": "User endpoint",
        "desktop": "User endpoint",
        "nas": "Network storage",
    }
    asset_role = role_map.get(device_type.lower(), "General network asset")

    health_score = 100 - risk_score
    if status == "TRUSTED":
        health_score += 8
    elif status in {"PENDING", "UNKNOWN", "UNTRUSTED"}:
        health_score -= 8
    if behaviour_status == "CHANGED":
        health_score -= 12
    elif behaviour_status in {"NORMAL", "STABLE"}:
        health_score += 4
    if intelligence.get("new_service_count", 0):
        health_score -= min(15, intelligence["new_service_count"] * 5)
    health_score = max(0, min(100, health_score))

    if health_score >= 85:
        health_label = "Healthy"
    elif health_score >= 65:
        health_label = "Needs attention"
    elif health_score >= 40:
        health_label = "At risk"
    else:
        health_label = "High concern"

    confidence = str(device.get("detection_confidence") or "Low").title()
    confidence_points = {"High": 90, "Medium": 70, "Low": 40}.get(confidence, 40)

    recommendations = []
    if status != "TRUSTED":
        recommendations.append("Confirm ownership and approve only if the device is expected.")
    if behaviour_status == "CHANGED":
        recommendations.append("Review the newly detected or missing network services.")
    if 23 in ports:
        recommendations.append("Disable Telnet and use an encrypted management protocol.")
    if 21 in ports:
        recommendations.append("Confirm whether FTP is required and restrict access where possible.")
    if not recommendations:
        recommendations.append("Continue routine monitoring and keep device software updated.")

    return {
        "asset_role": asset_role,
        "operating_system": operating_system,
        "os_confidence": os_confidence,
        "health_score": health_score,
        "health_label": health_label,
        "identity_confidence": confidence,
        "identity_confidence_score": confidence_points,
        "activity_state": "Recently observed" if intelligence.get("last_seen") else "No recorded activity",
        "recommendations": recommendations,
        "profile_summary": (
            f"{asset_role} identified as {device_type}. "
            f"Sentinel currently rates this asset as {health_label.lower()}."
        )
    }


def build_investigation_context(device, device_events):
    """Build analyst-oriented investigation guidance for one device."""

    score = int(device.get("risk_score", 0) or 0)
    status = str(device.get("status", "UNKNOWN")).upper()
    behaviour = device.get("behaviour_analysis", {}) or {}
    behaviour_status = str(
        behaviour.get("behaviour_status", "UNKNOWN")
    ).upper()
    services = device.get("open_ports", []) or []
    service_ports = {
        int(service.get("port", 0) or 0)
        for service in services
        if str(service.get("port", "")).isdigit()
    }

    if score >= 90:
        risk_band = "CRITICAL"
        investigation_status = "Immediate investigation"
    elif score >= 70:
        risk_band = "HIGH"
        investigation_status = "Priority review"
    elif score >= 40:
        risk_band = "ELEVATED"
        investigation_status = "Analyst review"
    else:
        risk_band = "LOW"
        investigation_status = "Routine monitoring"

    recommendations = []

    if status != "TRUSTED":
        recommendations.append({
            "priority": "HIGH",
            "title": "Confirm the device owner",
            "detail": (
                "Match the IP and MAC address to a known household or lab "
                "device before granting trust."
            )
        })

    if score >= 70:
        recommendations.append({
            "priority": "HIGH",
            "title": "Review before approving",
            "detail": (
                "Keep the device pending until its identity, expected services "
                "and recent behaviour have been confirmed."
            )
        })

    if behaviour_status == "CHANGED":
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Validate the behaviour change",
            "detail": (
                "Confirm whether the new or missing services were caused by "
                "an expected update, configuration change or device restart."
            )
        })

    if service_ports.intersection({139, 445}):
        recommendations.append({
            "priority": "MEDIUM",
            "title": "Verify Windows file-sharing exposure",
            "detail": (
                "Ports 139 or 445 can support NetBIOS and SMB. Confirm file "
                "sharing is required and restrict it when it is not needed."
            )
        })

    if service_ports.intersection({23, 21}):
        recommendations.append({
            "priority": "HIGH",
            "title": "Review legacy remote access",
            "detail": (
                "Telnet or FTP may expose credentials or management access. "
                "Disable the service or replace it with a safer alternative."
            )
        })

    vendor = str(device.get("vendor", "Unknown")).strip()
    if not vendor or vendor.lower() == "unknown":
        recommendations.append({
            "priority": "LOW",
            "title": "Confirm hardware identity",
            "detail": (
                "Compare the MAC address with the label or network settings "
                "on the suspected device."
            )
        })

    if not recommendations:
        recommendations.append({
            "priority": "LOW",
            "title": "Continue routine monitoring",
            "detail": (
                "No urgent analyst action is suggested. Recheck the device "
                "after future scans for changes in services or risk."
            )
        })

    severity_weight = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "INFO": 0
    }
    weighted_event_score = sum(
        severity_weight.get(
            str(event.get("severity", "INFO")).upper(),
            0
        )
        for event in device_events
    )

    exposure = []
    for service in services:
        port = int(service.get("port", 0) or 0)
        if port in {21, 23, 139, 445, 3389, 5900}:
            concern = "Review"
        elif port in {80, 443, 53}:
            concern = "Expected on some devices"
        else:
            concern = "Observe"

        exposure.append({
            "port": port,
            "protocol": service.get("protocol", "TCP"),
            "service": service.get("service", "Unknown"),
            "confidence": service.get("confidence", "Unknown"),
            "status": service.get("status", "Unknown"),
            "concern": concern
        })

    return {
        "risk_band": risk_band,
        "investigation_status": investigation_status,
        "recommendations": recommendations[:5],
        "exposure": exposure,
        "weighted_event_score": weighted_event_score,
        "behaviour_status": behaviour_status,
        "event_types": sorted({
            str(event.get("type", "UNKNOWN")).upper()
            for event in device_events
        }),
        "analyst_note": (
            "Sentinel recommendations are decision support based on passive "
            "network observations. They are not proof of compromise."
        )
    }

def build_soc_dashboard(snapshot):
    """Build presentation-ready Security Operations Centre intelligence."""

    summary = snapshot.get("summary", {}) or {}
    devices = snapshot.get("devices", []) or []
    recent_events = get_recent_events(limit=100)

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for event in recent_events:
        severity = str(event.get("severity", "INFO")).upper()
        if severity in severity_counts:
            severity_counts[severity] += 1

    actionable_events = [
        event
        for event in recent_events
        if str(event.get("severity", "INFO")).upper()
        in {"CRITICAL", "HIGH", "MEDIUM"}
    ]

    risky_devices = sorted(
        devices,
        key=lambda device: int(device.get("risk_score", 0) or 0),
        reverse=True
    )

    highest_risk_device = risky_devices[0] if risky_devices else None
    pending_devices = int(summary.get("pending_devices", 0) or 0)
    changed_devices = int(summary.get("behaviour_changed", 0) or 0)
    critical_high = severity_counts["CRITICAL"] + severity_counts["HIGH"]

    active_concerns = critical_high + pending_devices + changed_devices

    risk_score = int(summary.get("highest_device_risk", 0) or 0)
    posture_penalty = min(
        85,
        (severity_counts["CRITICAL"] * 8)
        + min(24, severity_counts["HIGH"] * 2)
        + min(15, severity_counts["MEDIUM"])
        + min(18, pending_devices)
        + min(15, changed_devices * 3)
        + max(0, (risk_score - 50) // 2)
    )
    posture_score = max(15, 100 - posture_penalty)

    if severity_counts["CRITICAL"] > 0 or risk_score >= 90:
        threat_level = "CRITICAL"
        threat_message = "Immediate investigation is required."
    elif severity_counts["HIGH"] > 0 or risk_score >= 70:
        threat_level = "HIGH"
        threat_message = "Significant security concerns need review."
    elif actionable_events or risk_score >= 40 or pending_devices > 0:
        threat_level = "ELEVATED"
        threat_message = "Sentinel has identified items requiring attention."
    else:
        threat_level = "LOW"
        threat_message = "No urgent security concerns are currently visible."

    if highest_risk_device:
        highest_concern = {
            "name": (
                highest_risk_device.get("friendly_name")
                or highest_risk_device.get("hostname")
                or "Unknown Device"
            ),
            "mac_address": highest_risk_device.get("mac_address", ""),
            "ip_address": highest_risk_device.get("ip_address", "Unknown"),
            "status": highest_risk_device.get("status", "UNKNOWN"),
            "risk_score": highest_risk_device.get("risk_score", 0),
            "risk_reasons": normalise_risk_reasons(
                highest_risk_device.get("risk_reasons", [])
            )[:3]
        }
    else:
        highest_concern = None

    return {
        "threat_level": threat_level,
        "threat_message": threat_message,
        "posture_score": posture_score,
        "active_concerns": active_concerns,
        "severity_counts": severity_counts,
        "actionable_event_count": len(actionable_events),
        "recent_events": recent_events[:8],
        "top_risk_devices": risky_devices[:5],
        "highest_concern": highest_concern,
        "asset_counts": {
            "visible": int(summary.get("devices_visible", len(devices)) or 0),
            "trusted": int(summary.get("trusted_devices", 0) or 0),
            "pending": pending_devices,
            "changed": changed_devices
        }
    }


def build_asset_inventory(snapshot):
    """Build a permanent asset inventory from the registry and latest scan."""

    registry = load_device_registry()
    visible_devices = {}

    for device in snapshot.get("devices", []):
        mac_address = normalise_mac_address(
            device.get("mac_address", "")
        )

        if mac_address:
            visible_devices[mac_address] = device

    assets = []

    for mac_address, registry_record in registry.items():
        current_device = visible_devices.get(mac_address, {})
        is_online = mac_address in visible_devices

        friendly_name = registry_record.get(
            "friendly_name",
            ""
        ).strip()

        hostname = str(
            current_device.get("hostname", "")
        ).strip()

        display_name = friendly_name

        if not display_name or display_name.lower() in {
            "unknown",
            "unknown device"
        }:
            if hostname and hostname.lower() != "unknown":
                display_name = hostname
            else:
                display_name = "Unknown Device"

        device_type = registry_record.get(
            "device_type",
            ""
        ).strip()

        if not device_type or device_type.lower() == "unknown":
            device_type = str(
                current_device.get(
                    "detected_device_type",
                    "Unknown"
                )
            ).strip() or "Unknown"

        status = str(
            registry_record.get("status", "UNKNOWN")
        ).upper()

        assets.append({
            "mac_address": mac_address,
            "ip_address": (
                current_device.get("ip_address")
                or registry_record.get("current_ip")
                or "Unknown"
            ),
            "display_name": display_name,
            "friendly_name": friendly_name,
            "hostname": hostname or "Unknown",
            "vendor": str(
                current_device.get("vendor", "Unknown")
            ).strip() or "Unknown",
            "device_type": device_type,
            "detected_device_type": str(
                current_device.get(
                    "detected_device_type",
                    "Unknown"
                )
            ).strip() or "Unknown",
            "owner": registry_record.get("owner", ""),
            "notes": registry_record.get("notes", ""),
            "trust_status": status,
            "risk_score": registry_record.get("risk_score", 0),
            "first_seen": registry_record.get("first_seen", ""),
            "last_seen": registry_record.get("last_seen", ""),
            "times_seen": registry_record.get("times_seen", 0),
            "online": is_online,
            "network_status": "ONLINE" if is_online else "OFFLINE"
        })

    assets.sort(
        key=lambda asset: (
            not asset["online"],
            asset["display_name"].lower(),
            asset["ip_address"]
        )
    )

    summary = {
        "total_assets": len(assets),
        "online_assets": sum(1 for asset in assets if asset["online"]),
        "offline_assets": sum(1 for asset in assets if not asset["online"]),
        "trusted_assets": sum(
            1
            for asset in assets
            if asset["trust_status"] == "TRUSTED"
        ),
        "pending_assets": sum(
            1
            for asset in assets
            if asset["trust_status"] == "PENDING"
        )
    }

    return assets, summary


def load_snapshot():
    """
    Load Sentinel's latest saved snapshot.
    """

    if not os.path.exists(LATEST_SNAPSHOT_FILE):
        return None, "Snapshot file does not exist."

    try:
        with open(
            LATEST_SNAPSHOT_FILE,
            "r",
            encoding="utf-8"
        ) as snapshot_file:
            snapshot = json.load(snapshot_file)

    except (OSError, json.JSONDecodeError) as error:
        return None, f"Unable to load snapshot: {error}"

    return snapshot, None


def save_snapshot(snapshot):
    """
    Save the latest snapshot using a temporary file.
    """

    snapshot_directory = (
        os.path.dirname(LATEST_SNAPSHOT_FILE)
        or "."
    )

    os.makedirs(
        snapshot_directory,
        exist_ok=True
    )

    temporary_file = (
        f"{LATEST_SNAPSHOT_FILE}.tmp"
    )

    with snapshot_write_lock:
        with open(
            temporary_file,
            "w",
            encoding="utf-8"
        ) as snapshot_file:
            json.dump(
                snapshot,
                snapshot_file,
                indent=4
            )

        os.replace(
            temporary_file,
            LATEST_SNAPSHOT_FILE
        )


def update_snapshot_device_inventory(
    mac_address,
    trusted_profile
):
    """
    Update a device in the latest snapshot after approval.

    This allows the page to show TRUSTED immediately without
    requiring another network scan.
    """

    snapshot, error = load_snapshot()

    if error:
        return False

    requested_mac = normalise_mac_address(
        mac_address
    )

    device_updated = False

    for device_record in snapshot.get(
        "devices",
        []
    ):
        device_mac = normalise_mac_address(
            device_record.get(
                "mac_address",
                ""
            )
        )

        if device_mac == requested_mac:
            device_record["status"] = "TRUSTED"
            device_record["friendly_name"] = trusted_profile[
                "friendly_name"
            ]
            device_record["owner"] = trusted_profile[
                "owner"
            ]
            device_record["device_type"] = trusted_profile[
                "device_type"
            ]
            device_record["trust_level"] = trusted_profile[
                "trust_level"
            ]
            device_record["notes"] = trusted_profile[
                "notes"
            ]

            device_updated = True
            break

    if not device_updated:
        return False

    summary = snapshot.get(
        "summary"
    )

    if isinstance(summary, dict):
        trusted_count = 0

        for device_record in snapshot.get(
            "devices",
            []
        ):
            if device_record.get("status") == "TRUSTED":
                trusted_count += 1

        summary["trusted_devices"] = trusted_count

    save_snapshot(
        snapshot
    )

    return True



def remove_snapshot_device_trust(mac_address):
    """Immediately return a snapshot device to pending review."""

    snapshot, error = load_snapshot()

    if error:
        return False

    requested_mac = normalise_mac_address(mac_address)
    device_updated = False

    for device_record in snapshot.get("devices", []):
        device_mac = normalise_mac_address(
            device_record.get("mac_address", "")
        )

        if device_mac == requested_mac:
            device_record["status"] = "PENDING"
            device_record["friendly_name"] = (
                device_record.get("hostname")
                if str(device_record.get("hostname", "")).lower() != "unknown"
                else "Unknown Device"
            )
            device_record["owner"] = ""
            device_record["device_type"] = ""
            device_record["trust_level"] = ""
            device_record["notes"] = ""
            device_updated = True
            break

    if not device_updated:
        return False

    summary = snapshot.get("summary")

    if isinstance(summary, dict):
        summary["trusted_devices"] = sum(
            1
            for device_record in snapshot.get("devices", [])
            if device_record.get("status") == "TRUSTED"
        )
        summary["pending_devices"] = sum(
            1
            for device_record in snapshot.get("devices", [])
            if device_record.get("status") == "PENDING"
        )

    save_snapshot(snapshot)
    return True


def snapshot_error_response(error_message):
    """
    Return a standard response when snapshot data is unavailable.
    """

    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "error",
            "message": error_message
        }
    ), 503


def get_scan_state():
    """
    Return a safe copy of the current scan state.
    """

    with scan_state_lock:
        return dict(scan_state)


def update_scan_state(**changes):
    """
    Update selected values in the current scan state.
    """

    with scan_state_lock:
        scan_state.update(changes)


def execute_background_scan():
    """
    Run one complete Sentinel cycle in a background thread.
    """

    try:
        update_scan_state(
            status="scanning",
            message="Discovering and analysing network devices.",
            started_at=current_timestamp(),
            completed_at=None,
            device_count=None,
            error=None
        )

        run_monitoring_cycle()

        snapshot, snapshot_error = load_snapshot()

        if snapshot_error:
            update_scan_state(
                status="completed",
                message=(
                    "Scan completed, but the latest snapshot "
                    "could not be loaded."
                ),
                completed_at=current_timestamp(),
                device_count=None,
                error=snapshot_error
            )

            return

        device_list = snapshot.get(
            "devices",
            []
        )

        update_scan_state(
            status="completed",
            message="Network scan completed successfully.",
            completed_at=current_timestamp(),
            device_count=len(device_list),
            error=None
        )

    except PermissionError:
        record_event(
            event_type="SCAN_FAILED",
            severity="HIGH",
            message=(
                "Network scan failed because raw socket permission "
                "was denied."
            ),
            metadata={
                "error": "Raw socket permission denied."
            }
        )

        update_scan_state(
            status="failed",
            message=(
                "Sentinel does not have permission to create "
                "the raw network socket required for ARP "
                "discovery."
            ),
            completed_at=current_timestamp(),
            device_count=None,
            error="Raw socket permission denied."
        )

    except Exception as error:
        record_event(
            event_type="SCAN_FAILED",
            severity="HIGH",
            message="The Sentinel network scan failed.",
            metadata={
                "error": str(error)
            }
        )

        app.logger.exception(
            "Sentinel background scan failed"
        )

        update_scan_state(
            status="failed",
            message="The Sentinel network scan failed.",
            completed_at=current_timestamp(),
            device_count=None,
            error=str(error)
        )

    finally:
        scan_lock.release()


def get_monitor_state():
    """Return a safe copy of the live-monitoring state."""

    with monitor_state_lock:
        return dict(monitor_state)


def update_monitor_state(**changes):
    """Update selected live-monitoring state values."""

    with monitor_state_lock:
        monitor_state.update(changes)


def monitoring_worker():
    """Run Sentinel scan cycles until live monitoring is stopped."""

    while not monitor_stop_event.is_set():
        update_monitor_state(
            status="waiting",
            message="Live monitoring is active and preparing the next cycle.",
            next_cycle_at=current_timestamp(),
            last_error=None
        )

        lock_acquired = scan_lock.acquire(blocking=False)

        if lock_acquired:
            update_monitor_state(
                status="scanning",
                message="Live monitoring is scanning the network.",
                next_cycle_at=None
            )

            execute_background_scan()
            current_scan = get_scan_state()
            completed = current_timestamp()

            with monitor_state_lock:
                monitor_state["last_cycle_at"] = completed
                monitor_state["cycles_completed"] += 1
                monitor_state["last_error"] = current_scan.get("error")
                monitor_state["status"] = "waiting"
                monitor_state["message"] = (
                    "Live monitoring is active. The next cycle will run "
                    f"in {monitor_state['interval_seconds']} seconds."
                )
        else:
            update_monitor_state(
                status="waiting",
                message="A manual scan is already running. Live monitoring will retry.",
                last_error=None
            )

        interval = get_monitor_state()["interval_seconds"]
        if monitor_stop_event.wait(interval):
            break

    update_monitor_state(
        enabled=False,
        status="stopped",
        message="Live monitoring is stopped.",
        next_cycle_at=None
    )


def start_monitoring(interval_seconds=60):
    """Start the background live-monitoring worker."""

    global monitor_thread

    interval_seconds = max(15, min(int(interval_seconds), 3600))

    with monitor_state_lock:
        if monitor_state["enabled"]:
            return False

        monitor_state.update({
            "enabled": True,
            "status": "starting",
            "message": "Starting live network monitoring.",
            "interval_seconds": interval_seconds,
            "started_at": current_timestamp(),
            "next_cycle_at": current_timestamp(),
            "last_error": None
        })

    monitor_stop_event.clear()
    monitor_thread = Thread(
        target=monitoring_worker,
        name="sentinel-live-monitor",
        daemon=True
    )
    monitor_thread.start()
    return True


def stop_monitoring():
    """Request a clean stop of the live-monitoring worker."""

    if not get_monitor_state()["enabled"]:
        return False

    update_monitor_state(
        status="stopping",
        message="Stopping live monitoring after the current cycle."
    )
    monitor_stop_event.set()
    return True



def agent_request_authorised():
    """Validate the optional shared key used by physical sensor agents."""

    configured_key = os.environ.get("SENTINEL_AGENT_KEY", "").strip()
    if not configured_key:
        return True
    supplied_key = request.headers.get("X-Sentinel-Key", "").strip()
    return supplied_key == configured_key


@app.route("/sensors")
def sensors_page():
    """Display registered ESP32 nodes and recent physical telemetry."""

    agents = list_agents()
    telemetry = recent_telemetry(limit=500)
    intelligence = build_sensor_intelligence(agents, telemetry, hours=24)
    return render_template(
        "sensors.html",
        agents=intelligence["agents"],
        sensor_summary=sensor_summary(),
        telemetry=telemetry[:80],
        sensor_intelligence=intelligence,
        agent_key_enabled=bool(os.environ.get("SENTINEL_AGENT_KEY", "").strip())
    )


@app.route("/api/sensors")
def sensors_api():
    """Return all registered sensor agents and their latest readings."""

    agents = list_agents()
    return jsonify({
        "application": "Project Sentinel",
        "version": "1.6.0",
        "summary": sensor_summary(),
        "agents": agents
    })


@app.route("/api/sensors/telemetry")
def sensor_telemetry_api():
    """Return recent telemetry, optionally filtered to one agent."""

    requested_limit = request.args.get("limit", "100")
    try:
        limit = min(max(int(requested_limit), 1), 500)
    except ValueError:
        limit = 100
    return jsonify({
        "application": "Project Sentinel",
        "telemetry": recent_telemetry(limit=limit, agent_id=request.args.get("agent_id"))
    })


@app.route("/api/agent/register", methods=["POST"])
def register_sensor_agent():
    """Register or update the descriptive profile of an ESP32 agent."""

    if not agent_request_authorised():
        return jsonify({"status": "error", "message": "Invalid Sentinel agent key."}), 401
    payload = request.get_json(silent=True) or {}
    try:
        agent = register_agent(payload)
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400
    return jsonify({"status": "registered", "agent": agent}), 201


@app.route("/api/agent/checkin", methods=["POST"])
def sensor_agent_checkin():
    """Receive a heartbeat and sensor readings from an ESP32 node."""

    if not agent_request_authorised():
        return jsonify({"status": "error", "message": "Invalid Sentinel agent key."}), 401
    payload = request.get_json(silent=True) or {}
    try:
        agent, telemetry, motion_started = record_checkin(payload, request.remote_addr or "")
    except ValueError as error:
        return jsonify({"status": "error", "message": str(error)}), 400

    if motion_started:
        record_event(
            event_type="SENSOR_MOTION",
            severity="MEDIUM",
            message=f"Motion detected by {agent.get('name', agent.get('agent_id'))}.",
            device={
                "friendly_name": agent.get("name", agent.get("agent_id")),
                "ip_address": telemetry.get("ip_address", ""),
                "mac_address": agent.get("agent_id", ""),
                "status": "SENSOR"
            },
            metadata={
                "agent_id": agent.get("agent_id"),
                "location": agent.get("location"),
                "temperature": telemetry.get("temperature"),
                "humidity": telemetry.get("humidity")
            }
        )

    return jsonify({
        "status": "accepted",
        "server_time": current_timestamp(),
        "agent_id": agent.get("agent_id"),
        "motion_event_created": motion_started
    })


@app.route("/")
def dashboard():
    """
    Display the main Sentinel dashboard.
    """

    snapshot, error = load_snapshot()

    if error:
        empty_snapshot = {
            "summary": {
                "overall_risk": "UNAVAILABLE",
                "devices_visible": 0,
                "trusted_devices": 0,
                "pending_devices": 0,
                "behaviour_changed": 0,
                "highest_device_risk": 0
            },
            "devices": []
        }

        return render_template(
            "dashboard.html",
            summary=empty_snapshot["summary"],
            devices=[],
            generated_at=None,
            soc=build_soc_dashboard(empty_snapshot),
            changes=build_change_intelligence(empty_snapshot, []),
            monitor=get_monitor_state(),
            dashboard_error=error
        ), 503

    return render_template(
        "dashboard.html",
        summary=snapshot.get("summary", {}),
        devices=snapshot.get("devices", []),
        generated_at=snapshot.get("generated_at"),
        soc=build_soc_dashboard(snapshot),
        changes=build_change_intelligence(
            snapshot,
            get_recent_events(limit=250)
        ),
        monitor=get_monitor_state(),
        dashboard_error=None
    )


@app.route("/changes")
def changes_page():
    """Display the dedicated network change history centre."""

    requested_hours = request.args.get("hours", "24")

    try:
        hours = int(requested_hours)
    except ValueError:
        hours = 24

    if hours not in {24, 72, 168}:
        hours = 24

    snapshot, error = load_snapshot()

    if error:
        snapshot = {"summary": {}, "devices": [], "network_changes": {}}
        event_list = []
    else:
        event_list = get_recent_events(limit=500)

    change_data = build_change_intelligence(
        snapshot,
        event_list,
        hours=hours,
        max_items=100
    )

    return render_template(
        "changes.html",
        changes=change_data,
        selected_hours=hours,
        change_error=error
    ), 503 if error else 200


@app.route("/exposures")
def exposures_page():
    """Display aggregated service exposure intelligence for all assets."""

    snapshot, error = load_snapshot()

    if error:
        return render_template(
            "exposures.html",
            exposure_assets=[],
            exposure_summary={
                "total_assets": 0,
                "assets_with_services": 0,
                "review_assets": 0,
                "critical_findings": 0,
                "high_findings": 0
            },
            generated_at=None,
            exposure_error=error
        ), 503

    exposure_assets = []
    for device in snapshot.get("devices", []):
        exposure = build_exposure_intelligence(device)
        if exposure.get("finding_count", 0) == 0:
            continue
        exposure_assets.append({
            "device": device,
            "exposure": exposure
        })

    rating_order = {"Critical": 4, "High": 3, "Moderate": 2, "Low": 1, "Minimal": 0}
    exposure_assets.sort(
        key=lambda item: (
            -rating_order.get(item["exposure"].get("rating", "Minimal"), 0),
            -item["exposure"].get("score", 0),
            str(item["device"].get("friendly_name", "Unknown"))
        )
    )

    exposure_summary = {
        "total_assets": len(snapshot.get("devices", [])),
        "assets_with_services": len(exposure_assets),
        "review_assets": sum(1 for item in exposure_assets if item["exposure"].get("review_count", 0) > 0),
        "critical_findings": sum(item["exposure"].get("critical_count", 0) for item in exposure_assets),
        "high_findings": sum(item["exposure"].get("high_count", 0) for item in exposure_assets)
    }

    return render_template(
        "exposures.html",
        exposure_assets=exposure_assets,
        exposure_summary=exposure_summary,
        generated_at=snapshot.get("generated_at"),
        exposure_error=None
    )


@app.route("/assets")
def assets_page():
    """Display Sentinel's permanent asset inventory."""

    snapshot, error = load_snapshot()

    if error:
        return render_template(
            "assets.html",
            assets=[],
            asset_summary={
                "total_assets": 0,
                "online_assets": 0,
                "offline_assets": 0,
                "trusted_assets": 0,
                "pending_assets": 0
            },
            generated_at=None,
            asset_error=error
        ), 503

    assets, asset_summary = build_asset_inventory(snapshot)

    return render_template(
        "assets.html",
        assets=assets,
        asset_summary=asset_summary,
        generated_at=snapshot.get("generated_at"),
        asset_error=None
    )


@app.route("/devices/<path:mac_address>")
def device_page(mac_address):
    """
    Display the dashboard page for one device.
    """

    snapshot, error = load_snapshot()

    approval_message = None
    approval_error = request.args.get(
        "approval_error"
    )

    if request.args.get("approved") == "1":
        approval_message = (
            "Device approved and added to the trusted inventory."
        )
    elif request.args.get("updated") == "1":
        approval_message = "Asset profile updated successfully."
    elif request.args.get("trust_removed") == "1":
        approval_message = (
            "Trust removed. The device is now pending analyst review."
        )

    if error:
        return render_template(
            "device.html",
            device={
                "friendly_name": "Device unavailable",
                "ip_address": "Unknown",
                "mac_address": mac_address,
                "hostname": "Unknown",
                "vendor": "Unknown",
                "device_type": "",
                "detected_device_type": "Unknown",
                "detection_confidence": "Low",
                "detection_reason": "Not available",
                "owner": "",
                "notes": "",
                "trust_level": "",
                "status": "UNKNOWN",
                "risk_score": 0,
                "risk_reasons": "Snapshot unavailable.",
                "open_ports": [],
                "behaviour_analysis": {
                    "behaviour_status": "UNAVAILABLE",
                    "current_service_count": 0,
                    "baseline_service_count": 0,
                    "change_count": 0,
                    "new_services": [],
                    "missing_services": []
                }
            },
            approval_message=None,
            approval_error=error,
            device_events=[],
            device_intelligence={
                "first_seen": None,
                "last_seen": None,
                "sightings": 0,
                "event_count": 0,
                "current_service_count": 0,
                "new_service_count": 0,
                "missing_service_count": 0,
                "risk_reasons": ["Snapshot unavailable."],
                "severity_counts": {}
            },
            asset_intelligence={
                "asset_role": "Unknown",
                "operating_system": "Not identified",
                "os_confidence": "Low",
                "health_score": 0,
                "health_label": "Unavailable",
                "identity_confidence": "Low",
                "identity_confidence_score": 0,
                "activity_state": "No recorded activity",
                "recommendations": ["Restore snapshot data and run a new scan."],
                "profile_summary": "Asset intelligence is unavailable."
            },
            exposure_intelligence={
                "score": 0,
                "rating": "Unavailable",
                "headline": "Exposure intelligence unavailable",
                "finding_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "review_count": 0,
                "findings": [],
                "disclaimer": "Restore snapshot data and run a new scan."
            },
            investigation={
                "risk_band": "UNAVAILABLE",
                "investigation_status": "Data unavailable",
                "recommendations": [],
                "exposure": [],
                "weighted_event_score": 0,
                "behaviour_status": "UNAVAILABLE",
                "event_types": [],
                "analyst_note": "Snapshot unavailable."
            }
        ), 503

    requested_mac = normalise_mac_address(
        mac_address
    )

    for device_record in snapshot.get(
        "devices",
        []
    ):
        device_mac = normalise_mac_address(
            device_record.get(
                "mac_address",
                ""
            )
        )

        if device_mac == requested_mac:
            device_events = get_device_events(requested_mac)
            device_intelligence = build_device_intelligence(
                device_record,
                device_events
            )

            return render_template(
                "device.html",
                device=device_record,
                approval_message=approval_message,
                approval_error=approval_error,
                device_events=device_events,
                device_intelligence=device_intelligence,
                asset_intelligence=build_asset_intelligence(
                    device_record,
                    device_events,
                    device_intelligence
                ),
                exposure_intelligence=build_exposure_intelligence(
                    device_record
                ),
                investigation=build_investigation_context(
                    device_record,
                    device_events
                )
            )

    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "not found",
            "message": (
                f"No device was found with MAC address "
                f"{mac_address}"
            )
        }
    ), 404


@app.route(
    "/devices/<path:mac_address>/approve",
    methods=["POST"]
)
def approve_device_route(mac_address):
    """
    Approve a device and move it into the trusted inventory.
    """

    snapshot, snapshot_error = load_snapshot()

    if snapshot_error:
        return redirect(
            url_for(
                "device_page",
                mac_address=mac_address,
                approval_error=snapshot_error
            )
        )

    requested_mac = normalise_mac_address(
        mac_address
    )

    matching_device = None

    for device_record in snapshot.get(
        "devices",
        []
    ):
        device_mac = normalise_mac_address(
            device_record.get(
                "mac_address",
                ""
            )
        )

        if device_mac == requested_mac:
            matching_device = device_record
            break

    if matching_device is None:
        return jsonify(
            {
                "application": "Project Sentinel",
                "status": "not found",
                "message": (
                    f"No device was found with MAC address "
                    f"{mac_address}"
                )
            }
        ), 404

    friendly_name = request.form.get(
        "friendly_name",
        ""
    ).strip()

    owner = request.form.get(
        "owner",
        ""
    ).strip()

    device_type = request.form.get(
        "device_type",
        ""
    ).strip()

    trust_level = request.form.get(
        "trust_level",
        "Trusted"
    ).strip()

    notes = request.form.get(
        "notes",
        ""
    ).strip()

    if not device_type:
        detected_type = matching_device.get(
            "detected_device_type",
            ""
        )

        if detected_type != "Unknown":
            device_type = detected_type

    try:
        trusted_profile = approve_inventory_device(
            mac_address=requested_mac,
            friendly_name=friendly_name,
            owner=owner,
            device_type=device_type,
            trust_level=trust_level,
            notes=notes
        )

    except ValueError as error:
        return redirect(
            url_for(
                "device_page",
                mac_address=requested_mac,
                approval_error=str(error)
            )
        )

    except OSError as error:
        app.logger.exception(
            "Unable to update device inventory"
        )

        return redirect(
            url_for(
                "device_page",
                mac_address=requested_mac,
                approval_error=(
                    f"Unable to update inventory: {error}"
                )
            )
        )

    update_snapshot_device_inventory(
        requested_mac,
        trusted_profile
    )

    return redirect(
        url_for(
            "device_page",
            mac_address=requested_mac,
            approved="1"
        )
    )



@app.route(
    "/devices/<path:mac_address>/profile",
    methods=["POST"]
)
def update_device_profile_route(mac_address):
    """Update the analyst-managed profile for a trusted device."""

    requested_mac = normalise_mac_address(mac_address)

    try:
        trusted_profile = approve_inventory_device(
            mac_address=requested_mac,
            friendly_name=request.form.get("friendly_name", "").strip(),
            owner=request.form.get("owner", "").strip(),
            device_type=request.form.get("device_type", "").strip(),
            trust_level=request.form.get("trust_level", "Trusted").strip(),
            notes=request.form.get("notes", "").strip()
        )
        update_snapshot_device_inventory(requested_mac, trusted_profile)
    except (ValueError, OSError) as error:
        return redirect(
            url_for(
                "device_page",
                mac_address=requested_mac,
                approval_error=str(error)
            )
        )

    return redirect(
        url_for(
            "device_page",
            mac_address=requested_mac,
            updated="1"
        )
    )


@app.route(
    "/devices/<path:mac_address>/remove-trust",
    methods=["POST"]
)
def remove_device_trust_route(mac_address):
    """Remove a device from trusted inventory and return it to review."""

    requested_mac = normalise_mac_address(mac_address)
    snapshot, snapshot_error = load_snapshot()

    if snapshot_error:
        return redirect(
            url_for(
                "device_page",
                mac_address=requested_mac,
                approval_error=snapshot_error
            )
        )

    ip_address = "Unknown"
    for device_record in snapshot.get("devices", []):
        if normalise_mac_address(device_record.get("mac_address", "")) == requested_mac:
            ip_address = device_record.get("ip_address", "Unknown")
            break

    try:
        removed = remove_inventory_trust(
            requested_mac,
            ip_address=ip_address
        )
    except (ValueError, OSError) as error:
        return redirect(
            url_for(
                "device_page",
                mac_address=requested_mac,
                approval_error=str(error)
            )
        )

    if not removed:
        return redirect(
            url_for(
                "device_page",
                mac_address=requested_mac,
                approval_error="This device is not currently trusted."
            )
        )

    remove_snapshot_device_trust(requested_mac)

    return redirect(
        url_for(
            "device_page",
            mac_address=requested_mac,
            trust_removed="1"
        )
    )


@app.route("/api")
def api_information():
    """
    Return information about the Sentinel REST API.
    """

    return jsonify(
        {
            "application": "Project Sentinel",
            "service": "REST API",
            "status": "running",
            "endpoints": {
                "dashboard": "/",
                "assets_page": "/assets",
                "health": "/health",
                "start_scan": "POST /scan",
                "scan_status": "/scan/status",
                "summary": "/summary",
                "devices": "/devices",
                "device_page": "/devices/<mac_address>",
                "approve_device": (
                    "POST /devices/<mac_address>/approve"
                ),
                "device_api": "/device/<mac_address>",
                "events_center": "/events-center",
                "events": "/events",
                "device_events": "/device/<mac_address>/events"
            }
        }
    )


@app.route("/monitor/status")
def monitor_status():
    """Return the current live-monitoring state."""

    return jsonify({
        "application": "Project Sentinel",
        "monitor": get_monitor_state(),
        "scan": get_scan_state()
    })


@app.route("/monitor/start", methods=["POST"])
def monitor_start():
    """Enable continuous Sentinel monitoring."""

    payload = request.get_json(silent=True) or {}
    interval = payload.get("interval_seconds", 60)

    try:
        interval = int(interval)
    except (TypeError, ValueError):
        interval = 60

    started = start_monitoring(interval)
    return jsonify({
        "application": "Project Sentinel",
        "status": "started" if started else "already_running",
        "monitor": get_monitor_state()
    }), 202 if started else 200


@app.route("/monitor/stop", methods=["POST"])
def monitor_stop():
    """Disable continuous Sentinel monitoring."""

    stopped = stop_monitoring()
    return jsonify({
        "application": "Project Sentinel",
        "status": "stopping" if stopped else "already_stopped",
        "monitor": get_monitor_state()
    })


@app.route("/scan", methods=["POST"])
def start_scan():
    """
    Start a Sentinel monitoring cycle in the background.
    """

    lock_acquired = scan_lock.acquire(
        blocking=False
    )

    if not lock_acquired:
        return jsonify(
            {
                "application": "Project Sentinel",
                "status": "busy",
                "message": (
                    "A Sentinel network scan is already running."
                ),
                "scan": get_scan_state()
            }
        ), 409

    update_scan_state(
        status="starting",
        message="Preparing Sentinel network scan.",
        started_at=current_timestamp(),
        completed_at=None,
        device_count=None,
        error=None
    )

    scan_thread = Thread(
        target=execute_background_scan,
        name="sentinel-network-scan",
        daemon=True
    )

    scan_thread.start()

    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "accepted",
            "message": "Sentinel network scan started.",
            "scan": get_scan_state()
        }
    ), 202


@app.route("/scan/status")
def scan_status():
    """
    Return the current background scan status.
    """

    return jsonify(
        {
            "application": "Project Sentinel",
            "scan": get_scan_state()
        }
    )


@app.route("/health")
def health():
    """
    Return API, snapshot and scan availability information.
    """

    snapshot, error = load_snapshot()
    current_scan = get_scan_state()

    if error:
        return jsonify(
            {
                "api_status": "running",
                "application": "Project Sentinel",
                "snapshot_status": "unavailable",
                "snapshot_generated_at": None,
                "scan_status": current_scan["status"]
            }
        ), 503

    return jsonify(
        {
            "api_status": "running",
            "application": "Project Sentinel",
            "snapshot_status": "available",
            "snapshot_generated_at": snapshot.get(
                "generated_at"
            ),
            "scan_status": current_scan["status"]
        }
    )


@app.route("/summary")
def summary():
    """
    Return the latest Sentinel security summary.
    """

    snapshot, error = load_snapshot()

    if error:
        return snapshot_error_response(
            error
        )

    return jsonify(
        {
            "generated_at": snapshot.get(
                "generated_at"
            ),
            "summary": snapshot.get(
                "summary",
                {}
            )
        }
    )


@app.route("/devices")
def devices():
    """
    Return all devices in the latest Sentinel snapshot.
    """

    snapshot, error = load_snapshot()

    if error:
        return snapshot_error_response(
            error
        )

    device_list = snapshot.get(
        "devices",
        []
    )

    return jsonify(
        {
            "generated_at": snapshot.get(
                "generated_at"
            ),
            "device_count": len(device_list),
            "devices": device_list
        }
    )


@app.route("/device/<path:mac_address>")
def device(mac_address):
    """
    Return one device from the latest Sentinel snapshot.
    """

    snapshot, error = load_snapshot()

    if error:
        return snapshot_error_response(
            error
        )

    requested_mac = normalise_mac_address(
        mac_address
    )

    for device_record in snapshot.get(
        "devices",
        []
    ):
        device_mac = normalise_mac_address(
            device_record.get(
                "mac_address",
                ""
            )
        )

        if device_mac == requested_mac:
            return jsonify(
                {
                    "generated_at": snapshot.get(
                        "generated_at"
                    ),
                    "device": device_record
                }
            )

    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "not found",
            "message": (
                f"No device was found with MAC address "
                f"{mac_address}"
            )
        }
    ), 404


@app.route("/events-center")
def events_center():
    """Display the Sentinel security events centre."""

    event_list = get_recent_events(limit=100)

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    event_types = set()

    for event_record in event_list:
        severity = str(
            event_record.get("severity", "INFO")
        ).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

        event_type = str(
            event_record.get("type", "UNKNOWN")
        ).strip().upper()

        if event_type:
            event_types.add(event_type)

    return render_template(
        "events.html",
        initial_events=event_list,
        severity_counts=severity_counts,
        event_types=sorted(event_types)
    )


@app.route("/events")
def events():
    """Return recent Sentinel events."""

    requested_limit = request.args.get("limit", "50")

    try:
        limit = min(max(int(requested_limit), 1), 500)
    except ValueError:
        limit = 50

    event_list = get_recent_events(
        limit=limit,
        severity=request.args.get("severity"),
        event_type=request.args.get("type")
    )

    return jsonify(
        {
            "application": "Project Sentinel",
            "event_count": len(event_list),
            "events": event_list
        }
    )


@app.route("/device/<path:mac_address>/events")
def device_events(mac_address):
    """Return the event timeline for one device."""

    event_list = get_device_events(mac_address)

    return jsonify(
        {
            "application": "Project Sentinel",
            "mac_address": normalise_mac_address(mac_address),
            "event_count": len(event_list),
            "events": event_list
        }
    )


@app.errorhandler(404)
def page_not_found(error):
    """
    Return a standard response for unknown routes.
    """

    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "not found",
            "message": (
                "The requested page or endpoint does not exist."
            )
        }
    ), 404


@app.errorhandler(500)
def internal_server_error(error):
    """
    Return a standard response for unexpected server errors.
    """

    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "error",
            "message": (
                "An internal server error occurred."
            )
        }
    ), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        threaded=True
    )