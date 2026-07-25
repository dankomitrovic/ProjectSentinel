import json
import os
from datetime import datetime
from threading import Lock, Thread

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
from inventory import approve_device as approve_inventory_device
from main import main as run_monitoring_cycle
from registry import load_device_registry


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


@app.route("/")
def dashboard():
    """
    Display the main Sentinel dashboard.
    """

    snapshot, error = load_snapshot()

    if error:
        return render_template(
            "dashboard.html",
            summary={
                "overall_risk": "UNAVAILABLE",
                "devices_visible": 0,
                "trusted_devices": 0,
                "highest_device_risk": 0
            },
            devices=[],
            generated_at=None
        )

    return render_template(
        "dashboard.html",
        summary=snapshot.get(
            "summary",
            {}
        ),
        devices=snapshot.get(
            "devices",
            []
        ),
        generated_at=snapshot.get(
            "generated_at"
        )
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
                device_intelligence=device_intelligence
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