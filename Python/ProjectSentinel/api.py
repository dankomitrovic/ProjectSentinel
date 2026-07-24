import json
import os
from datetime import datetime
from threading import Lock, Thread

from flask import Flask, jsonify, render_template

from config import LATEST_SNAPSHOT_FILE
from main import main as run_monitoring_cycle


app = Flask(__name__)

scan_lock = Lock()
scan_state_lock = Lock()

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

        device_list = snapshot.get("devices", [])

        update_scan_state(
            status="completed",
            message="Network scan completed successfully.",
            completed_at=current_timestamp(),
            device_count=len(device_list),
            error=None
        )

    except PermissionError:
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
        summary=snapshot.get("summary", {}),
        devices=snapshot.get("devices", []),
        generated_at=snapshot.get("generated_at")
    )


@app.route("/devices/<path:mac_address>")
def device_page(mac_address):
    """
    Display the dashboard page for one device.
    """

    snapshot, error = load_snapshot()

    if error:
        return render_template(
            "device.html",
            device={
                "friendly_name": "Device unavailable",
                "ip_address": "Unknown",
                "mac_address": mac_address,
                "risk_score": 0,
                "open_ports": [],
                "behaviour_analysis": {
                    "behaviour_status": "UNAVAILABLE",
                    "current_service_count": 0,
                    "baseline_service_count": 0,
                    "change_count": 0,
                    "new_services": [],
                    "missing_services": []
                }
            }
        ), 503

    requested_mac = mac_address.upper()

    for device_record in snapshot.get("devices", []):
        device_mac = str(
            device_record.get("mac_address", "")
        ).upper()

        if device_mac == requested_mac:
            return render_template(
                "device.html",
                device=device_record
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
                "health": "/health",
                "start_scan": "POST /scan",
                "scan_status": "/scan/status",
                "summary": "/summary",
                "devices": "/devices",
                "device_page": "/devices/<mac_address>",
                "device_api": "/device/<mac_address>"
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
            "message": (
                "Sentinel network scan started."
            ),
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
        return snapshot_error_response(error)

    return jsonify(
        {
            "generated_at": snapshot.get("generated_at"),
            "summary": snapshot.get("summary", {})
        }
    )


@app.route("/devices")
def devices():
    """
    Return all devices in the latest Sentinel snapshot.
    """

    snapshot, error = load_snapshot()

    if error:
        return snapshot_error_response(error)

    device_list = snapshot.get("devices", [])

    return jsonify(
        {
            "generated_at": snapshot.get("generated_at"),
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
        return snapshot_error_response(error)

    requested_mac = mac_address.upper()

    for device_record in snapshot.get("devices", []):
        device_mac = str(
            device_record.get("mac_address", "")
        ).upper()

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
