import json
import os
from threading import Lock

from flask import Flask, jsonify, render_template

from config import LATEST_SNAPSHOT_FILE
from main import main as run_monitoring_cycle


app = Flask(__name__)

scan_lock = Lock()


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
    Return a standard API response when snapshot data is unavailable.
    """

    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "error",
            "message": error_message
        }
    ), 503


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
            devices=[]
        )

    return render_template(
        "dashboard.html",
        summary=snapshot.get("summary", {}),
        devices=snapshot.get("devices", [])
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
    Return general information about the Sentinel REST API.
    """

    return jsonify(
        {
            "application": "Project Sentinel",
            "service": "REST API",
            "status": "running",
            "endpoints": {
                "dashboard": "/",
                "health": "/health",
                "scan": "/scan",
                "summary": "/summary",
                "devices": "/devices",
                "device_page": "/devices/<mac_address>",
                "device_api": "/device/<mac_address>"
            }
        }
    )


@app.route("/scan", methods=["POST"])
def scan_network():
    """
    Run one complete Sentinel monitoring cycle.

    Only one scan may run at a time.
    """

    lock_acquired = scan_lock.acquire(blocking=False)

    if not lock_acquired:
        return jsonify(
            {
                "application": "Project Sentinel",
                "status": "busy",
                "message": (
                    "A Sentinel network scan is already running."
                )
            }
        ), 409

    try:
        run_monitoring_cycle()

        snapshot, error = load_snapshot()

        if error:
            return jsonify(
                {
                    "application": "Project Sentinel",
                    "status": "success",
                    "message": (
                        "Network scan completed, but the new "
                        "snapshot could not be loaded."
                    ),
                    "snapshot_error": error
                }
            ), 200

        device_list = snapshot.get("devices", [])

        return jsonify(
            {
                "application": "Project Sentinel",
                "status": "success",
                "message": "Network scan completed successfully.",
                "generated_at": snapshot.get("generated_at"),
                "device_count": len(device_list),
                "summary": snapshot.get("summary", {})
            }
        )

    except PermissionError:
        return jsonify(
            {
                "application": "Project Sentinel",
                "status": "error",
                "message": (
                    "Sentinel does not have permission to create "
                    "the raw network socket required for ARP "
                    "discovery. Start the API with the required "
                    "network privileges."
                )
            }
        ), 500

    except Exception as error:
        app.logger.exception(
            "Sentinel network scan failed"
        )

        return jsonify(
            {
                "application": "Project Sentinel",
                "status": "error",
                "message": str(error)
            }
        ), 500

    finally:
        scan_lock.release()


@app.route("/health")
def health():
    """
    Return API and snapshot availability information.
    """

    snapshot, error = load_snapshot()

    if error:
        return jsonify(
            {
                "api_status": "running",
                "application": "Project Sentinel",
                "snapshot_status": "unavailable",
                "snapshot_generated_at": None,
                "scan_in_progress": scan_lock.locked()
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
            "scan_in_progress": scan_lock.locked()
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
    Return all devices from the latest Sentinel snapshot.
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