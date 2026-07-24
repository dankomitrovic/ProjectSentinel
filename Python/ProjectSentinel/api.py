import json
import os

from flask import Flask, jsonify, render_template

from config import LATEST_SNAPSHOT_FILE


app = Flask(__name__)


def load_snapshot():
    if not os.path.exists(LATEST_SNAPSHOT_FILE):
        return None, "Snapshot file does not exist."

    with open(LATEST_SNAPSHOT_FILE, "r", encoding="utf-8") as snapshot_file:
        snapshot = json.load(snapshot_file)

    return snapshot, None


def snapshot_error_response(error_message):
    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "error",
            "message": error_message
        }
    ), 503


@app.route("/")
def dashboard():
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
            "message": f"No device was found with MAC address {mac_address}"
        }
    ), 404

@app.route("/api")
def api_information():
    return jsonify(
        {
            "application": "Project Sentinel",
            "service": "REST API",
            "status": "running",
            "endpoints": {
                "dashboard": "/",
                "health": "/health",
                "summary": "/summary",
                "devices": "/devices",
                "device": "/device/<mac_address>"
            }
        }
    )


@app.route("/health")
def health():
    snapshot, error = load_snapshot()

    if error:
        return jsonify(
            {
                "api_status": "running",
                "application": "Project Sentinel",
                "snapshot_status": "unavailable",
                "snapshot_generated_at": None
            }
        ), 503

    return jsonify(
        {
            "api_status": "running",
            "application": "Project Sentinel",
            "snapshot_status": "available",
            "snapshot_generated_at": snapshot.get("generated_at")
        }
    )


@app.route("/summary")
def summary():
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
    snapshot, error = load_snapshot()

    if error:
        return snapshot_error_response(error)

    requested_mac = mac_address.upper()

    for device_record in snapshot.get("devices", []):
        device_mac = str(device_record.get("mac_address", "")).upper()

        if device_mac == requested_mac:
            return jsonify(
                {
                    "generated_at": snapshot.get("generated_at"),
                    "device": device_record
                }
            )

    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "not found",
            "message": f"No device was found with MAC address {mac_address}"
        }
    ), 404


@app.errorhandler(404)
def page_not_found(error):
    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "not found",
            "message": "The requested page or endpoint does not exist."
        }
    ), 404


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify(
        {
            "application": "Project Sentinel",
            "status": "error",
            "message": "An internal server error occurred."
        }
    ), 500


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )