# Project Sentinel Architecture

## Purpose
Project Sentinel is a local security operations and investigation platform combining network discovery, asset and exposure intelligence, change detection, ESP32 telemetry, security detections and analyst case management.

## Runtime topology

ESP32 sensor node -> Wi-Fi LAN -> Ubuntu VirtualBox VM -> Flask API -> JSON persistence -> Sentinel web interface

- Ubuntu VM address used by the ESP32: `192.168.1.172`
- Flask bind address: `0.0.0.0:5000`
- VirtualBox Adapter 1: Bridged Adapter
- VirtualBox Adapter 2: NAT
- Windows port forwarding is not required in the working configuration.

## Software layers
- `api.py`: Flask routes, page rendering and JSON APIs.
- Network modules: scanning, inventory, registry, service and change intelligence.
- Sensor modules: telemetry storage, sensor intelligence and detection events.
- `investigation_store.py`: persistent case creation, correlation, workflow, notes and timeline.
- `templates/`: analyst-facing pages.
- `static/`: Sentinel styling and live browser behaviour.
- `data/`: local JSON and CSV operational records.

## Security lifecycle
Discover -> identify -> assess exposure -> detect change -> collect telemetry -> generate detections -> correlate investigations -> document analyst response.

## Persistence
This release uses local JSON and CSV files for transparent, portable lab operation. Writes to investigations use a temporary file followed by atomic replacement.

## Current hardware integration
ESP32 firmware 2.1.2 posts telemetry by raw TCP HTTP to the Sentinel API. Payloads include DHT22 temperature and humidity, PIR motion, RSSI, uptime, firmware and IP address.
