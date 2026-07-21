from scapy.all import ARP, Ether, srp
from datetime import datetime
import csv
import os


# ----------------------------------------------------------
# File locations
# ----------------------------------------------------------

LATEST_SCAN_FILE = "data/latest_devices.csv"
SCAN_HISTORY_FILE = "data/scan_history.csv"


# ----------------------------------------------------------
# Discover devices that respond to ARP on the network
# ----------------------------------------------------------
def discover_devices(network):

    # Create an ARP request for the selected network range
    arp = ARP(pdst=network)

    # Broadcast the request to every device on the local network
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Place the ARP request inside the Ethernet frame
    packet = broadcast / arp

    # Send the packets and collect responses
    answered, unanswered = srp(
        packet,
        timeout=2,
        verbose=False
    )

    return answered


# ----------------------------------------------------------
# Convert Scapy replies into simple Python dictionaries
# ----------------------------------------------------------
def prepare_device_data(scan_results):

    prepared_devices = []

    for sent, received in scan_results:

        device = {
            "ip_address": received.psrc,
            "mac_address": received.hwsrc
        }

        prepared_devices.append(device)

    return prepared_devices


# ----------------------------------------------------------
# Display discovered devices in the terminal
# ----------------------------------------------------------
def display_devices(devices):

    print()

    device_number = 1

    for device in devices:

        print("=" * 50)
        print(f"Device {device_number}")
        print("=" * 50)

        print(f"IP Address : {device['ip_address']}")
        print(f"MAC Address: {device['mac_address']}")

        print()

        device_number += 1

    print("=" * 50)
    print(f"Total Devices Found: {len(devices)}")
    print("=" * 50)


# ----------------------------------------------------------
# Load the previous network state from CSV
# ----------------------------------------------------------
def load_previous_scan():

    previous_devices = []

    # On the first run there may be no previous scan file
    if not os.path.exists(LATEST_SCAN_FILE):
        return previous_devices

    with open(LATEST_SCAN_FILE, "r", newline="") as file:

        reader = csv.DictReader(file)

        for row in reader:

            device = {
                "ip_address": row["IP Address"],
                "mac_address": row["MAC Address"]
            }

            previous_devices.append(device)

    return previous_devices


# ----------------------------------------------------------
# Compare the previous scan with the current scan
# ----------------------------------------------------------
def compare_scans(previous_devices, current_devices):

    # MAC addresses are more reliable than IP addresses
    # when identifying the same device over time
    previous_macs = {
        device["mac_address"]
        for device in previous_devices
    }

    current_macs = {
        device["mac_address"]
        for device in current_devices
    }

    # Devices present now but not present previously
    new_macs = current_macs - previous_macs

    # Devices present previously but not present now
    missing_macs = previous_macs - current_macs

    new_devices = [
        device
        for device in current_devices
        if device["mac_address"] in new_macs
    ]

    missing_devices = [
        device
        for device in previous_devices
        if device["mac_address"] in missing_macs
    ]

    return new_devices, missing_devices


# ----------------------------------------------------------
# Display network changes and alerts
# ----------------------------------------------------------
def display_changes(new_devices, missing_devices):

    print()
    print("=" * 50)
    print("              SENTINEL CHANGE REPORT")
    print("=" * 50)

    if len(new_devices) == 0 and len(missing_devices) == 0:

        print("Status: No network changes detected")

    else:

        for device in new_devices:

            print()
            print("[ALERT] New device detected")
            print(f"IP Address : {device['ip_address']}")
            print(f"MAC Address: {device['mac_address']}")

        for device in missing_devices:

            print()
            print("[WARNING] Device no longer detected")
            print(f"Last IP    : {device['ip_address']}")
            print(f"MAC Address: {device['mac_address']}")

    print("=" * 50)


# ----------------------------------------------------------
# Save the current network state
# This replaces the previous latest_devices.csv file
# ----------------------------------------------------------
def save_latest_scan(devices):

    with open(LATEST_SCAN_FILE, "w", newline="") as file:

        writer = csv.writer(file)

        writer.writerow([
            "IP Address",
            "MAC Address"
        ])

        for device in devices:

            writer.writerow([
                device["ip_address"],
                device["mac_address"]
            ])

    print(f"Latest network state saved to {LATEST_SCAN_FILE}")


# ----------------------------------------------------------
# Append the current scan to the historical timeline
# ----------------------------------------------------------
def save_scan_history(devices):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    file_exists = os.path.exists(SCAN_HISTORY_FILE)

    with open(SCAN_HISTORY_FILE, "a", newline="") as file:

        writer = csv.writer(file)

        # Write headings only when the file is first created
        if not file_exists:

            writer.writerow([
                "Timestamp",
                "IP Address",
                "MAC Address"
            ])

        for device in devices:

            writer.writerow([
                timestamp,
                device["ip_address"],
                device["mac_address"]
            ])

    print(f"Scan added to {SCAN_HISTORY_FILE}")


# ----------------------------------------------------------
# Main program
# ----------------------------------------------------------

print("=" * 50)
print("       Project Sentinel Discovery Engine")
print("=" * 50)

network = "10.0.2.0/24"

# Load the previous network state before changing the file
previous_devices = load_previous_scan()

# Perform the new network scan
scan_results = discover_devices(network)

# Convert Scapy results into reusable dictionaries
current_devices = prepare_device_data(scan_results)

# Display the current network state
display_devices(current_devices)

# Compare the current scan with the previous scan
new_devices, missing_devices = compare_scans(
    previous_devices,
    current_devices
)

# Display any detected changes
display_changes(
    new_devices,
    missing_devices
)

# Save the current state and append the scan history
save_latest_scan(current_devices)
save_scan_history(current_devices)