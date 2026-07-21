from scapy.all import ARP, Ether, srp
from datetime import datetime
import csv
import os


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

    file_name = "latest_devices.csv"

    previous_devices = []

    # On the first run there may be no previous file
    if not os.path.exists(file_name):
        return previous_devices

    with open(file_name, "r", newline="") as file:

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

    # MAC addresses are more useful than IP addresses for
    # recognising devices because IP addresses can change
    previous_macs = {
        device["mac_address"]
        for device in previous_devices
    }

    current_macs = {
        device["mac_address"]
        for device in current_devices
    }

    # Present now, but absent from the previous scan
    new_macs = current_macs - previous_macs

    # Present previously, but absent from the current scan
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
# Replaces the previous latest_devices.csv file
# ----------------------------------------------------------
def save_latest_scan(devices):

    with open("latest_devices.csv", "w", newline="") as file:

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

    print("Latest network state saved to latest_devices.csv")


# ----------------------------------------------------------
# Append this scan to the historical timeline
# ----------------------------------------------------------
def save_scan_history(devices):

    file_name = "scan_history.csv"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    file_exists = os.path.exists(file_name)

    with open(file_name, "a", newline="") as file:

        writer = csv.writer(file)

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

    print("Scan added to scan_history.csv")


# ----------------------------------------------------------
# Main program
# ----------------------------------------------------------

print("=" * 50)
print("       Project Sentinel Discovery Engine")
print("=" * 50)

network = "10.0.2.0/24"

# Load the old state before changing the latest scan file
previous_devices = load_previous_scan()

# Perform the new scan
scan_results = discover_devices(network)

# Convert Scapy results into reusable dictionaries
current_devices = prepare_device_data(scan_results)

# Display the current state
display_devices(current_devices)

# Compare the old and current states
new_devices, missing_devices = compare_scans(
    previous_devices,
    current_devices
)

# Display alerts before saving the new state
display_changes(
    new_devices,
    missing_devices
)

# Store the new current state and append history
save_latest_scan(current_devices)
save_scan_history(current_devices)