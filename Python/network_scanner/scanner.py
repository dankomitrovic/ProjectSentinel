"""
Project Sentinel network scanner.

This module discovers devices on the local network using ARP.
It does not decide whether devices are trusted and does not save files.
"""

from scapy.all import ARP, Ether, srp

from config import SCAN_TIMEOUT, TARGET_NETWORK


def discover_devices():
    """
    Discover devices that respond to an ARP request.

    Returns:
        A list of dictionaries containing IP and MAC addresses.
    """

    # Create an ARP request asking every address in the target network
    # to identify the device that owns it.
    arp_request = ARP(pdst=TARGET_NETWORK)

    # Ethernet broadcasts use FF:FF:FF:FF:FF:FF so every device on the
    # local network segment receives the request.
    ethernet_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the Ethernet frame and ARP request into one packet.
    packet = ethernet_broadcast / arp_request

    # Send the packet and collect the devices that answered.
    answered, unanswered = srp(
        packet,
        timeout=SCAN_TIMEOUT,
        verbose=False
    )

    devices = []

    # Convert Scapy response objects into simple Python dictionaries.
    # Other Sentinel modules should not need to understand Scapy packets.
    for sent_packet, received_packet in answered:
        device = {
            "ip_address": received_packet.psrc,
            "mac_address": received_packet.hwsrc.lower()
        }

        devices.append(device)

    return devices