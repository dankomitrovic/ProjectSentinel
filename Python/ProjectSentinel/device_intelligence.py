"""
Project Sentinel device intelligence.

This module enriches discovered devices with additional information.

Mission Lima provides device enrichment including:

- MAC vendor identification
- Hostname resolution
- Basic device-type fingerprinting
"""

import socket

from mac_vendor_lookup import MacLookup, VendorNotFoundError

from config import ENABLE_VENDOR_LOOKUP, UNKNOWN_VENDOR_NAME
from logger import log_debug, log_warning


_mac_lookup = MacLookup()


def lookup_vendor(mac_address):
    """
    Return the manufacturer associated with a MAC address.

    If the vendor cannot be identified, return the configured
    unknown vendor value.
    """

    if not ENABLE_VENDOR_LOOKUP:
        log_debug("MAC vendor lookup is disabled")
        return UNKNOWN_VENDOR_NAME

    if not mac_address:
        log_debug(
            "Vendor lookup skipped because no MAC address was supplied"
        )
        return UNKNOWN_VENDOR_NAME

    try:
        vendor = _mac_lookup.lookup(mac_address)

        log_debug(
            f"Vendor identified for {mac_address}: {vendor}"
        )

        return vendor

    except VendorNotFoundError:
        log_debug(
            f"No vendor record found for {mac_address}"
        )

        return UNKNOWN_VENDOR_NAME

    except ValueError:
        log_warning(
            f"Invalid MAC address supplied for vendor lookup: "
            f"{mac_address}"
        )

        return UNKNOWN_VENDOR_NAME


def lookup_hostname(ip_address):
    """
    Attempt to resolve the hostname for an IP address.

    Returns:
        The resolved hostname or "Unknown" if no hostname
        can be determined.
    """

    if not ip_address:
        log_debug(
            "Hostname lookup skipped because no IP address was supplied"
        )
        return "Unknown"

    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)

        log_debug(
            f"Hostname identified for {ip_address}: {hostname}"
        )

        return hostname

    except (socket.herror, socket.gaierror):
        log_debug(
            f"No hostname found for {ip_address}"
        )

        return "Unknown"

    except OSError as error:
        log_warning(
            f"Hostname lookup failed for {ip_address}: {error}"
        )

        return "Unknown"


def fingerprint_device_type(hostname, vendor, ip_address):
    """
    Estimate a device type using available device intelligence.

    The result is intentionally conservative because hostname and
    vendor information alone cannot provide definitive identification.

    Returns:
        A dictionary containing:

        detected_device_type
        detection_confidence
        detection_reason
    """

    hostname_text = str(hostname or "").strip().lower()
    vendor_text = str(vendor or "").strip().lower()
    ip_text = str(ip_address or "").strip().lower()

    infrastructure_hostname_terms = (
        "gateway",
        "router",
        "dhcp",
        "dns",
        "firewall",
        "switch",
        "access-point",
        "accesspoint",
        "modem"
    )

    printer_hostname_terms = (
        "printer",
        "print",
        "laserjet",
        "officejet",
        "deskjet",
        "brother",
        "epson"
    )

    camera_hostname_terms = (
        "camera",
        "cam",
        "cctv",
        "doorbell",
        "nvr",
        "dvr"
    )

    television_hostname_terms = (
        "tv",
        "television",
        "chromecast",
        "firetv",
        "appletv",
        "roku"
    )

    nas_hostname_terms = (
        "nas",
        "synology",
        "qnap",
        "storage"
    )

    phone_hostname_terms = (
        "iphone",
        "android",
        "phone",
        "pixel",
        "galaxy"
    )

    computer_hostname_terms = (
        "desktop",
        "laptop",
        "macbook",
        "imac",
        "computer",
        "workstation",
        "pc-"
    )

    infrastructure_vendor_terms = (
        "cisco",
        "netgear",
        "ubiquiti",
        "aruba",
        "mikrotik",
        "tp-link",
        "d-link",
        "juniper"
    )

    printer_vendor_terms = (
        "hewlett packard",
        "hp inc",
        "brother",
        "epson",
        "canon",
        "xerox",
        "lexmark"
    )

    camera_vendor_terms = (
        "hikvision",
        "dahua",
        "reolink",
        "arlo",
        "axis",
        "ring"
    )

    nas_vendor_terms = (
        "synology",
        "qnap"
    )

    if any(
        term in hostname_text
        for term in infrastructure_hostname_terms
    ):
        result = {
            "detected_device_type": "Infrastructure",
            "detection_confidence": "High",
            "detection_reason": "Infrastructure keyword in hostname"
        }

    elif any(
        term in hostname_text
        for term in printer_hostname_terms
    ):
        result = {
            "detected_device_type": "Printer",
            "detection_confidence": "High",
            "detection_reason": "Printer keyword in hostname"
        }

    elif any(
        term in hostname_text
        for term in camera_hostname_terms
    ):
        result = {
            "detected_device_type": "Camera",
            "detection_confidence": "High",
            "detection_reason": "Camera keyword in hostname"
        }

    elif any(
        term in hostname_text
        for term in television_hostname_terms
    ):
        result = {
            "detected_device_type": "Smart TV",
            "detection_confidence": "High",
            "detection_reason": "Television keyword in hostname"
        }

    elif any(
        term in hostname_text
        for term in nas_hostname_terms
    ):
        result = {
            "detected_device_type": "NAS",
            "detection_confidence": "High",
            "detection_reason": "Storage keyword in hostname"
        }

    elif any(
        term in hostname_text
        for term in phone_hostname_terms
    ):
        result = {
            "detected_device_type": "Phone",
            "detection_confidence": "Medium",
            "detection_reason": "Phone keyword in hostname"
        }

    elif any(
        term in hostname_text
        for term in computer_hostname_terms
    ):
        result = {
            "detected_device_type": "Computer",
            "detection_confidence": "Medium",
            "detection_reason": "Computer keyword in hostname"
        }

    elif any(
        term in vendor_text
        for term in infrastructure_vendor_terms
    ):
        result = {
            "detected_device_type": "Infrastructure",
            "detection_confidence": "Medium",
            "detection_reason": "Network equipment vendor identified"
        }

    elif any(
        term in vendor_text
        for term in printer_vendor_terms
    ):
        result = {
            "detected_device_type": "Printer",
            "detection_confidence": "Low",
            "detection_reason": "Vendor commonly manufactures printers"
        }

    elif any(
        term in vendor_text
        for term in camera_vendor_terms
    ):
        result = {
            "detected_device_type": "Camera",
            "detection_confidence": "Medium",
            "detection_reason": "Camera equipment vendor identified"
        }

    elif any(
        term in vendor_text
        for term in nas_vendor_terms
    ):
        result = {
            "detected_device_type": "NAS",
            "detection_confidence": "Medium",
            "detection_reason": "Network storage vendor identified"
        }

    elif ip_text.startswith("10.0.2.") and hostname_text == "unknown":
        result = {
            "detected_device_type": "Infrastructure",
            "detection_confidence": "Low",
            "detection_reason": "VirtualBox NAT infrastructure address"
        }

    else:
        result = {
            "detected_device_type": "Unknown",
            "detection_confidence": "Low",
            "detection_reason": "Insufficient device intelligence"
        }

    log_debug(
        f"Device type fingerprint completed for {ip_address}: "
        f"type={result['detected_device_type']}, "
        f"confidence={result['detection_confidence']}, "
        f"reason={result['detection_reason']}"
    )

    return result


def enrich_devices(devices):
    """
    Add device-intelligence information to discovered devices.

    Each returned dictionary contains the original device
    information plus enrichment and fingerprinting fields.
    """

    log_debug(
        f"Beginning device intelligence enrichment for "
        f"{len(devices)} device(s)"
    )

    enriched_devices = []

    for device in devices:
        enriched_device = device.copy()

        enriched_device["vendor"] = lookup_vendor(
            device.get("mac_address")
        )

        enriched_device["hostname"] = lookup_hostname(
            device.get("ip_address")
        )

        fingerprint = fingerprint_device_type(
            enriched_device["hostname"],
            enriched_device["vendor"],
            device.get("ip_address")
        )

        enriched_device["detected_device_type"] = (
            fingerprint["detected_device_type"]
        )

        enriched_device["detection_confidence"] = (
            fingerprint["detection_confidence"]
        )

        enriched_device["detection_reason"] = (
            fingerprint["detection_reason"]
        )

        enriched_devices.append(enriched_device)

        log_debug(
            f"Enriched device "
            f"{enriched_device.get('ip_address')} "
            f"({enriched_device.get('mac_address')}): "
            f"vendor={enriched_device['vendor']}, "
            f"hostname={enriched_device['hostname']}, "
            f"detected_type="
            f"{enriched_device['detected_device_type']}, "
            f"confidence="
            f"{enriched_device['detection_confidence']}"
        )

    log_debug(
        f"Device intelligence enrichment completed for "
        f"{len(enriched_devices)} device(s)"
    )

    return enriched_devices