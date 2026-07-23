"""
Project Sentinel device intelligence.

This module enriches discovered devices with additional information.

Mission Lima begins with MAC address vendor identification.
"""

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


def enrich_devices(devices):
    """
    Add device-intelligence information to discovered devices.

    Each returned dictionary contains the original device information
    plus a vendor field.
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

        enriched_devices.append(enriched_device)

        log_debug(
            f"Enriched device "
            f"{enriched_device.get('ip_address')} "
            f"({enriched_device.get('mac_address')}): "
            f"vendor={enriched_device['vendor']}"
        )

    log_debug(
        f"Device intelligence enrichment completed for "
        f"{len(enriched_devices)} device(s)"
    )

    return enriched_devices