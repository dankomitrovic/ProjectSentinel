"""
Project Sentinel automatic network detection.

This module identifies the active network interface and IPv4 subnet
used for the system's default route.
"""

import ipaddress
import subprocess

from logger import log_debug, log_info, log_warning


def run_ip_command(arguments):
    """
    Run an Linux ip command and return its standard output.
    """

    result = subprocess.run(
        ["ip"] + arguments,
        capture_output=True,
        text=True,
        check=True
    )

    return result.stdout.strip()


def detect_default_interface():
    """
    Return the interface used by the system's default route.
    """

    route_output = run_ip_command(
        ["route", "show", "default"]
    )

    for route_line in route_output.splitlines():
        route_parts = route_line.split()

        if "dev" not in route_parts:
            continue

        interface_index = route_parts.index("dev") + 1

        if interface_index < len(route_parts):
            interface_name = route_parts[interface_index]

            log_debug(
                f"Default network interface detected: "
                f"{interface_name}"
            )

            return interface_name

    raise RuntimeError(
        "Sentinel could not identify a default network interface."
    )


def detect_interface_address(interface_name):
    """
    Return the active IPv4 address and prefix for an interface.
    """

    address_output = run_ip_command(
        [
            "-o",
            "-f",
            "inet",
            "addr",
            "show",
            "dev",
            interface_name,
            "scope",
            "global"
        ]
    )

    for address_line in address_output.splitlines():
        address_parts = address_line.split()

        if "inet" not in address_parts:
            continue

        address_index = address_parts.index("inet") + 1

        if address_index < len(address_parts):
            interface_address = address_parts[address_index]

            log_debug(
                f"Interface IPv4 address detected: "
                f"{interface_address}"
            )

            return interface_address

    raise RuntimeError(
        f"Sentinel could not identify an IPv4 address for "
        f"{interface_name}."
    )


def detect_active_network():
    """
    Detect and return information about the active IPv4 network.
    """

    interface_name = detect_default_interface()

    interface_address = detect_interface_address(
        interface_name
    )

    ipv4_interface = ipaddress.ip_interface(
        interface_address
    )

    network_details = {
        "interface": interface_name,
        "ip_address": str(ipv4_interface.ip),
        "prefix_length": ipv4_interface.network.prefixlen,
        "network": str(ipv4_interface.network)
    }

    log_info(
        f"Automatically detected active network "
        f"{network_details['network']} on "
        f"{network_details['interface']}"
    )

    return network_details


def resolve_scan_network(fallback_network=None):
    """
    Return the automatically detected network or a configured fallback.
    """

    try:
        network_details = detect_active_network()

        return network_details["network"]

    except (
        OSError,
        subprocess.CalledProcessError,
        ValueError,
        RuntimeError
    ) as error:
        log_warning(
            f"Automatic network detection failed: {error}"
        )

        if fallback_network:
            log_warning(
                f"Using configured fallback network: "
                f"{fallback_network}"
            )

            return fallback_network

        raise RuntimeError(
            "No network could be detected and no fallback "
            "network was configured."
        )
