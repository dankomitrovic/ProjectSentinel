"""
Project Sentinel service discovery.

This module performs lightweight TCP connection scans against
devices already discovered on the local network.

It does not exploit services, bypass authentication or send
application payloads.
"""

import ipaddress
import socket

from logger import log_debug, log_info, log_warning


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1883: "MQTT",
    3389: "RDP",
    5000: "Web Service",
    5001: "Secure Web Service",
    5353: "mDNS",
    8000: "Alternate HTTP",
    8080: "Alternate HTTP",
    8443: "Alternate HTTPS",
    8883: "Secure MQTT",
    9100: "JetDirect Printer"
}

DEFAULT_TIMEOUT = 0.25


def is_private_address(ip_address):
    """
    Return True when the supplied address is a valid private IP address.
    """

    try:
        address = ipaddress.ip_address(ip_address)
        return address.is_private

    except ValueError:
        return False


def scan_tcp_port(ip_address, port, timeout=DEFAULT_TIMEOUT):
    """
    Test whether one TCP port accepts a connection.

    Returns:
        True when the port is open.
        False when the port is closed, filtered or unreachable.
    """

    if not is_private_address(ip_address):
        log_warning(
            f"Port scan skipped for non-private or invalid address: "
            f"{ip_address}"
        )
        return False

    if not isinstance(port, int) or port < 1 or port > 65535:
        log_warning(
            f"Port scan skipped because the port is invalid: {port}"
        )
        return False

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as tcp_socket:
            tcp_socket.settimeout(timeout)

            result = tcp_socket.connect_ex(
                (ip_address, port)
            )

            return result == 0

    except OSError as error:
        log_debug(
            f"TCP connection test failed for "
            f"{ip_address}:{port}: {error}"
        )

        return False


def scan_device_ports(
    ip_address,
    services=None,
    timeout=DEFAULT_TIMEOUT
):
    """
    Scan one private IP address for selected TCP services.

    Args:
        ip_address:
            The private IP address to scan.

        services:
            Optional dictionary mapping port numbers to service names.
            COMMON_SERVICES is used when no dictionary is supplied.

        timeout:
            Maximum connection time for each port.

    Returns:
        A list of dictionaries describing open ports.
    """

    if services is None:
        services = COMMON_SERVICES

    if not is_private_address(ip_address):
        log_warning(
            f"Service discovery skipped for non-private or invalid "
            f"address: {ip_address}"
        )
        return []

    log_debug(
        f"Beginning service discovery for {ip_address} "
        f"across {len(services)} TCP port(s)"
    )

    open_ports = []

    for port, service_name in services.items():
        if scan_tcp_port(ip_address, port, timeout):
            open_port = {
                "port": port,
                "protocol": "TCP",
                "service": service_name
            }

            open_ports.append(open_port)

            log_debug(
                f"Open service identified on {ip_address}: "
                f"{port}/TCP {service_name}"
            )

    log_debug(
        f"Service discovery completed for {ip_address}: "
        f"{len(open_ports)} open TCP port(s)"
    )

    return open_ports


def scan_devices(devices, services=None, timeout=DEFAULT_TIMEOUT):
    """
    Perform service discovery for discovered local devices.

    Each returned dictionary preserves the original device fields
    and adds an open_ports field.
    """

    log_info(
        f"Starting service discovery for {len(devices)} device(s)"
    )

    scanned_devices = []

    for device in devices:
        scanned_device = device.copy()
        ip_address = device.get("ip_address")

        scanned_device["open_ports"] = scan_device_ports(
            ip_address,
            services,
            timeout
        )

        scanned_devices.append(scanned_device)

    total_open_ports = sum(
        len(device["open_ports"])
        for device in scanned_devices
    )

    log_info(
        f"Service discovery completed with "
        f"{total_open_ports} open TCP port(s) identified"
    )

    return scanned_devices