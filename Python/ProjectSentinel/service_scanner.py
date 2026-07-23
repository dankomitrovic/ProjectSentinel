"""
Project Sentinel service discovery.

This module performs lightweight TCP connection checks against
devices already discovered on the local network.

Successful connections are repeated to reduce false positives.
Where a service sends a banner automatically, Sentinel may inspect
that banner without sending commands, credentials or application data.

It does not exploit services, bypass authentication or attempt
service authentication.
"""

import ipaddress
import socket
import time

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

PASSIVE_BANNER_PORTS = {
    21,
    22,
    23,
    25,
    110,
    143
}

EXPECTED_BANNER_TEXT = {
    21: ["ftp"],
    22: ["ssh"],
    23: ["telnet"],
    25: ["smtp", "mail", "esmtp"],
    110: ["pop3", "+ok"],
    143: ["imap", "* ok"]
}

DEFAULT_TIMEOUT = 0.25
DEFAULT_VALIDATION_ATTEMPTS = 3
MAXIMUM_BANNER_BYTES = 256


def is_private_address(ip_address):
    """
    Return True when the supplied address is a valid private IP address.
    """

    try:
        address = ipaddress.ip_address(ip_address)
        return address.is_private

    except ValueError:
        return False


def is_valid_port(port):
    """
    Return True when the supplied value is a valid TCP port number.
    """

    return isinstance(port, int) and 1 <= port <= 65535


def test_tcp_connection(
    ip_address,
    port,
    timeout=DEFAULT_TIMEOUT,
    read_banner=False
):
    """
    Perform one TCP connection test.

    Args:
        ip_address:
            Private IP address to test.

        port:
            TCP port number.

        timeout:
            Maximum connection and banner-read time.

        read_banner:
            Attempt to read data automatically sent by the service.

    Returns:
        A dictionary containing:

            connected:
                True when the TCP connection succeeded.

            response_time_ms:
                Approximate TCP connection time in milliseconds.

            banner:
                Passive service banner text when available.
    """

    result = {
        "connected": False,
        "response_time_ms": None,
        "banner": ""
    }

    if not is_private_address(ip_address):
        log_warning(
            f"TCP connection test skipped for non-private or invalid "
            f"address: {ip_address}"
        )
        return result

    if not is_valid_port(port):
        log_warning(
            f"TCP connection test skipped because the port is invalid: "
            f"{port}"
        )
        return result

    started_at = time.perf_counter()

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as tcp_socket:
            tcp_socket.settimeout(timeout)

            connection_result = tcp_socket.connect_ex(
                (ip_address, port)
            )

            elapsed_time = time.perf_counter() - started_at

            if connection_result != 0:
                return result

            result["connected"] = True
            result["response_time_ms"] = round(
                elapsed_time * 1000,
                2
            )

            if read_banner:
                try:
                    banner_bytes = tcp_socket.recv(
                        MAXIMUM_BANNER_BYTES
                    )

                    if banner_bytes:
                        result["banner"] = banner_bytes.decode(
                            "utf-8",
                            errors="replace"
                        ).strip()

                except socket.timeout:
                    log_debug(
                        f"No passive banner received from "
                        f"{ip_address}:{port}"
                    )

                except OSError as error:
                    log_debug(
                        f"Passive banner read failed for "
                        f"{ip_address}:{port}: {error}"
                    )

    except OSError as error:
        log_debug(
            f"TCP connection test failed for "
            f"{ip_address}:{port}: {error}"
        )

    return result


def scan_tcp_port(ip_address, port, timeout=DEFAULT_TIMEOUT):
    """
    Test whether one TCP port accepts a connection.

    This compatibility function performs one connection attempt.

    Returns:
        True when the TCP connection succeeds.
        False when it is closed, filtered or unreachable.
    """

    result = test_tcp_connection(
        ip_address,
        port,
        timeout
    )

    return result["connected"]


def banner_matches_expected_service(port, banner):
    """
    Determine whether a passive banner supports the expected service.

    Returns:
        True when expected service text is present.
        False when no expected match is found.
    """

    if not banner:
        return False

    expected_values = EXPECTED_BANNER_TEXT.get(port, [])

    if not expected_values:
        return False

    normalised_banner = banner.lower()

    for expected_value in expected_values:
        if expected_value in normalised_banner:
            return True

    return False


def determine_service_status(
    successful_attempts,
    total_attempts,
    banner_confirmed
):
    """
    Determine the confidence status of a candidate service.

    OPEN:
        All TCP checks succeeded and a passive service banner
        confirmed the expected protocol.

    PROBABLE:
        All TCP checks succeeded but the application service could
        not be confirmed passively.

    UNVERIFIED:
        At least one TCP check succeeded, but results were inconsistent.

    Returns:
        A tuple containing status and confidence.
    """

    if (
        successful_attempts == total_attempts
        and banner_confirmed
    ):
        return "OPEN", "High"

    if successful_attempts == total_attempts:
        return "PROBABLE", "Medium"

    return "UNVERIFIED", "Low"


def validate_tcp_service(
    ip_address,
    port,
    service_name,
    timeout=DEFAULT_TIMEOUT,
    attempts=DEFAULT_VALIDATION_ATTEMPTS
):
    """
    Repeat TCP checks and produce a validated service result.

    Passive banner inspection is only attempted for services that
    commonly send text immediately after a connection.

    Returns:
        A service dictionary when at least one connection succeeds.

        None when every connection attempt fails.
    """

    if not isinstance(attempts, int) or attempts < 1:
        attempts = DEFAULT_VALIDATION_ATTEMPTS

    connection_results = []
    banners = []

    for attempt_number in range(1, attempts + 1):
        read_banner = (
            port in PASSIVE_BANNER_PORTS
            and attempt_number == 1
        )

        connection_result = test_tcp_connection(
            ip_address,
            port,
            timeout,
            read_banner
        )

        connection_results.append(connection_result)

        if connection_result["banner"]:
            banners.append(connection_result["banner"])

    successful_results = [
        result
        for result in connection_results
        if result["connected"]
    ]

    successful_attempts = len(successful_results)

    if successful_attempts == 0:
        return None

    response_times = [
        result["response_time_ms"]
        for result in successful_results
        if result["response_time_ms"] is not None
    ]

    average_response_time_ms = None

    if response_times:
        average_response_time_ms = round(
            sum(response_times) / len(response_times),
            2
        )

    banner = ""

    if banners:
        banner = banners[0]

    banner_confirmed = banner_matches_expected_service(
        port,
        banner
    )

    status, confidence = determine_service_status(
        successful_attempts,
        attempts,
        banner_confirmed
    )

    validation_reason = (
        f"{successful_attempts} of {attempts} TCP connection "
        f"attempts succeeded"
    )

    if banner_confirmed:
        validation_reason += (
            " and the passive banner matched the expected service"
        )

    elif banner:
        validation_reason += (
            " but the passive banner did not confirm the expected service"
        )

    else:
        validation_reason += (
            " without passive application-level confirmation"
        )

    return {
        "port": port,
        "protocol": "TCP",
        "service": service_name,
        "status": status,
        "confidence": confidence,
        "successful_attempts": successful_attempts,
        "total_attempts": attempts,
        "response_time_ms": average_response_time_ms,
        "banner_confirmed": banner_confirmed,
        "banner": banner,
        "validation_reason": validation_reason
    }


def scan_device_ports(
    ip_address,
    services=None,
    timeout=DEFAULT_TIMEOUT,
    attempts=DEFAULT_VALIDATION_ATTEMPTS
):
    """
    Scan one private IP address for selected TCP services.

    Args:
        ip_address:
            Private IP address to scan.

        services:
            Optional dictionary mapping port numbers to service names.
            COMMON_SERVICES is used when no dictionary is supplied.

        timeout:
            Maximum connection time for each attempt.

        attempts:
            Number of TCP connection attempts for each port.

    Returns:
        A list of dictionaries describing candidate services.
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

    identified_services = []

    for port, service_name in services.items():
        if not is_valid_port(port):
            log_warning(
                f"Skipping invalid service port: {port}"
            )
            continue

        service_result = validate_tcp_service(
            ip_address,
            port,
            service_name,
            timeout,
            attempts
        )

        if service_result is None:
            continue

        identified_services.append(service_result)

        log_debug(
            f"Candidate service identified on {ip_address}: "
            f"{port}/TCP {service_name}, "
            f"status={service_result['status']}, "
            f"confidence={service_result['confidence']}, "
            f"attempts="
            f"{service_result['successful_attempts']}/"
            f"{service_result['total_attempts']}"
        )

    log_debug(
        f"Service discovery completed for {ip_address}: "
        f"{len(identified_services)} candidate TCP service(s)"
    )

    return identified_services


def scan_devices(
    devices,
    services=None,
    timeout=DEFAULT_TIMEOUT,
    attempts=DEFAULT_VALIDATION_ATTEMPTS
):
    """
    Perform service discovery for discovered local devices.

    Each returned dictionary preserves the original device fields
    and adds an open_ports field containing validated service results.
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
            timeout,
            attempts
        )

        scanned_devices.append(scanned_device)

    total_identified_services = sum(
        len(device["open_ports"])
        for device in scanned_devices
    )

    open_count = 0
    probable_count = 0
    unverified_count = 0

    for device in scanned_devices:
        for service in device["open_ports"]:
            status = service.get("status")

            if status == "OPEN":
                open_count += 1

            elif status == "PROBABLE":
                probable_count += 1

            else:
                unverified_count += 1

    log_info(
        f"Service discovery completed with "
        f"{total_identified_services} candidate TCP service(s): "
        f"open={open_count}, "
        f"probable={probable_count}, "
        f"unverified={unverified_count}"
    )

    return scanned_devices