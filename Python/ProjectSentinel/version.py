"""
Project Sentinel application information.

This module stores application metadata in one location.

Keeping version information centralised ensures every part of
Sentinel displays the same application identity.
"""

APPLICATION_NAME = "PROJECT SENTINEL"
APPLICATION_DESCRIPTION = "Network Discovery and Trusted Device Monitoring"

VERSION = "0.5.0"
STATUS = "Alpha"

AUTHOR = "Danko Mitrovic"
COPYRIGHT_YEAR = "2026"


def get_banner():
    """
    Build and return Sentinel's application banner.
    """

    banner = [
        "",
        "=" * 60,
        APPLICATION_NAME,
        APPLICATION_DESCRIPTION,
        f"Version : {VERSION}",
        f"Status  : {STATUS}",
        "=" * 60
    ]

    return "\n".join(banner)