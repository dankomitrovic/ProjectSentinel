"""Project Sentinel service exposure intelligence.

Turns observed TCP services into analyst-friendly findings without claiming
that a vulnerability has been confirmed. Results are based on exposed ports,
validation status and device context from the latest Sentinel snapshot.
"""

SERVICE_KNOWLEDGE = {
    21: ("File transfer", "High", "FTP commonly exposes credentials or data when used without encryption.", "Disable FTP where possible or replace it with SFTP/SSH-based transfer."),
    22: ("Remote administration", "Low", "SSH provides remote administration and should only be exposed where required.", "Use key-based authentication, disable password login where practical, and restrict source addresses."),
    23: ("Legacy remote administration", "Critical", "Telnet sends sessions without modern transport protection and is unsafe on untrusted networks.", "Disable Telnet and use SSH or a vendor-supported secure management method."),
    25: ("Mail service", "Medium", "SMTP exposure may be legitimate but can be abused when relay or authentication settings are weak.", "Confirm the service is expected, prevent open relay, and require authenticated encrypted connections."),
    53: ("Name resolution", "Low", "DNS is normal on infrastructure but unexpected DNS listeners can indicate misconfiguration.", "Confirm the device is an approved DNS server and restrict recursion to trusted clients."),
    80: ("Web administration", "Medium", "Unencrypted HTTP may expose management sessions or device information.", "Prefer HTTPS, disable plain HTTP where supported, and restrict management access."),
    110: ("Legacy mail access", "High", "POP3 commonly transmits credentials without encryption when TLS is not enforced.", "Disable plain POP3 or require POP3S/TLS."),
    139: ("Windows file sharing", "High", "NetBIOS file sharing increases lateral-movement and information-disclosure exposure.", "Disable NetBIOS where unnecessary and restrict file-sharing access with host firewalls."),
    143: ("Mail access", "Medium", "IMAP should use encrypted authentication and transport.", "Require TLS or use IMAPS and remove unencrypted access."),
    443: ("Secure web service", "Low", "HTTPS is commonly expected, but administrative interfaces still require patching and access control.", "Confirm the interface is expected, patched, and protected by strong authentication."),
    445: ("Windows file sharing", "High", "SMB is a frequent lateral-movement target and should not be broadly reachable.", "Restrict SMB to required hosts, disable SMBv1, and keep the operating system patched."),
    554: ("Media streaming", "Medium", "RTSP is common on cameras and media devices but may expose streams or weak authentication.", "Require authentication, update firmware, and isolate the device on an IoT network where possible."),
    631: ("Printing", "Low", "IPP is normal for printers but unnecessary administrative exposure should be limited.", "Restrict printer access to trusted devices and keep printer firmware current."),
    1883: ("IoT messaging", "High", "Unencrypted MQTT may permit unauthorised publishing, subscription, or data disclosure.", "Use MQTT authentication and TLS, or isolate the broker from untrusted clients."),
    3389: ("Remote desktop", "Critical", "RDP is a high-value remote-access target when broadly exposed.", "Restrict RDP with firewall rules or VPN, enable Network Level Authentication, MFA where available, and patch promptly."),
    5000: ("Application service", "Medium", "Port 5000 often hosts development or device management applications.", "Confirm the application is intended, avoid development servers, and restrict access."),
    5001: ("Secure application service", "Low", "Port 5001 often hosts a secured management or application service.", "Confirm ownership, certificate validity, patch level, and access controls."),
    5353: ("Service discovery", "Low", "mDNS reveals service and device information to the local network.", "Disable unnecessary discovery and segment IoT devices where practical."),
    8000: ("Alternate web service", "Medium", "Alternate web ports often expose development or management interfaces.", "Identify the application, patch it, require authentication, and restrict network access."),
    8080: ("Alternate web service", "Medium", "Port 8080 commonly exposes proxies, applications, or management interfaces.", "Confirm the service is expected and protect it with authentication, TLS, and access restrictions."),
    8443: ("Secure management service", "Low", "Port 8443 commonly hosts an HTTPS management interface.", "Verify the certificate, software version, authentication controls, and intended exposure."),
    8883: ("Secure IoT messaging", "Low", "MQTT over TLS is preferable, though broker authentication and authorisation still matter.", "Confirm TLS validation, strong credentials, and topic-level access controls."),
    9100: ("Raw printing", "Medium", "Raw printer services may accept unauthenticated print jobs and reveal device behaviour.", "Restrict access to approved print clients and isolate the printer from guest networks."),
}

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
STATUS_FACTOR = {"OPEN": 1.0, "PROBABLE": 0.65, "UNVERIFIED": 0.35}


def _downgrade(severity, steps=1):
    levels = ["Info", "Low", "Medium", "High", "Critical"]
    index = levels.index(severity) if severity in levels else 1
    return levels[max(0, index - steps)]


def build_exposure_intelligence(device):
    """Return exposure summary and per-service analyst findings."""
    services = device.get("open_ports", []) or []
    findings = []
    weighted_score = 0

    for service in services:
        try:
            port = int(service.get("port", 0) or 0)
        except (TypeError, ValueError):
            port = 0

        status = str(service.get("status", "UNVERIFIED") or "UNVERIFIED").upper()
        name = str(service.get("service", "Unknown service") or "Unknown service")
        protocol = str(service.get("protocol", "TCP") or "TCP").upper()
        category, severity, explanation, remediation = SERVICE_KNOWLEDGE.get(
            port,
            ("Unclassified service", "Medium", "An unclassified network service is reachable and requires analyst validation.", "Identify the listening application, confirm business need, patch it, and restrict access where possible.")
        )

        if status == "PROBABLE":
            effective_severity = _downgrade(severity, 1)
            confidence_note = "Service presence is probable rather than application-confirmed."
        elif status == "UNVERIFIED":
            effective_severity = _downgrade(severity, 2)
            confidence_note = "Service presence is unverified and should be manually confirmed."
        else:
            effective_severity = severity
            confidence_note = "Service was reported as open by the latest scan."

        points = round(SEVERITY_ORDER.get(effective_severity, 1) * 10 * STATUS_FACTOR.get(status, 0.35))
        weighted_score += points
        findings.append({
            "port": port,
            "protocol": protocol,
            "service": name,
            "category": category,
            "severity": effective_severity,
            "status": status,
            "confidence": str(service.get("confidence", "Low") or "Low"),
            "explanation": explanation,
            "confidence_note": confidence_note,
            "remediation": remediation,
        })

    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item["severity"], 0), item["port"]))
    exposure_score = min(100, weighted_score)
    if not findings:
        rating = "Minimal"
        headline = "No exposed TCP services detected"
    elif any(item["severity"] == "Critical" for item in findings):
        rating = "Critical"
        headline = "Critical remote or legacy exposure requires review"
    elif any(item["severity"] == "High" for item in findings):
        rating = "High"
        headline = "High-risk network services require review"
    elif any(item["severity"] == "Medium" for item in findings):
        rating = "Moderate"
        headline = "Network services should be validated"
    else:
        rating = "Low"
        headline = "Limited service exposure detected"

    return {
        "score": exposure_score,
        "rating": rating,
        "headline": headline,
        "finding_count": len(findings),
        "critical_count": sum(1 for item in findings if item["severity"] == "Critical"),
        "high_count": sum(1 for item in findings if item["severity"] == "High"),
        "review_count": sum(1 for item in findings if item["severity"] in {"Critical", "High", "Medium"}),
        "findings": findings,
        "disclaimer": "Exposure intelligence identifies service-related risk indicators; it does not confirm a software vulnerability or CVE."
    }
