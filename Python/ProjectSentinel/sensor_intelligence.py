"""Sensor intelligence, health scoring and trend analysis for Project Sentinel."""

from datetime import datetime, timedelta


def _parse_timestamp(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _status(label, severity, message):
    return {"label": label, "severity": severity, "message": message}


def classify_temperature(value):
    if value is None:
        return _status("No data", "unknown", "No temperature reading has been received.")
    if value < 5:
        return _status("Critical low", "critical", "Potential freezing or sensor placement issue.")
    if value < 15:
        return _status("Cool", "warning", "Below the preferred indoor operating range.")
    if value <= 27:
        return _status("Normal", "normal", "Within the preferred indoor operating range.")
    if value <= 32:
        return _status("Warm", "warning", "Elevated temperature; monitor for sustained heat.")
    return _status("Critical high", "critical", "High temperature requires prompt investigation.")


def classify_humidity(value):
    if value is None:
        return _status("No data", "unknown", "No humidity reading has been received.")
    if value < 25:
        return _status("Very dry", "warning", "Air is unusually dry for an occupied indoor space.")
    if value < 35:
        return _status("Dry", "advisory", "Humidity is below the preferred comfort range.")
    if value <= 60:
        return _status("Comfortable", "normal", "Humidity is within the preferred indoor range.")
    if value <= 70:
        return _status("Humid", "warning", "Humidity is elevated; monitor ventilation and condensation.")
    return _status("Critical humidity", "critical", "Sustained high humidity may increase mould or condensation risk.")


def classify_rssi(value):
    if value is None:
        return _status("No data", "unknown", "No Wi-Fi signal reading has been received.")
    if value >= -55:
        return _status("Excellent", "normal", "Strong and reliable Wi-Fi signal.")
    if value >= -67:
        return _status("Good", "normal", "Suitable signal for reliable telemetry.")
    if value >= -75:
        return _status("Fair", "advisory", "Usable signal, but packet loss may increase.")
    return _status("Weak", "warning", "Relocate the node or improve Wi-Fi coverage.")


def _heartbeat_points(agent):
    age = agent.get("age_seconds")
    if age is None:
        return 0
    if age <= 45:
        return 35
    if age <= 90:
        return 28
    if age <= 180:
        return 12
    return 0


def _wifi_points(value):
    if value is None:
        return 0
    if value >= -55:
        return 20
    if value >= -67:
        return 17
    if value >= -75:
        return 11
    if value >= -85:
        return 5
    return 1


def _sensor_points(latest):
    return (10 if latest.get("temperature") is not None else 0) + (10 if latest.get("humidity") is not None else 0)


def _firmware_points(agent):
    firmware = str(agent.get("firmware") or "").strip().lower()
    return 15 if firmware and firmware != "unknown" else 0


def _environment_points(temperature_status, humidity_status):
    severity_points = {"normal": 5, "advisory": 4, "warning": 2, "critical": 0, "unknown": 0}
    return severity_points.get(temperature_status["severity"], 0) + severity_points.get(humidity_status["severity"], 0)


def _health_score(agent, temperature_status, humidity_status):
    latest = agent.get("latest") or {}
    components = {
        "heartbeat": _heartbeat_points(agent),
        "wifi": _wifi_points(latest.get("rssi")),
        "sensors": _sensor_points(latest),
        "firmware": _firmware_points(agent),
        "environment": _environment_points(temperature_status, humidity_status),
    }
    return sum(components.values()), components


def _health_label(score):
    if score >= 90:
        return "Excellent", "normal"
    if score >= 75:
        return "Good", "normal"
    if score >= 55:
        return "Attention", "warning"
    return "At risk", "critical"


def _build_points(values, width=300, height=74):
    numeric = [value for value in values if value is not None]
    if len(numeric) < 2:
        return "", None, None
    minimum = min(numeric)
    maximum = max(numeric)
    spread = maximum - minimum or 1
    count = len(values)
    points = []
    for index, value in enumerate(values):
        if value is None:
            continue
        x = 0 if count == 1 else (index / (count - 1)) * width
        y = height - ((value - minimum) / spread) * (height - 8) - 4
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points), round(minimum, 1), round(maximum, 1)


def _trend(records, field, unit):
    values = [record.get(field) for record in records]
    points, minimum, maximum = _build_points(values)
    latest = next((value for value in reversed(values) if value is not None), None)
    previous = next((value for value in reversed(values[:-1]) if value is not None), None)
    change = None if latest is None or previous is None else round(latest - previous, 1)
    return {
        "field": field,
        "unit": unit,
        "points": points,
        "minimum": minimum,
        "maximum": maximum,
        "latest": latest,
        "change": change,
        "sample_count": len([value for value in values if value is not None]),
    }


def _motion_context(records, now):
    motion_records = [record for record in records if record.get("motion")]
    last_motion = motion_records[-1] if motion_records else None
    latest = records[-1] if records else None
    active = bool(latest and latest.get("motion"))
    active_since = None
    if active:
        for record in reversed(records):
            if not record.get("motion"):
                break
            active_since = record.get("timestamp")
    active_seconds = None
    active_timestamp = _parse_timestamp(active_since)
    if active_timestamp is not None:
        active_seconds = max(0, int((now - active_timestamp.astimezone()).total_seconds()))
    return {
        "active": active,
        "active_since": active_since,
        "active_seconds": active_seconds,
        "last_motion": last_motion.get("timestamp") if last_motion else None,
        "active_samples_24h": len(motion_records),
    }


def _relative_age(seconds):
    if seconds is None:
        return "Never"
    if seconds < 5:
        return "Just now"
    if seconds < 60:
        return f"{seconds} sec ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    return f"{hours} hr ago"


def build_sensor_intelligence(agents, telemetry, hours=24):
    now = datetime.now().astimezone()
    cutoff = now - timedelta(hours=hours)
    recent = []
    for record in telemetry:
        timestamp = _parse_timestamp(record.get("timestamp"))
        if timestamp is not None and timestamp.astimezone() >= cutoff:
            recent.append(record)
    recent.sort(key=lambda item: item.get("timestamp", ""))

    enriched = []
    alerts = []
    for agent in agents:
        latest = agent.get("latest") or {}
        temperature = classify_temperature(latest.get("temperature"))
        humidity = classify_humidity(latest.get("humidity"))
        rssi = classify_rssi(latest.get("rssi"))
        score, components = _health_score(agent, temperature, humidity)
        health_label, health_severity = _health_label(score)
        records = [item for item in recent if item.get("agent_id") == agent.get("agent_id")]
        motion = _motion_context(records, now)

        item = dict(agent)
        item["heartbeat_label"] = _relative_age(agent.get("age_seconds"))
        item["intelligence"] = {
            "health_score": score,
            "health_label": health_label,
            "health_severity": health_severity,
            "health_components": components,
            "temperature": temperature,
            "humidity": humidity,
            "rssi": rssi,
            "motion": motion,
            "motion_count_24h": motion["active_samples_24h"],
            "trends": {
                "temperature": _trend(records, "temperature", "°C"),
                "humidity": _trend(records, "humidity", "%"),
                "rssi": _trend(records, "rssi", " dBm"),
            },
        }
        enriched.append(item)

        if not agent.get("online"):
            alerts.append({"severity": "critical", "agent": agent, "title": "Node offline", "message": "No heartbeat was received within 90 seconds."})
        for title, classification in (("Temperature", temperature), ("Humidity", humidity), ("Wi-Fi signal", rssi)):
            if classification["severity"] in {"warning", "critical"}:
                alerts.append({"severity": classification["severity"], "agent": agent, "title": title, "message": classification["message"]})
        if motion["active"]:
            alerts.append({"severity": "advisory", "agent": agent, "title": "Motion active", "message": "The PIR sensor currently reports motion."})

    severity_order = {"critical": 0, "warning": 1, "advisory": 2, "normal": 3}
    alerts.sort(key=lambda item: severity_order.get(item["severity"], 9))
    fleet_score = round(sum(item["intelligence"]["health_score"] for item in enriched) / len(enriched)) if enriched else 0
    if fleet_score >= 90:
        posture = "Excellent"
    elif fleet_score >= 75:
        posture = "Good"
    elif fleet_score >= 55:
        posture = "Attention"
    else:
        posture = "At risk"

    latest_record = recent[-1] if recent else None
    last_motion_record = next((item for item in reversed(recent) if item.get("motion")), None)
    operations = {
        "api": {"label": "Operational", "severity": "normal"},
        "storage": {"label": "Operational", "severity": "normal"},
        "fleet": {"label": f"{sum(1 for item in enriched if item.get('online'))}/{len(enriched)} online", "severity": "normal" if enriched and all(item.get("online") for item in enriched) else "warning"},
        "last_telemetry": latest_record.get("timestamp") if latest_record else None,
        "last_motion": last_motion_record.get("timestamp") if last_motion_record else None,
        "server_time": now.isoformat(timespec="seconds"),
    }

    return {
        "agents": enriched,
        "alerts": alerts,
        "fleet_score": fleet_score,
        "posture": posture,
        "window_hours": hours,
        "telemetry_samples": len(recent),
        "operations": operations,
    }
