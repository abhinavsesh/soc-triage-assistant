"""Build a small, whitelisted, sanitised evidence packet from an alert."""
import ipaddress
import re

IP_FIELDS = {"src_ip", "success_ip"}
INVALID_IP = "invalid_ip_value"

MAX_STR = 64
MAX_OBSERVATIONS = 5
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_ALLOWED = re.compile(r"[^A-Za-z0-9_.:@\- ]")


def sanitise(value):
    """Untrusted text -> short, plain, low-risk string. Lossy on purpose."""
    s = _CTRL.sub(" ", str(value))
    s = _ALLOWED.sub("?", s)
    return s[:MAX_STR]


def _valid_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def clean_field(key, value):
    """Typed fields are validated, not cleaned. Numbers pass, IP fields must be IPs."""
    if isinstance(value, (int, float)):
        return value
    if key in IP_FIELDS:
        return str(value) if _valid_ip(value) else INVALID_IP
    return sanitise(value)


def clean_entity(entity):
    """An ip: entity must contain a valid IP. Other entities are plain sanitised text."""
    kind, _, rest = entity.partition(":")
    if kind == "ip":
        ip, sep, port = rest.partition(":port:")
        if not _valid_ip(ip):
            return f"ip:{INVALID_IP}{sep}{sanitise(port)}"
    return sanitise(entity)


def build_evidence(alert):
    """Whitelist only. Our numbers and labels pass; text from logs is sanitised."""
    packet = {
        "entity_type": alert["entity"].split(":")[0],
        "entity": clean_entity(alert["entity"]),  # untrusted: built from log text
        "kind": alert["kind"],
        "first_seen": sanitise(alert["first_seen"]),
        "risk_score": int(alert["risk_score"]),
        "severity": alert["severity"],
        "signals": list(alert["signals"]),
        "score_breakdown": {k: int(v) for k, v in alert["score_breakdown"].items()},
        "mitre": [
            {"id": m["id"], "name": m["name"], "confidence": m["confidence"]}
            for m in alert["mitre"]
        ],
        "facts": {},
    }
    for scenario, observations in alert.get("evidence", {}).items():
        shown = [
            {k: clean_field(k, v) for k, v in obs.items()}
            for obs in observations[:MAX_OBSERVATIONS]
        ]
        packet["facts"][scenario] = {"total_observations": len(observations), "shown": shown}
    return packet
