"""Replace IPs and usernames with stable placeholders. The mapping never leaves the machine."""
import re

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)
    elif isinstance(obj, str):
        yield obj


def pseudonymise(packet):
    """Return (new_packet, mapping) where mapping is placeholder -> original value."""
    scoped = {"entity": packet["entity"], "facts": packet["facts"]}
    ips = set()
    for s in _strings(scoped):
        ips.update(IP_RE.findall(s))
    users = set()
    if packet["entity"].startswith("user:"):
        name = packet["entity"].split(":", 1)[1]
        if name:
            users.add(name)

    forward, mapping = {}, {}
    for i, ip in enumerate(sorted(ips), 1):
        forward[ip], mapping[f"ip_{i}"] = f"ip_{i}", ip
    for i, user in enumerate(sorted(users), 1):
        forward[user], mapping[f"user_{i}"] = f"user_{i}", user
    if not forward:
        return packet, mapping

    pattern = re.compile(
        r"(?<![A-Za-z0-9_.])("
        + "|".join(re.escape(k) for k in sorted(forward, key=len, reverse=True))
        + r")(?![A-Za-z0-9_])"
    )

    def walk(o):
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, str):
            return pattern.sub(lambda m: forward[m.group(0)], o)
        return o

    out = dict(packet)
    out["entity"] = walk(packet["entity"])
    out["facts"] = walk(packet["facts"])
    return out, mapping


def restore(text, mapping):
    """Placeholders back to originals, for DISPLAY only. Never feed this back to the model."""
    for ph in sorted(mapping, key=len, reverse=True):
        text = re.sub(rf"\b{re.escape(ph)}\b", lambda _m, v=mapping[ph]: v, text)
    return text


def restore_obj(obj, mapping):
    if isinstance(obj, dict):
        return {k: restore_obj(v, mapping) for k, v in obj.items()}
    if isinstance(obj, list):
        return [restore_obj(v, mapping) for v in obj]
    if isinstance(obj, str):
        return restore(obj, mapping)
    return obj
