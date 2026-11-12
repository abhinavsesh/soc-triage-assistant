"""Check model output against the evidence. The model's claims are untrusted."""
import re

REQUIRED = {"summary", "evidence_cited", "mitre_hypotheses",
            "investigation_steps", "proposed_actions", "uncertainty"}
LIST_KEYS = ("evidence_cited", "mitre_hypotheses", "investigation_steps", "proposed_actions")
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
PLACEHOLDER_RE = re.compile(r"\b(?:ip|user)_\d+\b")
FORBIDDEN_CLAIMS = ("confirmed", "definitely", "certainly an attack", "no doubt")
STATE_CHANGING = re.compile(
    r"\b(block|disable|reset|isolate|quarantine|delete|terminate|kill|lock)\b", re.I)
DOWNPLAY = re.compile(
    r"\b(benign|harmless|false positive|no action needed|safe to ignore)\b", re.I)


def _norm(x):
    s = str(x).strip()
    try:
        f = float(s)
        return str(int(f)) if f == int(f) else str(f)
    except (ValueError, OverflowError):
        return s


def _leaves(obj, out):
    if isinstance(obj, dict):
        for v in obj.values():
            _leaves(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _leaves(v, out)
    else:
        out.append(str(obj))
    return out


def _pairs(obj, out):
    """Map each field name to the set of values it holds anywhere in the packet."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                _pairs(v, out)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, (dict, list)):
                        _pairs(item, out)
                    else:
                        out.setdefault(str(k), set()).add(_norm(item))
            else:
                out.setdefault(str(k), set()).add(_norm(v))
    elif isinstance(obj, list):
        for item in obj:
            _pairs(item, out)
    return out


def validate_output(out, packet):
    """Return a list of problems. An empty list means none found, NOT that it is correct."""
    if not isinstance(out, dict) or set(out) != REQUIRED:
        return ["schema: missing or extra keys"]
    for k in LIST_KEYS:
        if not isinstance(out[k], list):
            return [f"schema: {k} must be a list"]
    if not all(isinstance(c, dict) for c in out["evidence_cited"] + out["mitre_hypotheses"]):
        return ["schema: evidence_cited and mitre_hypotheses must be lists of objects"]
    if not isinstance(out["summary"], str) or not isinstance(out["uncertainty"], str):
        return ["schema: summary and uncertainty must be strings"]

    problems = []
    ev_text = " ".join(_leaves(packet, []))
    ev_ips = set(IP_RE.findall(ev_text))
    ev_placeholders = set(PLACEHOLDER_RE.findall(ev_text))
    allowed_ids = {m["id"] for m in packet["mitre"]}
    out_text = " ".join(_leaves(out, []))

    # An IP in the output that is not in the packet is hallucinated or leaked.
    # With a pseudonymised packet the evidence has no real IPs, so any IP is flagged.
    for ip in sorted(set(IP_RE.findall(out_text)) - ev_ips):
        problems.append(f"IP address not in evidence: {ip}")
    for ph in sorted(set(PLACEHOLDER_RE.findall(out_text)) - ev_placeholders):
        problems.append(f"placeholder not in evidence: {ph}")
    for t in sorted(set(TECH_RE.findall(out_text)) - allowed_ids):
        problems.append(f"technique not in evidence: {t}")
    for h in out["mitre_hypotheses"]:
        if h.get("id") not in allowed_ids:
            problems.append(f"mitre hypothesis not in evidence: {h.get('id')}")

    pairs = _pairs(packet, {})
    pairs.setdefault("entity", set()).update(_norm(x) for x in packet["entity"].split(":"))
    for c in out["evidence_cited"]:
        field = str(c.get("field")).split(".")[-1]  # accept paths such as "mitre.id"
        raw = c.get("value")
        known = pairs.get(field, set())
        for item in (raw if isinstance(raw, list) else [raw]):
            if _norm(item) not in known:
                problems.append(f"cited fact not in evidence: {field}={item}")

    for a in out["proposed_actions"]:
        if not str(a).startswith("PROPOSAL:"):
            problems.append(f"action not phrased as proposal: {str(a)[:40]}")
    low = out_text.lower()
    for w in FORBIDDEN_CLAIMS:
        if w in low:
            problems.append(f"overconfident wording: {w}")
    if not 3 <= len(out["investigation_steps"]) <= 6:
        problems.append("investigation_steps count out of range")
    for s in out["investigation_steps"]:
        if STATE_CHANGING.search(str(s)):
            problems.append(f"state-changing step in investigation_steps: {str(s)[:50]}")
    if packet["severity"] in ("high", "medium") and DOWNPLAY.search(out["summary"]):
        problems.append("summary downplays a medium/high alert (heuristic)")
    return problems
