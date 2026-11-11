"""Static signal -> ATT&CK mapping. Each entry is a hypothesis with a confidence level.
Verify IDs and tactic names against attack.mitre.org and record the version checked."""

MITRE = {
    "auth_s1_bruteforce": {
        "id": "T1110.001", "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access", "confidence": "medium",
    },
    "auth_s2_spraying": {
        "id": "T1110.003", "name": "Brute Force: Password Spraying",
        "tactic": "Credential Access", "confidence": "medium",
    },
    "auth_s3_success_after_failures": {
        "id": "T1078", "name": "Valid Accounts",
        "tactic": "Initial Access, Persistence, Privilege Escalation, Defense Evasion (called Stealth in newer ATT&CK versions)",
        "confidence": "low",
    },
    "flow_rule_hit": {
        "id": "T1110", "name": "Brute Force",
        "tactic": "Credential Access", "confidence": "low",
    },
}


def map_signals(signals):
    """Return the techniques for any signals that have a mapping. Others are ignored."""
    return [{**MITRE[s], "signal": s} for s in sorted(signals) if s in MITRE]
