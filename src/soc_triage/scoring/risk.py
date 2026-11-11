"""Additive, explainable risk score. Weights are judgement, not tuned values."""

WEIGHTS = {
    "flow_rule_hit": 40,
    "flow_volume_3x_threshold": 20,
    "flow_sustained_5plus_windows": 15,
    "auth_s1_bruteforce": 30,
    "auth_s2_spraying": 30,
    "auth_s3_success_after_failures": 40,
    "new_source_ip": 15,
    "off_hours": 10,
    "multi_scenario_correlation": 20,
}

SEVERITY_BANDS = [(70, "high"), (40, "medium"), (0, "low")]


def severity(score):
    for floor, label in SEVERITY_BANDS:
        if score >= floor:
            return label


def score_alert(signals):
    """Return the score, severity and per-signal points. Unknown signals fail loudly."""
    unknown = set(signals) - set(WEIGHTS)
    if unknown:
        raise ValueError(f"Unknown signals: {sorted(unknown)}")
    breakdown = {s: WEIGHTS[s] for s in sorted(signals)}
    score = min(100, sum(breakdown.values()))
    return {"score": score, "severity": severity(score), "breakdown": breakdown}
