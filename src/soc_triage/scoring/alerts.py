from soc_triage.mitre.mapping import map_signals
from soc_triage.scoring.risk import score_alert


def build_alerts(incidents):
    """Attach score, severity, breakdown and MITRE tags. Highest risk first."""
    alerts = []
    for inc in incidents:
        s = score_alert(inc["signals"])
        alerts.append({
            **inc,
            "signals": sorted(inc["signals"]),
            "risk_score": s["score"],
            "severity": s["severity"],
            "score_breakdown": s["breakdown"],
            "mitre": map_signals(inc["signals"]),
        })
    return sorted(alerts, key=lambda a: a["risk_score"], reverse=True)
