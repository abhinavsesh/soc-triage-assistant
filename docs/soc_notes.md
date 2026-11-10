# SOC Notes

1. A system generates telemetry (for example, a login record), which is forwarded to a SIEM.
2. The SIEM normalises and correlates logs and raises an alert when a rule matches.
3. A Tier 1 analyst triages the alert as a true positive, a false positive or needs escalation.
4. Confirmed or unclear cases go to Tier 2 for investigation, and serious incidents to Tier 3 and incident response.
5. Response actions (containment, password reset, blocking) are taken, then the ticket is documented and closed.
6. Our tool sits between steps 2 and 3: it scores and prioritises alerts and explains the evidence, so triage is faster.
7. It does not replace the analyst or take response actions. A human decides.
8. A false negative (missed attack) is usually worse than a false alarm, because the attacker keeps access and the damage grows unnoticed.
9. Too many false alarms still cause misses, because alert fatigue makes analysts slower and more likely to dismiss real alerts.
10. So we need high recall without drowning analysts in false positives, which is why we measure both precision and recall.
