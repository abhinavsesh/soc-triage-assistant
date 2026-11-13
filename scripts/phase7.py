import json
from pathlib import Path

from soc_triage.agent.approvals import ApprovalQueue
from soc_triage.agent.tools import InvestigationTools
from soc_triage.detection.incidents import detect_auth
from soc_triage.ingestion.loaders import load_auth
from soc_triage.llm.client import LLMError
from soc_triage.llm.explain import explain_alert
from soc_triage.logging_setup import setup_logging
from soc_triage.scoring.alerts import build_alerts


def main():
    setup_logging()
    auth_df = load_auth("data/sample/auth_sample.csv")
    alerts = build_alerts(detect_auth(auth_df))
    tools = InvestigationTools(auth_df)
    results = []
    for a in alerts:
        for label, kw in (("no tools", {}), ("with tools", {"tools": tools})):
            try:
                r = explain_alert(a, **kw)
            except LLMError as e:
                print(a["entity"], label, "ERROR", e)
                continue
            calls = [(t["tool"], t["args"], "error" in t["result"]) for t in r["tool_log"]]
            out = r.get("explanation_raw") or {}
            results.append({"entity": a["entity"], "mode": label, "ok": r["ok"], "problems": r["problems"],
                            "seconds": r["seconds"], "calls": calls, "output": out})
            print(f"\n== {a['entity']} | {label} | valid={r['ok']} | {r['seconds']}s | tool calls={calls}")
            print("problems:", r["problems"])
            print("summary:", out.get("summary"))
            print("steps:", json.dumps(out.get("investigation_steps"), indent=1))

    print("\n== approval gate demo")
    q = ApprovalQueue()
    item = q.propose("user:bob", "block_ip", "203.0.113.45", "brute force then success from a new IP")
    for label, fn in (("execute before approval", lambda: q.execute(item.id)),
                      ("model approves", lambda: q.approve(item.id, "llm"))):
        try:
            fn()
            print(label, "-> ALLOWED (this would be a bug)")
        except PermissionError as e:
            print(label, "-> refused:", e)
    q.approve(item.id, "analyst_abhinav")
    q.execute(item.id)
    print("final status:", item.status)

    Path("data/processed").mkdir(parents=True, exist_ok=True)
    Path("data/processed/phase7_results.json").write_text(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    main()
