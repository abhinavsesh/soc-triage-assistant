import logging
import time

from soc_triage.llm.client import call_llm, parse_json
from soc_triage.llm.evidence import build_evidence
from soc_triage.llm.prompt import build_messages
from soc_triage.llm.pseudonymise import pseudonymise, restore_obj
from soc_triage.llm.validate import validate_output

logger = logging.getLogger(__name__)


def explain_alert(alert, pseudonymise_entities=True, call=call_llm):
    """Explain one alert. `call` is injectable so tests need no model.

    explanation_raw is what the model said (placeholders), validated against the packet.
    explanation is the same with real names restored, for display only.
    """
    packet = build_evidence(alert)
    mapping = {}
    if pseudonymise_entities:
        packet, mapping = pseudonymise(packet)
    system, user = build_messages(packet)

    t0 = time.time()
    raw = call(system, user)
    seconds = round(time.time() - t0, 1)

    try:
        out = parse_json(raw)
    except ValueError:
        logger.warning("LLM output was not valid JSON (entity type %s)", packet["entity_type"])
        return {"ok": False, "problems": ["unparseable output"], "explanation": None,
                "explanation_raw": None, "raw": raw[:500], "seconds": seconds}

    problems = validate_output(out, packet)
    logger.info("Explained %s alert in %.1fs with %d validation problems",
                packet["entity_type"], seconds, len(problems))
    return {"ok": not problems, "problems": problems, "explanation_raw": out,
            "explanation": restore_obj(out, mapping), "raw": None, "seconds": seconds}
