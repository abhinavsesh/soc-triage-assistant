import logging
import time

from soc_triage.agent.investigate import investigate
from soc_triage.agent.runner import ToolRunner
from soc_triage.llm.client import call_llm, chat_raw, parse_json
from soc_triage.llm.evidence import build_evidence
from soc_triage.llm.prompt import build_messages
from soc_triage.llm.pseudonymise import pseudonymise, restore_obj
from soc_triage.llm.validate import validate_output

logger = logging.getLogger(__name__)


def explain_alert(alert, pseudonymise_entities=True, call=call_llm, tools=None, chat=chat_raw):
    """Explain one alert. `call` and `chat` are injectable so tests need no model.

    tools=None gives the plain explanation. With tools, the model may first request a few
    read-only lookups, whose cleaned results are added to the evidence before the explanation.
    explanation_raw is what the model said (placeholders), validated against the packet.
    explanation is the same with real names restored, for display only.
    """
    if tools is not None and not pseudonymise_entities:
        raise ValueError("tool use requires pseudonymisation")
    packet = build_evidence(alert)
    mapping = {}
    if pseudonymise_entities:
        packet, mapping = pseudonymise(packet)

    t0 = time.time()
    tool_log = []
    if tools is not None:
        runner = ToolRunner(tools, mapping)
        tool_log = investigate(packet, runner, chat=chat)
        packet = {**packet, "tool_results": tool_log}
        mapping = runner.mapping()

    system, user = build_messages(packet)
    raw = call(system, user)
    seconds = round(time.time() - t0, 1)

    try:
        out = parse_json(raw)
    except ValueError:
        logger.warning("LLM output was not valid JSON (entity type %s)", packet["entity_type"])
        return {"ok": False, "problems": ["unparseable output"], "explanation": None,
                "explanation_raw": None, "raw": raw[:500], "seconds": seconds, "tool_log": tool_log}

    problems = validate_output(out, packet)
    logger.info("Explained %s alert in %.1fs, %d tool calls, %d validation problems",
                packet["entity_type"], seconds, len(tool_log), len(problems))
    return {"ok": not problems, "problems": problems, "explanation_raw": out,
            "explanation": restore_obj(out, mapping), "raw": None, "seconds": seconds,
            "tool_log": tool_log}
