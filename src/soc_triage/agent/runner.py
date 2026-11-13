"""The only door between the model and the tools. Enforces an allowlist, a call budget,
placeholder-only arguments, redacted and pseudonymised output, and an audit log."""
import ipaddress
import logging
import re

from soc_triage.agent.tools import BAD_USER, USER_RE, ToolError

logger = logging.getLogger(__name__)

PLACEHOLDER_RE = re.compile(r"^(?:ip|user)_\d+$")
BAD_IP = "invalid_ip_value"
IP_KEYS = {"src_ip", "success_ips", "failure_ips"}
USER_KEYS = {"user", "users"}
TEXT_KEYS = {"at", "first_seen", "last_seen", "first_success_at", "result"}


def _spec(name, description, **params):
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object",
                       "properties": {p: {"type": "string", "description": d} for p, d in params.items()},
                       "required": list(params)}}}


TOOL_SPECS = [
    _spec("user_history", "Read-only. Login history for one user: counts, IPs seen, recent events.",
          user="a user placeholder such as user_1"),
    _spec("ip_activity", "Read-only. Activity from one IP: failures, successes, users targeted.",
          ip="an IP placeholder such as ip_1"),
    _spec("is_known_ip", "Read-only. Whether a user has successful logins from an IP, and when the first was.",
          user="a user placeholder such as user_1", ip="an IP placeholder such as ip_1"),
]


REQUIRED_ARGS = {s["function"]["name"]: s["function"]["parameters"]["required"]
                 for s in TOOL_SPECS}


class ToolRunner:
    def __init__(self, tools, mapping, max_calls=3):
        self._real = dict(mapping)                              # placeholder -> real
        self._alias_of = {v: k for k, v in mapping.items()}     # real -> placeholder
        self._fns = {"user_history": tools.user_history,
                     "ip_activity": tools.ip_activity,
                     "is_known_ip": tools.is_known_ip}
        self.max_calls = max_calls
        self.audit = []

    def mapping(self):
        return dict(self._real)

    def _resolve(self, value):
        s = str(value)
        if not PLACEHOLDER_RE.match(s):
            raise ToolError("use placeholders such as ip_1 or user_1")
        if s not in self._real:
            raise ToolError(f"unknown placeholder {s}")
        return self._real[s]

    def _alias(self, kind, value):
        if value in (BAD_IP, BAD_USER):
            return value
        if kind == "ip":
            try:
                value = str(ipaddress.ip_address(str(value)))
            except ValueError:
                return BAD_IP
        else:
            value = str(value)
            if not USER_RE.match(value):
                return BAD_USER
        if value not in self._alias_of:
            n = 1 + sum(1 for k in self._real if k.startswith(kind + "_"))
            self._real[f"{kind}_{n}"] = value
            self._alias_of[value] = f"{kind}_{n}"
        return self._alias_of[value]

    def _clean(self, obj, key=None):
        if isinstance(obj, dict):
            return {k: self._clean(v, k) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._clean(v, key) for v in obj]
        if obj is None or isinstance(obj, (bool, int, float)):
            return obj
        if key in IP_KEYS:
            return self._alias("ip", obj)
        if key in USER_KEYS:
            return self._alias("user", obj)
        return obj if key in TEXT_KEYS else "redacted"

    def call(self, name, args):
        entry = {"tool": str(name)[:40], "args": args, "ok": False}
        self.audit.append(entry)
        try:
            if len(self.audit) > self.max_calls:
                raise ToolError("tool call budget exhausted")
            fn = self._fns.get(name)
            if fn is None:
                raise ToolError("unknown tool")
            if not isinstance(args, dict):
                raise ToolError("arguments must be an object")
            kwargs = {str(k): self._resolve(v) for k, v in args.items()}
            result = self._clean(fn(**kwargs))
            entry["ok"] = True
            return result
        except ToolError as e:
            return {"error": str(e)}
        except TypeError:
            needs = REQUIRED_ARGS.get(entry["tool"])
            hint = f"; {entry['tool']} requires: {', '.join(needs)}" if needs else ""
            return {"error": "wrong arguments" + hint}
        finally:
            logger.info("tool call %s ok=%s", entry["tool"], entry["ok"])
