"""Read-only investigation tools over the auth log. Least privilege by construction:
fixed functions, validated arguments, capped output, no writes, no shell, no SQL."""
import ipaddress
import re

MAX_ITEMS = 10
USER_RE = re.compile(r"^[A-Za-z0-9_.@\-]{1,64}$")
BAD_USER = "invalid_user_value"


class ToolError(Exception):
    """Bad arguments or an unknown tool. Reported to the model as a fixed error string."""


def check_ip(value):
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise ToolError("argument is not a valid IP address") from None


def check_user(value):
    if not USER_RE.match(str(value)):
        raise ToolError("argument is not a valid username")
    return str(value)


def _safe_user(u):
    return u if USER_RE.match(str(u)) else BAD_USER


class InvestigationTools:
    def __init__(self, auth_df):
        self._df = auth_df.copy()  # a private copy: tools read it and never write back

    def user_history(self, user):
        user = check_user(user)
        d = self._df[self._df["user"] == user]
        ok, bad = d[d["is_failure"] == 0], d[d["is_failure"] == 1]
        recent = d.sort_values("timestamp").tail(MAX_ITEMS)
        return {
            "user": user,
            "events": int(len(d)),
            "successes": int(len(ok)),
            "failures": int(len(bad)),
            "success_ips": sorted(ok["src_ip"].unique())[:MAX_ITEMS],
            "failure_ips": sorted(bad["src_ip"].unique())[:MAX_ITEMS],
            "recent": [
                {"at": str(r.timestamp), "src_ip": r.src_ip,
                 "result": "failure" if r.is_failure else "success"}
                for r in recent.itertuples()
            ],
        }

    def ip_activity(self, ip):
        ip = check_ip(ip)
        d = self._df[self._df["src_ip"] == ip]
        users = sorted(d["user"].unique())
        return {
            "src_ip": ip,
            "events": int(len(d)),
            "failures": int((d["is_failure"] == 1).sum()),
            "successes": int((d["is_failure"] == 0).sum()),
            "distinct_users": int(len(users)),
            "users": [_safe_user(u) for u in users][:MAX_ITEMS],
            "first_seen": str(d["timestamp"].min()) if len(d) else None,
            "last_seen": str(d["timestamp"].max()) if len(d) else None,
        }

    def is_known_ip(self, user, ip):
        user, ip = check_user(user), check_ip(ip)
        d = self._df[(self._df["user"] == user) & (self._df["src_ip"] == ip)
                     & (self._df["is_failure"] == 0)]
        return {
            "user": user,
            "src_ip": ip,
            "successful_logins_from_this_ip": int(len(d)),
            "first_success_at": str(d["timestamp"].min()) if len(d) else None,
        }
