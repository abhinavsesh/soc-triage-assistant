"""Thin client for the SOC API. The key is held in memory only and is never logged."""
import requests


class ApiError(Exception):
    def __init__(self, status, detail):
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


def _detail(response):
    """A short, safe message. Only plain-string details from the API are passed through."""
    try:
        detail = response.json().get("detail")
    except (ValueError, AttributeError):
        return "unexpected error"
    if isinstance(detail, str):
        return detail[:200]
    if isinstance(detail, list):
        return "invalid input, check the fields"
    return "unexpected error"


class ApiClient:
    def __init__(self, base_url, api_key, session=None, timeout=15):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.session = session or requests.Session()
        self.timeout = timeout

    def _request(self, method, path, timeout=None, **kwargs):
        try:
            r = self.session.request(method, self.base_url + path,
                                     headers={"X-API-Key": self.api_key},
                                     timeout=timeout or self.timeout, **kwargs)
        except requests.RequestException:
            raise ApiError(0, "API not reachable. Is the server running?") from None
        if r.status_code >= 400:
            raise ApiError(r.status_code, _detail(r))
        return r.json()

    def me(self):
        return self._request("GET", "/me")

    def alerts(self, status=None, severity=None, min_score=0, limit=100):
        params = {"status": status, "severity": severity, "min_score": min_score, "limit": limit}
        return self._request("GET", "/alerts", params=params)

    def alert(self, alert_id):
        return self._request("GET", f"/alerts/{int(alert_id)}")

    def set_status(self, alert_id, status, note=None):
        return self._request("PATCH", f"/alerts/{int(alert_id)}/status",
                             json={"status": status, "note": note})

    def explain(self, alert_id, refresh=False):
        return self._request("POST", f"/alerts/{int(alert_id)}/explain", timeout=180,
                             params={"refresh": "true" if refresh else "false"})

    def propose(self, alert_id, action, target, reason):
        return self._request("POST", f"/alerts/{int(alert_id)}/actions",
                             json={"action": action, "target": target, "reason": reason})

    def actions(self, status=None):
        return self._request("GET", "/actions", params={"status": status})

    def decide(self, action_id, decision):
        return self._request("POST", f"/actions/{int(action_id)}/decision",
                             json={"decision": decision})

    def execute(self, action_id):
        return self._request("POST", f"/actions/{int(action_id)}/execute")
