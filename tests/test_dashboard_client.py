import pytest
import requests

from soc_triage.dashboard.client import ApiClient, ApiError


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = {} if data is None else data

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class FakeSession:
    def __init__(self, response=None, error=None):
        self.calls = []
        self.response = response or FakeResponse()
        self.error = error

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.error:
            raise self.error
        return self.response


def client(session):
    return ApiClient("http://api.test/", "secret-key", session=session)


def test_sends_key_and_builds_url():
    s = FakeSession()
    client(s).alerts(min_score=50)
    method, url, kw = s.calls[0]
    assert (method, url) == ("GET", "http://api.test/alerts")
    assert kw["headers"] == {"X-API-Key": "secret-key"} and kw["params"]["min_score"] == 50


def test_error_detail_string_is_passed_through():
    s = FakeSession(FakeResponse(409, {"detail": "cannot move from a to b"}))
    with pytest.raises(ApiError) as e:
        client(s).set_status(1, "closed")
    assert e.value.status == 409 and e.value.detail == "cannot move from a to b"


def test_validation_error_detail_is_summarised():
    s = FakeSession(FakeResponse(422, {"detail": [{"loc": ["body", "x"], "msg": "bad", "input": "secret"}]}))
    with pytest.raises(ApiError) as e:
        client(s).propose(1, "block_ip", "x", "r")
    assert "loc" not in e.value.detail and "secret" not in e.value.detail


def test_unreachable_api_gives_a_clean_error():
    s = FakeSession(error=requests.ConnectionError("boom at localhost:8000"))
    with pytest.raises(ApiError) as e:
        client(s).me()
    assert e.value.status == 0 and "boom" not in e.value.detail


def test_non_json_error_body():
    s = FakeSession(FakeResponse(500, ValueError("not json")))
    with pytest.raises(ApiError) as e:
        client(s).me()
    assert e.value.status == 500 and e.value.detail == "unexpected error"


def test_ids_are_coerced_to_int():
    with pytest.raises(ValueError):
        client(FakeSession()).alert("1/../../actions")


def test_explain_uses_flag_and_long_timeout():
    s = FakeSession()
    client(s).explain(3, refresh=True)
    _, url, kw = s.calls[0]
    assert url.endswith("/alerts/3/explain") and kw["params"] == {"refresh": "true"} and kw["timeout"] >= 60


def test_status_payload():
    s = FakeSession()
    client(s).set_status(2, "investigating", "looking")
    assert s.calls[0][2]["json"] == {"status": "investigating", "note": "looking"}
