from fastapi.testclient import TestClient

from pwscore.api import app


def _client() -> TestClient:
    return TestClient(app)


class TestApi:
    def test_healthz(self) -> None:
        with _client() as c:
            r = c.get("/healthz")
            assert r.status_code == 200
            assert r.json()["status"] == "ok"

    def test_metrics_is_prometheus_text(self) -> None:
        with _client() as c:
            r = c.get("/metrics")
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("text/plain")
            assert "pwscore_requests_total" in r.text

    def test_analyze_weak(self) -> None:
        with _client() as c:
            r = c.post(
                "/analyze",
                json={"password": "password", "offline": True},
            )
            assert r.status_code == 200
            body = r.json()
            assert body["verdict"] == "weak"
            assert body["reasons"]

    def test_analyze_missing_password_is_422(self) -> None:
        with _client() as c:
            r = c.post("/analyze", json={"offline": True})
            assert r.status_code == 422

    def test_password_not_in_response(self) -> None:
        # Response must not echo the raw password back.
        with _client() as c:
            r = c.post(
                "/analyze",
                json={"password": "S3cret!Horse42", "offline": True},
            )
            assert r.status_code == 200
            assert "S3cret!Horse42" not in r.text
