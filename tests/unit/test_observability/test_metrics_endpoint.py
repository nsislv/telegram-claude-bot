"""End-to-end test for ``GET /metrics`` (R5 from upgrade.md)."""

from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from src.api.server import create_api_app
from src.events.bus import EventBus
from src.observability import bot_metrics


def _settings() -> MagicMock:
    s = MagicMock()
    s.development_mode = False  # so /docs isn't registered
    s.github_webhook_secret = "gh"
    s.webhook_api_secret = "ws"
    s.api_server_port = 8080
    s.debug = False
    return s


class TestMetricsEndpoint:
    def test_returns_prometheus_text(self):
        app = create_api_app(EventBus(), _settings())
        client = TestClient(app)

        response = client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers.get("content-type", "")
        assert "version=0.0.4" in response.headers.get("content-type", "")

    def test_body_contains_all_bot_metrics(self):
        app = create_api_app(EventBus(), _settings())
        client = TestClient(app)

        response = client.get("/metrics")
        body = response.text

        # Every metric we advertise must show up in the exposition.
        for name in [
            "bot_messages_received_total",
            "bot_claude_calls_total",
            "bot_claude_latency_seconds",
            "bot_db_query_latency_seconds",
            "bot_active_sessions",
            "bot_rate_limit_rejections_total",
        ]:
            assert f"# TYPE {name}" in body, f"missing # TYPE line for {name}"

    def test_observations_show_up_in_next_scrape(self):
        """Observations made between scrapes must appear in the
        subsequent scrape — end-to-end proof that the module-level
        singleton is the one backing /metrics."""
        import asyncio

        app = create_api_app(EventBus(), _settings())
        client = TestClient(app)

        # Baseline
        before = client.get("/metrics").text

        # Observe something on the production singleton.
        asyncio.run(_inc_counter_once(bot_metrics.messages_received_total))

        after = client.get("/metrics").text

        # The counter's value line should be different — even a
        # single increment changes either the value or introduces
        # a new series.
        assert after != before


async def _inc_counter_once(counter):
    await counter.inc()
