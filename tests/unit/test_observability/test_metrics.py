"""Tests for ``src.observability.metrics`` (R5 from upgrade.md).

Hand-rolled Prometheus exposition — no external dep — so we need
reasonable coverage of the text-format output to make sure scrapers
can parse it. Tests cover:

- Counter increment semantics and rejection of negative increments.
- Gauge set / inc / dec.
- Histogram bucket accounting, ``_sum`` / ``_count`` / ``+Inf``
  series, and rendering of non-integer edges.
- Label normalisation (sorted + stable) and escaping.
- Registry collision detection.
- End-to-end exposition for ``BotMetrics`` — the shape a real
  Prometheus scrape would parse.
"""

import pytest

from src.observability.metrics import (
    BotMetrics,
    Counter,
    Gauge,
    Histogram,
    MetricsRegistry,
    _format_labels,
    _normalise_labels,
    render_prometheus,
)

# ---------------------------------------------------------------------
# Label helpers
# ---------------------------------------------------------------------


class TestLabelNormalisation:
    def test_empty_yields_empty_tuple(self):
        assert _normalise_labels(None) == ()
        assert _normalise_labels({}) == ()

    def test_keys_are_sorted(self):
        """Sorted order is a stability contract — tests + humans can
        diff exposition output without caring about dict insertion
        order."""
        result = _normalise_labels({"b": 2, "a": 1, "c": 3})
        assert result == (("a", "1"), ("b", "2"), ("c", "3"))

    def test_values_are_stringified(self):
        result = _normalise_labels({"count": 42, "ok": True})
        assert result == (("count", "42"), ("ok", "True"))


class TestLabelFormatting:
    def test_empty_labels_no_braces(self):
        assert _format_labels(()) == ""

    def test_quotes_are_escaped(self):
        assert _format_labels((("path", 'has"quote'),)) == '{path="has\\"quote"}'

    def test_newlines_are_escaped(self):
        assert _format_labels((("line", "a\nb"),)) == '{line="a\\nb"}'

    def test_extra_labels_merged(self):
        formatted = _format_labels((("a", "1"),), extra={"le": "0.5"})
        # Order is alphabetical
        assert formatted == '{a="1",le="0.5"}'


# ---------------------------------------------------------------------
# Counter
# ---------------------------------------------------------------------


class TestCounter:
    async def test_single_increment(self):
        c = Counter("x_total", "help")
        await c.inc()
        assert "x_total 1.0" in "\n".join(c.render())

    async def test_labelled_increments_independent(self):
        c = Counter("x_total", "help")
        await c.inc(outcome="success")
        await c.inc(outcome="success")
        await c.inc(outcome="error")

        rendered = "\n".join(c.render())
        assert 'x_total{outcome="success"} 2.0' in rendered
        assert 'x_total{outcome="error"} 1.0' in rendered

    async def test_negative_rejected(self):
        c = Counter("x_total", "help")
        with pytest.raises(ValueError):
            await c.inc(-1.0)

    async def test_help_and_type_rendered(self):
        c = Counter("my_counter", "My neat counter")
        await c.inc()
        lines = c.render()
        assert "# HELP my_counter My neat counter" in lines
        assert "# TYPE my_counter counter" in lines


# ---------------------------------------------------------------------
# Gauge
# ---------------------------------------------------------------------


class TestGauge:
    async def test_set_overrides(self):
        g = Gauge("live", "help")
        await g.set(5)
        await g.set(3)
        assert "live 3.0" in "\n".join(g.render())

    async def test_inc_dec_round_trip(self):
        g = Gauge("live", "help")
        await g.inc(5)
        await g.inc(3)
        await g.dec(2)
        assert "live 6.0" in "\n".join(g.render())

    async def test_labelled_values_rendered_separately(self):
        g = Gauge("live", "help")
        await g.set(2, region="eu")
        await g.set(7, region="us")

        rendered = "\n".join(g.render())
        assert 'live{region="eu"} 2.0' in rendered
        assert 'live{region="us"} 7.0' in rendered


# ---------------------------------------------------------------------
# Histogram
# ---------------------------------------------------------------------


class TestHistogram:
    async def test_buckets_accumulate(self):
        h = Histogram("lat", "help", buckets=(0.1, 0.5, 1.0))
        for v in (0.05, 0.2, 0.3, 0.7, 2.0):
            await h.observe(v)

        rendered = "\n".join(h.render())
        # 1 obs ≤ 0.1
        assert 'lat_bucket{le="0.1"} 1' in rendered
        # obs ≤ 0.5: the 0.05, 0.2, 0.3 — so 3
        assert 'lat_bucket{le="0.5"} 3' in rendered
        # obs ≤ 1.0: above + 0.7 — so 4
        assert 'lat_bucket{le="1"} 4' in rendered
        # +Inf equals total count (5)
        assert 'lat_bucket{le="+Inf"} 5' in rendered

    async def test_sum_and_count(self):
        h = Histogram("lat", "help", buckets=(1.0,))
        for v in (0.5, 1.0, 0.25):
            await h.observe(v)

        rendered = "\n".join(h.render())
        assert "lat_sum 1.75" in rendered
        assert "lat_count 3" in rendered

    async def test_labelled_series_independent(self):
        h = Histogram("lat", "help", buckets=(1.0,))
        await h.observe(0.1, endpoint="a")
        await h.observe(0.1, endpoint="a")
        await h.observe(0.1, endpoint="b")

        rendered = "\n".join(h.render())
        assert 'lat_count{endpoint="a"} 2' in rendered
        assert 'lat_count{endpoint="b"} 1' in rendered

    async def test_integer_bucket_edges_formatted_without_trailing_zeros(self):
        h = Histogram("lat", "help", buckets=(1.0, 2.5))
        await h.observe(0.1)
        rendered = "\n".join(h.render())
        # ``1.0`` renders as ``1``, ``2.5`` renders as ``2.5``.
        assert 'le="1"' in rendered
        assert 'le="2.5"' in rendered


# ---------------------------------------------------------------------
# Registry + end-to-end
# ---------------------------------------------------------------------


class TestRegistry:
    async def test_collision_raises(self):
        reg = MetricsRegistry()
        reg.register(Counter("m", "help"))
        with pytest.raises(ValueError):
            reg.register(Counter("m", "other"))

    async def test_render_is_deterministic(self):
        reg = MetricsRegistry()
        a = Counter("a_total", "help a")
        b = Counter("b_total", "help b")
        reg.register(a)
        reg.register(b)
        await a.inc()
        await b.inc()

        first = await reg.render()
        second = await reg.render()
        # Repeated scrapes of the same state produce byte-identical output.
        assert first == second

    async def test_output_ends_with_newline(self):
        reg = MetricsRegistry()
        reg.register(Counter("x_total", "help"))
        output = await reg.render()
        assert output.endswith("\n")


class TestBotMetricsShape:
    """End-to-end: the default :class:`BotMetrics` (a fresh registry)
    renders every metric we advertised with its HELP + TYPE lines."""

    async def test_all_metrics_registered(self):
        bm = BotMetrics(MetricsRegistry())

        expected = {
            "bot_messages_received_total",
            "bot_claude_calls_total",
            "bot_claude_latency_seconds",
            "bot_db_query_latency_seconds",
            "bot_active_sessions",
            "bot_rate_limit_rejections_total",
        }
        for name in expected:
            assert name in bm.registry._metrics, f"missing {name}"

    async def test_rendered_exposition_contains_help_and_type(self):
        bm = BotMetrics(MetricsRegistry())
        await bm.messages_received_total.inc()
        await bm.claude_latency_seconds.observe(0.42)

        body = await render_prometheus(bm.registry)

        # Every metric has HELP + TYPE per the spec
        assert "# HELP bot_messages_received_total" in body
        assert "# TYPE bot_messages_received_total counter" in body
        assert "# HELP bot_claude_latency_seconds" in body
        assert "# TYPE bot_claude_latency_seconds histogram" in body

        # Observation made it through.
        assert "bot_claude_latency_seconds_count 1" in body
        assert "bot_claude_latency_seconds_sum 0.42" in body
