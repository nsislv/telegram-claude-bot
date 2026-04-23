"""Observability primitives: metrics, traces (future), health (future).

Kept in its own package so ``src/api/server.py`` can import the
``/metrics`` renderer without dragging in orchestrator code, and so
individual instrumentation callers (``orchestrator``,
``sdk_integration``, ``rate_limiter`` …) have one stable symbol to
import from.
"""

from .metrics import (
    BotMetrics,
    Counter,
    Gauge,
    Histogram,
    MetricsRegistry,
    bot_metrics,
    render_prometheus,
)

__all__ = (
    "BotMetrics",
    "Counter",
    "Gauge",
    "Histogram",
    "MetricsRegistry",
    "bot_metrics",
    "render_prometheus",
)
