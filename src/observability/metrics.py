"""Minimal Prometheus-compatible metrics registry.

Pre-fix (R5, upgrade.md), the bot had structlog everywhere but no
metrics surface — operators could reconstruct request lifecycles by
tailing JSON logs, but there was no way to answer "how many Claude
calls failed in the last hour" or "what's the p95 latency of a
database query" without running ad-hoc grep pipelines.

This module provides just enough to feed Prometheus / Grafana /
alertmanager without taking a new dependency (``prometheus_client``
is ~100 KB and widely used, but adding it to ``pyproject.toml`` in
the same change as the first metric seemed more invasive than
hand-rolling the text format — which is a small, stable spec).

Types supported:

* :class:`Counter` — monotonically increasing. Optional labels.
* :class:`Gauge` — up/down integer or float. Optional labels.
* :class:`Histogram` — observations bucketed by configurable edges.
  We render ``_bucket`` / ``_sum`` / ``_count`` series as specified
  in the Prometheus text format.

Everything is keyed on ``(metric_name, labels_tuple)``. Labels are
stored as ``tuple[tuple[str, str], ...]`` so they hash stably and
the Prometheus serialiser can sort them deterministically.

Concurrency: all writes funnel through an ``asyncio.Lock`` on each
metric. Scrapes also take the lock so a read doesn't see a
partially-incremented histogram bucket. This is coarse but fine at
the traffic volumes a Telegram bot sees (small double-digit
requests/second even under load).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Type alias — labels are an ordered tuple of (key, value) pairs so
# the dictionary used for storage stays hashable and deterministic.
LabelSet = Tuple[Tuple[str, str], ...]


def _normalise_labels(labels: Optional[Dict[str, Any]]) -> LabelSet:
    """Convert an optional label dict to a sorted ``LabelSet``.

    Sorting makes equality comparisons and serialisation order
    stable regardless of how the caller built the dict.
    """
    if not labels:
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


def _format_labels(labels: LabelSet, extra: Optional[Dict[str, str]] = None) -> str:
    """Render a ``LabelSet`` into the ``{k="v",k2="v2"}`` Prometheus form."""
    merged: List[Tuple[str, str]] = list(labels)
    if extra:
        merged.extend(extra.items())
    if not merged:
        return ""
    escaped = [f'{k}="{_escape(v)}"' for k, v in sorted(merged)]
    return "{" + ",".join(escaped) + "}"


def _escape(value: str) -> str:
    """Escape a label value per the Prometheus text format rules."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class _BaseMetric:
    """Shared machinery for the three metric types."""

    kind: str = "untyped"

    def __init__(self, name: str, description: str) -> None:
        self.name = name
        self.description = description
        self._lock = asyncio.Lock()

    def _describe(self) -> List[str]:
        return [
            f"# HELP {self.name} {self.description}",
            f"# TYPE {self.name} {self.kind}",
        ]

    def render(self) -> List[str]:
        raise NotImplementedError


class Counter(_BaseMetric):
    """Monotonic counter."""

    kind = "counter"

    def __init__(self, name: str, description: str) -> None:
        super().__init__(name, description)
        self._values: Dict[LabelSet, float] = {}

    async def inc(self, amount: float = 1.0, **labels: Any) -> None:
        if amount < 0:
            raise ValueError("Counter can only be incremented by non-negative values")
        key = _normalise_labels(labels)
        async with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    def render(self) -> List[str]:
        lines = self._describe()
        for labels, value in sorted(self._values.items()):
            lines.append(f"{self.name}{_format_labels(labels)} {value}")
        return lines


class Gauge(_BaseMetric):
    """Up/down gauge."""

    kind = "gauge"

    def __init__(self, name: str, description: str) -> None:
        super().__init__(name, description)
        self._values: Dict[LabelSet, float] = {}

    async def set(self, value: float, **labels: Any) -> None:
        key = _normalise_labels(labels)
        async with self._lock:
            self._values[key] = float(value)

    async def inc(self, amount: float = 1.0, **labels: Any) -> None:
        key = _normalise_labels(labels)
        async with self._lock:
            self._values[key] = self._values.get(key, 0.0) + amount

    async def dec(self, amount: float = 1.0, **labels: Any) -> None:
        await self.inc(-amount, **labels)

    def render(self) -> List[str]:
        lines = self._describe()
        for labels, value in sorted(self._values.items()):
            lines.append(f"{self.name}{_format_labels(labels)} {value}")
        return lines


# Default latency buckets (seconds). Skewed toward sub-second so we
# can distinguish "fast local DB query" from "slow Claude call".
# Operators can construct their own Histogram with custom buckets.
_DEFAULT_BUCKETS: Tuple[float, ...] = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
    120.0,
    300.0,
)


@dataclass
class _HistogramSeries:
    sum: float = 0.0
    count: int = 0
    buckets: List[int] = field(default_factory=list)


class Histogram(_BaseMetric):
    """Bucketed histogram of observations (typically latency)."""

    kind = "histogram"

    def __init__(
        self,
        name: str,
        description: str,
        buckets: Iterable[float] = _DEFAULT_BUCKETS,
    ) -> None:
        super().__init__(name, description)
        self._buckets: Tuple[float, ...] = tuple(sorted(buckets))
        self._series: Dict[LabelSet, _HistogramSeries] = {}

    async def observe(self, value: float, **labels: Any) -> None:
        key = _normalise_labels(labels)
        async with self._lock:
            series = self._series.get(key)
            if series is None:
                series = _HistogramSeries(buckets=[0] * len(self._buckets))
                self._series[key] = series
            series.sum += float(value)
            series.count += 1
            for i, edge in enumerate(self._buckets):
                if value <= edge:
                    series.buckets[i] += 1

    def render(self) -> List[str]:
        lines = self._describe()
        for labels, series in sorted(self._series.items()):
            for i, edge in enumerate(self._buckets):
                bucket_label = _format_labels(labels, {"le": _format_edge(edge)})
                lines.append(f"{self.name}_bucket{bucket_label} {series.buckets[i]}")
            # The mandatory ``+Inf`` bucket equals the total count.
            plus_inf_label = _format_labels(labels, {"le": "+Inf"})
            lines.append(f"{self.name}_bucket{plus_inf_label} {series.count}")
            lines.append(f"{self.name}_sum{_format_labels(labels)} {series.sum}")
            lines.append(f"{self.name}_count{_format_labels(labels)} {series.count}")
        return lines


def _format_edge(edge: float) -> str:
    """Render a bucket edge as Prometheus expects (no trailing zeros)."""
    if edge == int(edge):
        return f"{int(edge)}"
    return f"{edge}"


class MetricsRegistry:
    """Holds every metric and renders the full exposition.

    Not a singleton — tests can instantiate their own registry. The
    module-level :data:`bot_metrics` object is the one production
    code uses.
    """

    def __init__(self) -> None:
        self._metrics: Dict[str, _BaseMetric] = {}
        self._lock = asyncio.Lock()

    def register(self, metric: _BaseMetric) -> None:
        if metric.name in self._metrics:
            raise ValueError(f"Metric {metric.name!r} already registered")
        self._metrics[metric.name] = metric

    async def render(self) -> str:
        """Produce the full ``text/plain; version=0.0.4`` payload."""
        parts: List[str] = []
        # Snapshot the metric list first so new registrations during
        # a scrape don't invalidate iteration.
        names = sorted(self._metrics)
        for name in names:
            metric = self._metrics[name]
            async with metric._lock:
                parts.extend(metric.render())
        # One trailing newline per the spec.
        return "\n".join(parts) + "\n"


async def render_prometheus(registry: "MetricsRegistry") -> str:
    """Convenience wrapper — used by the FastAPI ``/metrics`` handler."""
    return await registry.render()


class BotMetrics:
    """Bot-specific metric instances wired to a shared registry.

    Instantiated exactly once at module load (:data:`bot_metrics`).
    Callers interact with the counters / histograms through methods
    on this object rather than touching the registry directly, so
    adding a new metric doesn't require every callsite to learn a
    new symbol.
    """

    def __init__(self, registry: Optional[MetricsRegistry] = None) -> None:
        self.registry = registry or MetricsRegistry()

        self.messages_received_total = Counter(
            "bot_messages_received_total",
            "Total Telegram messages received and accepted by the bot.",
        )
        self.claude_calls_total = Counter(
            "bot_claude_calls_total",
            "Total Claude Agent SDK calls, labelled by outcome "
            "(success / error / interrupted).",
        )
        self.claude_latency_seconds = Histogram(
            "bot_claude_latency_seconds",
            "Wall-clock latency of a single Claude SDK call (seconds).",
        )
        self.db_query_latency_seconds = Histogram(
            "bot_db_query_latency_seconds",
            "Wall-clock latency of a single SQLite query (seconds), "
            "labelled by query kind (read / write).",
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
        )
        self.active_sessions = Gauge(
            "bot_active_sessions",
            "Current number of active Claude sessions across all users.",
        )
        self.rate_limit_rejections_total = Counter(
            "bot_rate_limit_rejections_total",
            "Total requests rejected by the rate limiter, labelled by "
            "reason (rate / cost).",
        )

        for metric in (
            self.messages_received_total,
            self.claude_calls_total,
            self.claude_latency_seconds,
            self.db_query_latency_seconds,
            self.active_sessions,
            self.rate_limit_rejections_total,
        ):
            self.registry.register(metric)


# Module-level singleton used by production code. Tests that need
# isolation can instantiate their own ``BotMetrics(MetricsRegistry())``.
bot_metrics = BotMetrics()
