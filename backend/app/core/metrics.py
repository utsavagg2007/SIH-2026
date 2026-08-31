"""Throughput and latency accounting.

Requirement (d) asks for a stated, demonstrated throughput figure, and Build
Plan layer 6 requires reporting packet-to-alert latency.  This module measures
what this process can honestly measure and refuses to guess at the rest.

What the backend measures itself:
    * alerts/sec sustained through the ingest path
    * the latency distribution of event_end -> backend receipt

What only the upstream layers can see:
    * flows/sec, packets/sec, Mb/s of the actual traffic

The backend cannot infer traffic rate from alert rate - a quiet link and a
perfectly-defended one look identical from here.  So the traffic figures are
reported by the ingestion/detection layer via ``POST /api/v1/telemetry`` and are
marked stale when nothing has reported recently, rather than being shown as a
confident zero.
"""

from __future__ import annotations

import time
from bisect import insort
from collections import deque
from dataclasses import dataclass, field


@dataclass(slots=True)
class TrafficTelemetry:
    """Last traffic-rate report from the ingestion/detection layer."""

    flows_per_sec: float = 0.0
    packets_per_sec: float = 0.0
    mbps: float = 0.0
    detectors_online: int = 0
    detectors_total: int = 0
    reported_at: float = 0.0
    source: str = "none"


@dataclass(slots=True)
class DetectorRecord:
    """Per-detector accounting for the System view's status panel."""

    detector: str
    detector_version: str = ""
    alerts_produced: int = 0
    last_seen: float = 0.0
    #: Sum of event_end -> detected_at, i.e. time spent inside the detector.
    #: Deliberately NOT pipeline latency: the System view's per-detector column
    #: is "mean scoring time" (Frontend spec 6.2), which is a property of the
    #: detector alone. Mixing in transport would make a slow network look like a
    #: slow model.
    detector_latency_sum_ms: float = 0.0
    threat_classes: set[str] = field(default_factory=set)

    @property
    def mean_detector_latency_ms(self) -> float:
        if not self.alerts_produced:
            return 0.0
        return self.detector_latency_sum_ms / self.alerts_produced


class MetricsRegistry:
    """Rolling metrics over a fixed time window.

    Both series are plain deques of (timestamp, value) trimmed on read.  At the
    rates this backend targets that is cheaper and far easier to reason about
    than a histogram sketch, and it keeps the percentiles exact.
    """

    def __init__(
        self,
        window_s: float = 60.0,
        max_samples: int = 200_000,
        max_plausible_latency_ms: float = 300_000.0,
    ) -> None:
        self._window = window_s
        self._max_samples = max_samples
        self._max_plausible_latency_ms = max_plausible_latency_ms
        self._alert_times: deque[float] = deque()
        self._latencies: deque[tuple[float, float]] = deque()
        self._started = time.time()

        self.alerts_total = 0
        self.alerts_deduplicated = 0
        self.alerts_rejected = 0
        self.incidents_total = 0
        #: Alerts whose packet-to-alert delay exceeded any plausible bound,
        #: which means their event time came from a recorded capture rather
        #: than from live traffic. Excluded from the latency distribution and
        #: reported separately, so the System view can say "replayed capture -
        #: pipeline latency not measurable" instead of showing a number in the
        #: billions.
        self.historical_alerts = 0

        self.traffic = TrafficTelemetry()
        self.detectors: dict[str, DetectorRecord] = {}

        # Peak sustained rate observed over any one-second bucket. This is the
        # number requirement (d) actually wants: measured, not estimated.
        self.peak_alerts_per_sec = 0.0
        self._bucket_start = self._started
        self._bucket_count = 0

    # ------------------------------------------------------------------

    def record_alert(
        self,
        *,
        detector: str,
        detector_version: str,
        threat_class: str,
        detector_latency_ms: float,
        pipeline_latency_ms: float,
        deduplicated: bool,
        now: float | None = None,
    ) -> None:
        now = time.time() if now is None else now
        self.alerts_total += 1
        if deduplicated:
            self.alerts_deduplicated += 1

        self._alert_times.append(now)
        # A negative latency means the detector's clock is ahead of ours. Clamp
        # rather than discard: a distorted percentile is more useful than a
        # silently missing sample, and the System view surfaces clock skew
        # through detector_latency_ms separately.
        latency = max(pipeline_latency_ms, 0.0)
        if latency > self._max_plausible_latency_ms:
            # Not a latency at all: the age of a replayed capture.
            # pipeline_latency_ms is (receipt - event_end), which is the true
            # packet-to-alert delay on live traffic and is meaningless on a
            # capture recorded last month - it reads in the billions of
            # milliseconds and drags p50, p95 and the whole histogram with it.
            # The backend's own ReplayEngine shifts fixture timestamps onto the
            # wall clock for exactly this reason, but alerts POSTed by the
            # detection layer from a historical PCAP do not go through it.
            #
            # Counted, not silently dropped: the System view labels these as
            # replayed rather than pretending the sample never arrived, and the
            # honest per-alert value still travels on the alert itself.
            self.historical_alerts += 1
        else:
            self._latencies.append((now, latency))
        self._trim(now)

        rec = self.detectors.get(detector)
        if rec is None:
            rec = DetectorRecord(detector=detector)
            self.detectors[detector] = rec
        rec.detector_version = detector_version
        rec.alerts_produced += 1
        rec.last_seen = now
        rec.detector_latency_sum_ms += max(detector_latency_ms, 0.0)
        rec.threat_classes.add(threat_class)

        self._update_peak(now)

    def record_rejection(self) -> None:
        self.alerts_rejected += 1

    def record_incident(self) -> None:
        self.incidents_total += 1

    def record_telemetry(
        self,
        *,
        flows_per_sec: float,
        packets_per_sec: float,
        mbps: float,
        detectors_online: int,
        detectors_total: int,
        source: str,
        now: float | None = None,
    ) -> None:
        self.traffic = TrafficTelemetry(
            flows_per_sec=flows_per_sec,
            packets_per_sec=packets_per_sec,
            mbps=mbps,
            detectors_online=detectors_online,
            detectors_total=detectors_total,
            reported_at=time.time() if now is None else now,
            source=source,
        )

    # ------------------------------------------------------------------

    def _trim(self, now: float) -> None:
        cutoff = now - self._window
        while self._alert_times and self._alert_times[0] < cutoff:
            self._alert_times.popleft()
        while self._latencies and self._latencies[0][0] < cutoff:
            self._latencies.popleft()
        # Backstop for a burst so intense that one window's worth of samples is
        # itself too much to hold.
        while len(self._alert_times) > self._max_samples:
            self._alert_times.popleft()
        while len(self._latencies) > self._max_samples:
            self._latencies.popleft()

    def _update_peak(self, now: float) -> None:
        if now - self._bucket_start >= 1.0:
            elapsed = now - self._bucket_start
            rate = self._bucket_count / elapsed if elapsed > 0 else 0.0
            self.peak_alerts_per_sec = max(self.peak_alerts_per_sec, rate)
            self._bucket_start = now
            self._bucket_count = 1
        else:
            self._bucket_count += 1

    # ------------------------------------------------------------------

    def alerts_per_sec(self, now: float | None = None) -> float:
        now = time.time() if now is None else now
        self._trim(now)
        if not self._alert_times:
            return 0.0
        # Divide by elapsed time rather than the nominal window, so the rate is
        # correct in the first minute after startup instead of reading low.
        span = min(self._window, max(now - self._started, 1e-6))
        return len(self._alert_times) / span

    def latency_percentiles(
        self, now: float | None = None, window_s: float | None = None
    ) -> tuple[float, float, float]:
        """(p50, p95, max) in milliseconds over the rolling window.

        ``window_s`` narrows the sample set to the last N seconds. Without it a
        caller measuring a short burst reads percentiles dominated by whatever
        happened in the preceding minute - which makes a fast phase that follows
        a saturated one look catastrophically slow, and is exactly how a load
        harness ends up reporting the previous phase's numbers.
        """
        now = time.time() if now is None else now
        self._trim(now)
        if not self._latencies:
            return (0.0, 0.0, 0.0)
        cutoff = now - window_s if window_s else None
        values: list[float] = []
        for ts, v in self._latencies:
            if cutoff is not None and ts < cutoff:
                continue
            insort(values, v)
        if not values:
            return (0.0, 0.0, 0.0)
        n = len(values)
        p50 = values[int(n * 0.50)] if n else 0.0
        p95 = values[min(int(n * 0.95), n - 1)] if n else 0.0
        return (round(p50, 3), round(p95, 3), round(values[-1], 3))

    def latency_histogram(self, bins: int = 24) -> list[dict[str, float]]:
        """For the System view's latency panel (Frontend spec 6.2)."""
        if not self._latencies:
            return []
        values = sorted(v for _, v in self._latencies)
        lo, hi = values[0], values[-1]
        if hi - lo < 1e-9:
            return [{"bin_start": lo, "bin_end": lo, "count": len(values)}]
        width = (hi - lo) / bins
        counts = [0] * bins
        for v in values:
            counts[min(int((v - lo) / width), bins - 1)] += 1
        return [
            {"bin_start": lo + i * width, "bin_end": lo + (i + 1) * width, "count": c}
            for i, c in enumerate(counts)
        ]

    def traffic_is_live(self, stale_after_s: float, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return (
            self.traffic.reported_at > 0
            and (now - self.traffic.reported_at) <= stale_after_s
        )

    @property
    def uptime_s(self) -> float:
        return time.time() - self._started
