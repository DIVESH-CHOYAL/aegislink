"""Behavioral monitoring engine for AegisLink.

Tracks per-agent metrics:
- Request frequency (rolling 10-second window)
- File access patterns (sensitive file ratio)
- Response latency signature (average latency)
"""

import time
from collections import defaultdict, deque
from models import AgentEvent, MonitoringMetrics


class BehavioralMonitor:
    """Tracks and computes behavioral metrics for each agent."""

    WINDOW_SECONDS = 10  # Rolling window size

    def __init__(self):
        # Per-agent event history (deque of (timestamp, event) tuples)
        self._events: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # Per-agent total request count
        self._total_requests: dict[str, int] = defaultdict(int)

    def record_event(self, event: AgentEvent):
        """Record a new event for an agent."""
        now = time.time()
        self._events[event.agent_id].append((now, event))
        self._total_requests[event.agent_id] += 1

    def get_metrics(self, agent_id: str) -> MonitoringMetrics:
        """Compute current behavioral metrics for an agent."""
        now = time.time()
        window_start = now - self.WINDOW_SECONDS
        events = self._events[agent_id]

        # Filter events within the rolling window
        recent_events = [(ts, ev) for ts, ev in events if ts >= window_start]

        if not recent_events:
            return MonitoringMetrics(
                agent_id=agent_id,
                request_frequency=0.0,
                sensitive_file_ratio=0.0,
                avg_latency_ms=0.0,
                flags=[],
            )

        # Request frequency: count in window
        request_frequency = len(recent_events)

        # Sensitive file ratio
        sensitive_count = sum(1 for _, ev in recent_events if ev.is_sensitive)
        sensitive_file_ratio = sensitive_count / len(recent_events)

        # Average latency
        avg_latency = sum(ev.latency_ms for _, ev in recent_events) / len(recent_events)

        return MonitoringMetrics(
            agent_id=agent_id,
            request_frequency=float(request_frequency),
            sensitive_file_ratio=round(sensitive_file_ratio, 3),
            avg_latency_ms=round(avg_latency, 1),
        )

    def get_total_requests(self, agent_id: str) -> int:
        return self._total_requests.get(agent_id, 0)

    def reset(self):
        """Clear all monitoring data."""
        self._events.clear()
        self._total_requests.clear()
