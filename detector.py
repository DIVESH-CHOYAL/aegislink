"""Anomaly detection engine for AegisLink.

Uses configurable threshold rules to detect Shadow Agents:
- High request frequency (>10 per 10s window)
- High sensitive file access ratio (>50%)
- Suspiciously low latency (<30ms avg)

If >= 2 flags triggered → classify as Shadow Agent.
"""

import uuid
from datetime import datetime, timezone
from models import MonitoringMetrics, Alert


# Configurable thresholds
FREQ_THRESHOLD = 10        # max requests per 10-second window
SENSITIVE_RATIO_THRESHOLD = 0.50  # max sensitive file ratio
LATENCY_THRESHOLD = 30.0   # min avg latency (below = suspicious)
FLAG_COUNT_TO_BLOCK = 2    # number of flags needed to trigger blocking


class AnomalyDetector:
    """Evaluates agent metrics against threshold rules."""

    def __init__(self):
        self._blocked_agents: set[str] = set()

    def evaluate(self, metrics: MonitoringMetrics, agent_name: str) -> tuple[float, list[str], Alert | None]:
        """
        Evaluate metrics and return (risk_score, flags, optional_alert).

        Risk score: 0-100 based on how many thresholds are exceeded and by how much.
        """
        if metrics.agent_id in self._blocked_agents:
            return 100.0, ["BLOCKED"], None

        flags = []
        risk_score = 0.0

        # Check request frequency
        if metrics.request_frequency > FREQ_THRESHOLD:
            flags.append(f"HIGH_FREQUENCY: {metrics.request_frequency:.0f} req/10s (threshold: {FREQ_THRESHOLD})")
            # Scale risk by how far over threshold
            overshoot = metrics.request_frequency / FREQ_THRESHOLD
            risk_score += min(overshoot * 20, 40)

        # Check sensitive file ratio
        if metrics.sensitive_file_ratio > SENSITIVE_RATIO_THRESHOLD:
            flags.append(f"SENSITIVE_ACCESS: {metrics.sensitive_file_ratio:.1%} sensitive files (threshold: {SENSITIVE_RATIO_THRESHOLD:.0%})")
            risk_score += metrics.sensitive_file_ratio * 35

        # Check latency (suspiciously low = automated/malicious)
        if metrics.avg_latency_ms > 0 and metrics.avg_latency_ms < LATENCY_THRESHOLD:
            flags.append(f"LOW_LATENCY: {metrics.avg_latency_ms:.1f}ms avg (threshold: {LATENCY_THRESHOLD}ms)")
            # Lower latency = higher risk
            latency_ratio = 1 - (metrics.avg_latency_ms / LATENCY_THRESHOLD)
            risk_score += latency_ratio * 30

        # Cap at 100
        risk_score = min(round(risk_score, 1), 100.0)

        # If no flags, give a small base risk from frequency
        if not flags and metrics.request_frequency > 0:
            risk_score = min(metrics.request_frequency * 1.5, 15.0)

        # Determine if agent should be blocked
        alert = None
        if len(flags) >= FLAG_COUNT_TO_BLOCK:
            self._blocked_agents.add(metrics.agent_id)
            risk_score = 100.0
            alert = Alert(
                alert_id=str(uuid.uuid4())[:8],
                agent_id=metrics.agent_id,
                agent_name=agent_name,
                risk_score=risk_score,
                reason=" | ".join(flags),
                action="blocked",
                classification="Imposter AI",
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        return risk_score, flags, alert

    def is_blocked(self, agent_id: str) -> bool:
        return agent_id in self._blocked_agents

    def reset(self):
        self._blocked_agents.clear()
