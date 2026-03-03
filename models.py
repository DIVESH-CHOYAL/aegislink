"""Pydantic models for AegisLink events, alerts, and agent status."""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class AgentEvent(BaseModel):
    """A single request event emitted by an AI agent."""
    agent_id: str
    agent_name: str
    agent_type: str  # "legitimate" or "malicious"
    request_type: str  # "read", "write", "query"
    file_accessed: str
    latency_ms: float
    timestamp: str
    is_sensitive: bool = False


class Alert(BaseModel):
    """An alert generated when anomalous behavior is detected."""
    alert_id: str
    agent_id: str
    agent_name: str
    risk_score: float
    reason: str
    action: str  # "flagged", "blocked"
    classification: str  # "Good AI" or "Imposter AI"
    timestamp: str


class AgentStatus(BaseModel):
    """Current status summary for an AI agent."""
    agent_id: str
    agent_name: str
    agent_type: str  # "legitimate" or "malicious"
    is_blocked: bool = False
    total_requests: int = 0
    risk_score: float = 0.0
    classification: str = "Good AI"


class MonitoringMetrics(BaseModel):
    """Behavioral monitoring metrics for an agent."""
    agent_id: str
    request_frequency: float  # requests per 10-second window
    sensitive_file_ratio: float  # 0.0 - 1.0
    avg_latency_ms: float
    flags: list[str] = []


class AnalyzeRequest(BaseModel):
    """Input payload for behavioral anomaly analysis."""
    requests: int
    folders_accessed: int
    latency: float


class AnalyzeResponse(BaseModel):
    """Response from behavioral anomaly analysis."""
    status: str              # "safe" or "blocked"
    risk_score: float        # 0-100
    threat_level: str        # "low", "moderate", "critical"

