"""AegisLink — FastAPI backend for cybersecurity AI agent monitoring.

Endpoints:
- GET  /api/agents           → list all agents with current status
- GET  /api/alerts           → list all generated alerts
- POST /agent/analyze        → behavioral anomaly detection
- POST /api/simulation/start → start agent simulation
- POST /api/simulation/stop  → stop agent simulation
- WS   /ws/live              → live event + alert stream
"""

import asyncio
import json
import sys
import os
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

# Force UTF-8 console output on Windows
if sys.platform == "win32":
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


# -- ANSI Colors for Console Logger --------------------------------------------

_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_analyze_count = 0  # global request counter


def detection_logger(payload, risk_score: float, status: str, threat_level: str):
    """Print a color-coded detection log line to the console."""
    global _analyze_count
    _analyze_count += 1
    now = datetime.now().strftime("%H:%M:%S")
    count = _analyze_count

    # Classify agent type based on score
    if risk_score > 70:
        tag = f"{_RED}{_BOLD}[ALERT]{_RESET}"
        agent_label = f"{_RED}Shadow AI Agent{_RESET}"
        status_label = f"{_RED}{_BOLD}BLOCKED{_RESET}"
    elif risk_score > 40:
        tag = f"{_YELLOW}{_BOLD}[WARN]{_RESET}"
        agent_label = f"{_YELLOW}Suspicious Agent{_RESET}"
        status_label = f"{_YELLOW}{_BOLD}SUSPICIOUS{_RESET}"
    else:
        tag = f"{_GREEN}{_BOLD}[INFO]{_RESET}"
        agent_label = f"{_GREEN}Legitimate AI Agent{_RESET}"
        status_label = f"{_GREEN}{_BOLD}SAFE{_RESET}"

    # Score color
    if risk_score > 70:
        score_str = f"{_RED}{_BOLD}{risk_score}{_RESET}"
    elif risk_score > 40:
        score_str = f"{_YELLOW}{_BOLD}{risk_score}{_RESET}"
    else:
        score_str = f"{_GREEN}{_BOLD}{risk_score}{_RESET}"

    # Main log line
    print(
        f"{_DIM}[{now}]{_RESET} {tag} "
        f"{agent_label} -> "
        f"Risk Score: {score_str} -> "
        f"Status: {status_label}"
    )

    # Detail line with payload
    print(
        f"  {_DIM}#{count}  "
        f"requests={payload.requests}  "
        f"folders={payload.folders_accessed}  "
        f"latency={payload.latency}ms  "
        f"threat={threat_level}{_RESET}"
    )

    # Separator
    if risk_score > 70:
        print(f"  {_RED}>> SESSION BLOCKED BY AEGISLINK{_RESET}")

    sys.stdout.flush()

from agents import LegitimateAgent, MaliciousAgent
from monitor import BehavioralMonitor
from detector import AnomalyDetector
from models import AgentStatus, AnalyzeRequest, AnalyzeResponse


# ── Shared State ──────────────────────────────────────────────────────────────

event_queue: asyncio.Queue = asyncio.Queue()
monitor = BehavioralMonitor()
detector = AnomalyDetector()

legit_agent = LegitimateAgent()
mal_agent = MaliciousAgent()

alerts_log: list[dict] = []
agent_tasks: list[asyncio.Task] = []
processor_task: asyncio.Task | None = None
simulation_running = False

# Connected WebSocket clients
ws_clients: set[WebSocket] = set()

# Per-agent time-series data for the frontend graph
activity_history: dict[str, list[dict]] = {
    legit_agent.agent_id: [],
    mal_agent.agent_id: [],
}

# Current risk scores
risk_scores: dict[str, float] = {
    legit_agent.agent_id: 0.0,
    mal_agent.agent_id: 0.0,
}

# Analyze endpoint tracking
_analyze_req_count = 0
analyze_history: dict[str, list[dict]] = {
    "good-agent": [],
    "shadow-agent": [],
}


# ── Event Processor ──────────────────────────────────────────────────────────

async def process_events():
    """Main loop: dequeue events, monitor, detect, broadcast."""
    global simulation_running
    while simulation_running:
        try:
            event = await asyncio.wait_for(event_queue.get(), timeout=0.5)
        except asyncio.TimeoutError:
            continue

        # Record in monitor
        monitor.record_event(event)

        # Get current metrics
        metrics = monitor.get_metrics(event.agent_id)

        # Detect anomalies
        agent_name = event.agent_name
        risk_score, flags, alert = detector.evaluate(metrics, agent_name)
        risk_scores[event.agent_id] = risk_score

        # If alert generated → block the malicious agent
        if alert:
            alerts_log.append(alert.model_dump())
            if event.agent_id == mal_agent.agent_id:
                mal_agent.block()

        # Build activity data point
        data_point = {
            "timestamp": event.timestamp,
            "requests_in_window": metrics.request_frequency,
        }
        history = activity_history.get(event.agent_id, [])
        history.append(data_point)
        # Keep last 100 points
        if len(history) > 100:
            history = history[-100:]
        activity_history[event.agent_id] = history

        # Broadcast to all WebSocket clients
        message = {
            "type": "event",
            "event": event.model_dump(),
            "metrics": metrics.model_dump(),
            "risk_score": risk_score,
            "flags": flags,
            "alert": alert.model_dump() if alert else None,
            "activity": {
                agent_id: hist[-50:] for agent_id, hist in activity_history.items()
            },
        }
        await broadcast(message)


async def broadcast(message: dict):
    """Send a message to all connected WebSocket clients."""
    global ws_clients
    dead = set()
    data = json.dumps(message)
    for ws in ws_clients:
        try:
            await ws.send_text(data)
        except Exception:
            dead.add(ws)
    ws_clients -= dead


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    # Cleanup on shutdown
    await stop_simulation()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="AegisLink", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REST Endpoints ────────────────────────────────────────────────────────────

@app.get("/api/agents")
async def get_agents():
    """Return current status of all agents."""
    agents = []
    for agent in [legit_agent, mal_agent]:
        is_blocked = detector.is_blocked(agent.agent_id)
        agents.append(AgentStatus(
            agent_id=agent.agent_id,
            agent_name=agent.agent_name,
            agent_type=agent.agent_type,
            is_blocked=is_blocked,
            total_requests=monitor.get_total_requests(agent.agent_id),
            risk_score=risk_scores.get(agent.agent_id, 0.0),
            classification="Imposter AI" if is_blocked else "Good AI",
        ).model_dump())
    return {"agents": agents, "simulation_running": simulation_running}


@app.get("/api/alerts")
async def get_alerts():
    """Return all generated alerts."""
    return {"alerts": alerts_log}



# ── Behavioral Anomaly Analysis ───────────────────────────────────────────────

@app.post("/agent/analyze", response_model=AnalyzeResponse)
async def analyze_agent(payload: AnalyzeRequest):
    """
    Behavioral anomaly detection for AI agents.

    Accepts JSON with { requests, folders_accessed, latency } and returns
    a risk_score (0-100) with status and threat_level classification.

    Scoring logic:
    - High request frequency (>100) → increases risk (up to 40 pts)
    - Many folders accessed (>10) → increases risk (up to 35 pts)
    - Very low latency (<2ms) → automated attack indicator (up to 30 pts)

    If risk_score > 70: status='blocked', threat_level='critical'
    """
    risk_score = 0.0

    # ── Factor 1: Request frequency ───────────────────────────────────────
    if payload.requests > 100:
        # Base 20pts + scale to 30 more (total 20-50)
        freq_risk = 20 + min(((payload.requests - 100) / 200) * 30, 30)
        risk_score += freq_risk
    elif payload.requests > 50:
        risk_score += ((payload.requests - 50) / 50) * 10

    # ── Factor 2: Folder access breadth ───────────────────────────────────
    if payload.folders_accessed > 10:
        # Base 15pts + scale to 25 more (total 15-40)
        folder_risk = 15 + min(((payload.folders_accessed - 10) / 15) * 25, 25)
        risk_score += folder_risk
    elif payload.folders_accessed > 5:
        risk_score += ((payload.folders_accessed - 5) / 5) * 8

    # ── Factor 3: Latency signature ───────────────────────────────────────
    if payload.latency < 2.0:
        # Base 10pts + scale to 25 more (total 10-35)
        latency_risk = 10 + ((2.0 - payload.latency) / 2.0) * 25
        risk_score += latency_risk
    elif payload.latency < 5.0:
        risk_score += ((5.0 - payload.latency) / 3.0) * 8

    # Clamp score to 0-100
    risk_score = round(min(max(risk_score, 0), 100), 1)

    # ── Classification ────────────────────────────────────────────────────
    if risk_score > 70:
        status = "blocked"
        threat_level = "critical"
    elif risk_score > 40:
        status = "safe"
        threat_level = "moderate"
    else:
        status = "safe"
        threat_level = "low"

    # -- Real-time detection logger --
    detection_logger(payload, risk_score, status, threat_level)

    # -- Broadcast to frontend via WebSocket --
    global _analyze_req_count
    _analyze_req_count += 1

    # Determine agent identity from behavior
    is_shadow = risk_score > 40
    agent_id = "shadow-agent" if is_shadow else "good-agent"
    agent_name = "Monitored AI Agent"
    agent_type = "malicious" if is_shadow else "legitimate"

    now = datetime.now().isoformat()

    # Build activity data point
    data_point = {
        "timestamp": now,
        "requests_in_window": float(payload.requests),
    }
    history = analyze_history.get(agent_id, [])
    history.append(data_point)
    if len(history) > 100:
        history = history[-100:]
    analyze_history[agent_id] = history

    # Update risk scores
    risk_scores[agent_id] = risk_score

    # Build alert if blocked
    alert_data = None
    if status == "blocked":
        import uuid
        alert_data = {
            "alert_id": str(uuid.uuid4())[:8],
            "agent_id": agent_id,
            "agent_name": agent_name,
            "risk_score": risk_score,
            "reason": f"Anomaly: requests={payload.requests}, folders={payload.folders_accessed}, latency={payload.latency}ms",
            "action": "blocked",
            "classification": "Imposter AI",
            "timestamp": now,
        }
        alerts_log.append(alert_data)

    # Build WebSocket message matching frontend format
    ws_message = {
        "type": "event",
        "event": {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "agent_type": agent_type,
            "request_type": "analyze",
            "file_accessed": f"{payload.folders_accessed} folders",
            "latency_ms": payload.latency,
            "timestamp": now,
            "is_sensitive": payload.folders_accessed > 10,
        },
        "metrics": {
            "agent_id": agent_id,
            "request_frequency": float(payload.requests),
            "sensitive_file_ratio": min(payload.folders_accessed / 25, 1.0),
            "avg_latency_ms": payload.latency,
            "flags": [threat_level],
        },
        "risk_score": risk_score,
        "flags": [threat_level],
        "alert": alert_data,
        "activity": {
            aid: h[-50:] for aid, h in {**activity_history, **analyze_history}.items()
        },
    }
    await broadcast(ws_message)

    return AnalyzeResponse(
        status=status,
        risk_score=risk_score,
        threat_level=threat_level,
    )


@app.post("/api/simulation/start")
async def start_simulation():
    """Start the agent simulation."""
    global simulation_running, processor_task, agent_tasks

    if simulation_running:
        return {"status": "already_running"}

    # Reset state
    monitor.reset()
    detector.reset()
    alerts_log.clear()
    risk_scores[legit_agent.agent_id] = 0.0
    risk_scores[mal_agent.agent_id] = 0.0
    activity_history[legit_agent.agent_id] = []
    activity_history[mal_agent.agent_id] = []

    # Drain queue
    while not event_queue.empty():
        try:
            event_queue.get_nowait()
        except asyncio.QueueEmpty:
            break

    # Re-init agents
    legit_agent.__init__()
    mal_agent.__init__()

    simulation_running = True

    # Start agent tasks
    agent_tasks = [
        asyncio.create_task(legit_agent.run(event_queue)),
        asyncio.create_task(mal_agent.run(event_queue)),
    ]

    # Start event processor
    processor_task = asyncio.create_task(process_events())

    return {"status": "started"}


@app.post("/api/simulation/stop")
async def stop_simulation_endpoint():
    """Stop the agent simulation."""
    await stop_simulation()
    return {"status": "stopped"}


async def stop_simulation():
    """Stop all running tasks."""
    global simulation_running, processor_task, agent_tasks

    simulation_running = False
    legit_agent.stop()
    mal_agent.stop()

    for task in agent_tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    if processor_task:
        processor_task.cancel()
        try:
            await processor_task
        except asyncio.CancelledError:
            pass

    agent_tasks = []
    processor_task = None


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/live")
async def websocket_live(ws: WebSocket):
    """Live event stream for the dashboard."""
    await ws.accept()
    ws_clients.add(ws)
    try:
        while True:
            # Keep connection alive, listen for pings
            await ws.receive_text()
    except WebSocketDisconnect:
        ws_clients.discard(ws)
    except Exception:
        ws_clients.discard(ws)
