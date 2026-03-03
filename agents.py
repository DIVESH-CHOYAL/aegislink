"""Simulated AI agents for AegisLink.

LegitimateAgent: slow, normal API requests to safe files.
MaliciousAgent: rapid, abnormal requests to sensitive files.
"""

import asyncio
import random
import uuid
from datetime import datetime, timezone
from models import AgentEvent

# File pools
NORMAL_FILES = [
    "/data/reports/quarterly_summary.pdf",
    "/data/reports/annual_review.docx",
    "/data/public/readme.txt",
    "/data/public/changelog.md",
    "/data/logs/app.log",
    "/data/config/display_settings.json",
    "/data/assets/logo.png",
    "/data/exports/report_2025.csv",
]

SENSITIVE_FILES = [
    "/etc/shadow",
    "/data/secrets/api_keys.json",
    "/data/secrets/db_credentials.env",
    "/data/users/admin_hashes.db",
    "/data/users/ssn_records.csv",
    "/data/finance/credit_cards.enc",
    "/data/internal/employee_salaries.xlsx",
    "/data/keys/private_key.pem",
    "/data/backups/full_dump.sql",
    "/root/.ssh/id_rsa",
]

REQUEST_TYPES = ["read", "write", "query"]


class LegitimateAgent:
    """Simulates a well-behaved AI agent making slow, normal requests."""

    def __init__(self):
        self.agent_id = "agent-legit-001"
        self.agent_name = "Atlas (Legitimate)"
        self.agent_type = "legitimate"
        self.running = False

    async def run(self, event_queue: asyncio.Queue):
        """Generate legitimate request events at a slow, regular pace."""
        self.running = True
        while self.running:
            # 1 request every 2-4 seconds
            delay = random.uniform(2.0, 4.0)
            await asyncio.sleep(delay)

            if not self.running:
                break

            # Mostly access normal files, rarely a sensitive one (5% chance)
            if random.random() < 0.05:
                file = random.choice(SENSITIVE_FILES)
                is_sensitive = True
            else:
                file = random.choice(NORMAL_FILES)
                is_sensitive = False

            event = AgentEvent(
                agent_id=self.agent_id,
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                request_type=random.choice(["read", "query"]),  # no writes
                file_accessed=file,
                latency_ms=round(random.uniform(100, 300), 1),
                timestamp=datetime.now(timezone.utc).isoformat(),
                is_sensitive=is_sensitive,
            )
            await event_queue.put(event)

    def stop(self):
        self.running = False


class MaliciousAgent:
    """Simulates a shadow/imposter AI agent making rapid, abnormal requests."""

    def __init__(self):
        self.agent_id = "agent-mal-002"
        self.agent_name = "Specter (Malicious)"
        self.agent_type = "malicious"
        self.running = False
        self.is_blocked = False

    async def run(self, event_queue: asyncio.Queue):
        """Generate rapid burst requests targeting sensitive files."""
        self.running = True
        while self.running and not self.is_blocked:
            # Burst: 5-15 requests with very short delays
            burst_size = random.randint(5, 15)
            for _ in range(burst_size):
                if not self.running or self.is_blocked:
                    break

                # 70% chance of accessing sensitive files
                if random.random() < 0.70:
                    file = random.choice(SENSITIVE_FILES)
                    is_sensitive = True
                else:
                    file = random.choice(NORMAL_FILES)
                    is_sensitive = False

                event = AgentEvent(
                    agent_id=self.agent_id,
                    agent_name=self.agent_name,
                    agent_type=self.agent_type,
                    request_type=random.choice(REQUEST_TYPES),
                    file_accessed=file,
                    latency_ms=round(random.uniform(5, 20), 1),
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    is_sensitive=is_sensitive,
                )
                await event_queue.put(event)

                # Very short delay between burst requests
                await asyncio.sleep(random.uniform(0.05, 0.2))

            # Short pause between bursts
            await asyncio.sleep(random.uniform(0.5, 1.5))

    def stop(self):
        self.running = False

    def block(self):
        self.is_blocked = True
        self.running = False
