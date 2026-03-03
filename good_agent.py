"""
AegisLink — Good AI Agent Simulator (Legitimate)
═══════════════════════════════════════════════════

Simulates a trusted corporate AI assistant performing normal,
predictable enterprise operations:
  • Scheduled file access with low folder breadth
  • Controlled API usage with stable request counts
  • Human-like latency (5-15ms response times)

Sends periodic POST requests to /agent/analyze and logs responses.

Usage:
    python good_agent.py
    python good_agent.py --url http://localhost:8000 --interval 3
"""

import argparse
import random
import sys
import time
import os
import requests
from datetime import datetime

# Force UTF-8 output on Windows
if sys.platform == "win32":
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Configuration ─────────────────────────────────────────────────────────────

DEFAULT_URL = "http://localhost:8000/agent/analyze"
DEFAULT_INTERVAL = 3  # seconds between requests

# Legitimate agent behavioral parameters
REQUESTS_RANGE = (10, 40)         # low, stable request count
FOLDERS_RANGE = (1, 5)            # minimal folder access
LATENCY_RANGE = (5.0, 15.0)      # normal human-like latency (ms)

# Simulated task descriptions for logging
TASKS = [
    "[FILE] Accessed quarterly sales report",
    "[MAIL] Processed incoming email queue",
    "[DATA] Generated analytics dashboard",
    "[SYNC] Synced CRM database records",
    "[DOCS] Updated employee onboarding docs",
    "[SCHED] Scheduled calendar invites",
    "[AUDIT] Compiled compliance audit log",
    "[BACKUP] Backed up project repository",
    "[INDEX] Indexed document search cache",
    "[KPI] Refreshed KPI metrics feed",
]


# ── Display Helpers ───────────────────────────────────────────────────────────

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner():
    print(f"""
{CYAN}{BOLD}+----------------------------------------------------------+
|          [OK]  AegisLink -- Good AI Agent Simulator       |
|              Trusted Corporate AI Assistant                |
+----------------------------------------------------------+{RESET}
{DIM}  Agent Type   : Legitimate (Verified)
  Behavior     : Low & stable activity
  Requests     : {REQUESTS_RANGE[0]}-{REQUESTS_RANGE[1]} per cycle
  Folders      : {FOLDERS_RANGE[0]}-{FOLDERS_RANGE[1]} accessed
  Latency      : {LATENCY_RANGE[0]}-{LATENCY_RANGE[1]}ms
{RESET}""")


def format_threat(level: str) -> str:
    colors = {"low": GREEN, "moderate": YELLOW, "critical": RED}
    return f"{colors.get(level, RESET)}{BOLD}{level.upper()}{RESET}"


def format_status(status: str) -> str:
    if status == "safe":
        return f"{GREEN}{BOLD}✅ SAFE{RESET}"
    else:
        return f"{RED}{BOLD}⛔ BLOCKED{RESET}"


# ── Main Loop ─────────────────────────────────────────────────────────────────

def simulate(url: str, interval: float):
    """Run the good agent simulation loop."""
    print_banner()
    print(f"{DIM}  Target URL   : {url}")
    print(f"  Interval     : {interval}s{RESET}")
    print(f"\n{CYAN}{'=' * 58}{RESET}\n")

    cycle = 0
    while True:
        cycle += 1
        now = datetime.now().strftime("%H:%M:%S")

        # Generate normal behavioral data
        req_count = random.randint(*REQUESTS_RANGE)
        folders = random.randint(*FOLDERS_RANGE)
        latency = round(random.uniform(*LATENCY_RANGE), 2)
        task = random.choice(TASKS)

        payload = {
            "requests": req_count,
            "folders_accessed": folders,
            "latency": latency,
        }

        print(f"{DIM}[{now}]{RESET} {CYAN}Cycle #{cycle}{RESET}  {task}")
        print(f"  >> Payload: requests={req_count}, folders={folders}, latency={latency}ms")

        try:
            resp = requests.post(url, json=payload, timeout=5)
            data = resp.json()

            status = data.get("status", "unknown")
            risk_score = data.get("risk_score", 0)
            threat_level = data.get("threat_level", "unknown")

            print(f"  << Response: {format_status(status)} | "
                  f"Risk: {BOLD}{risk_score}{RESET} | "
                  f"Threat: {format_threat(threat_level)}")
            print(f"  {GREEN}{BOLD}[OK] Good AI Agent - Status: SAFE{RESET}")

        except requests.ConnectionError:
            print(f"  {RED}[X] Connection failed -- is the backend running at {url}?{RESET}")
        except requests.Timeout:
            print(f"  {YELLOW}[!] Request timed out{RESET}")
        except Exception as e:
            print(f"  {RED}[X] Error: {e}{RESET}")

        print(f"{DIM}  {'.' * 50}{RESET}")

        # Wait before next cycle (with small jitter for realism)
        jitter = random.uniform(-0.5, 0.5)
        time.sleep(max(interval + jitter, 1.0))


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AegisLink Good AI Agent Simulator — demonstrates baseline legitimate behavior"
    )
    parser.add_argument(
        "--url", default=DEFAULT_URL,
        help=f"Backend analyze endpoint URL (default: {DEFAULT_URL})"
    )
    parser.add_argument(
        "--interval", type=float, default=DEFAULT_INTERVAL,
        help=f"Seconds between requests (default: {DEFAULT_INTERVAL})"
    )
    args = parser.parse_args()

    try:
        simulate(args.url, args.interval)
    except KeyboardInterrupt:
        print(f"\n\n{CYAN}{BOLD}Good AI Agent stopped gracefully. Bye!{RESET}\n")
