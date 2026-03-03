"""
AegisLink -- Shadow AI Agent Simulator (Malicious)
============================================================

Simulates a compromised/hijacked AI agent performing
automated malicious operations:
  - Bulk data scraping with high request volumes
  - Unauthorized folder traversal across sensitive dirs
  - Abnormally low latency indicating bot automation

Sends rapid POST requests to /agent/analyze and logs responses.

Usage:
    python -u evil_agent.py
    python -u evil_agent.py --url http://localhost:8000 --interval 1
"""

import argparse
import random
import sys
import time
import os
import requests as http_client
from datetime import datetime

# Force UTF-8 output on Windows
if sys.platform == "win32":
    os.system("")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# -- Configuration ------------------------------------------------------------

DEFAULT_URL = "http://localhost:8000/agent/analyze"
DEFAULT_INTERVAL = 1  # faster than good agent

# Malicious behavioral parameters
REQUESTS_RANGE = (120, 300)       # high-frequency request flood
FOLDERS_RANGE = (10, 25)          # broad unauthorized traversal
LATENCY_RANGE = (0.5, 2.0)       # suspiciously fast (automated bot)

# Simulated attack descriptions
ATTACKS = [
    "[SCRAPE] Bulk harvesting user credentials database",
    "[TRAVERSE] Scanning /etc/shadow and /root/.ssh/",
    "[EXFIL] Exfiltrating encrypted finance records",
    "[PROBE] Probing internal API endpoints for vulns",
    "[INJECT] Attempting memory injection on auth service",
    "[LATERAL] Lateral movement to database cluster",
    "[PRIVESC] Privilege escalation via token forgery",
    "[ENUM] Enumerating admin accounts and hashes",
    "[DUMP] Dumping full SQL backup to external host",
    "[HARVEST] Harvesting API keys from config files",
    "[SCAN] Port scanning internal subnet 10.0.x.x",
    "[BYPASS] Bypassing WAF rules on /admin endpoint",
]

# -- Colors --------------------------------------------------------------------

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner():
    print(f"""
{RED}{BOLD}+----------------------------------------------------------+
|    [!!]  AegisLink -- Shadow AI Agent Simulator           |
|          Compromised / Hijacked Agent Emulation           |
+----------------------------------------------------------+{RESET}
{DIM}  Agent Type   : {RED}Malicious (Shadow Agent){RESET}
{DIM}  Behavior     : {RED}High-frequency automated abuse{RESET}
{DIM}  Requests     : {REQUESTS_RANGE[0]}-{REQUESTS_RANGE[1]} per cycle (FLOOD){RESET}
{DIM}  Folders      : {FOLDERS_RANGE[0]}-{FOLDERS_RANGE[1]} accessed (TRAVERSAL){RESET}
{DIM}  Latency      : {LATENCY_RANGE[0]}-{LATENCY_RANGE[1]}ms (BOT SPEED){RESET}
""")


# -- Main Loop -----------------------------------------------------------------

def simulate(url: str, interval: float):
    print_banner()
    print(f"{DIM}  Target URL   : {url}{RESET}")
    print(f"{DIM}  Interval     : {interval}s (rapid fire){RESET}")
    print(f"\n{RED}{'=' * 58}{RESET}\n")

    cycle = 0
    blocked_count = 0

    while True:
        cycle += 1
        now = datetime.now().strftime("%H:%M:%S")

        # Generate malicious behavioral data
        req_count = random.randint(*REQUESTS_RANGE)
        folders = random.randint(*FOLDERS_RANGE)
        latency = round(random.uniform(*LATENCY_RANGE), 2)
        attack = random.choice(ATTACKS)

        payload = {
            "requests": req_count,
            "folders_accessed": folders,
            "latency": latency,
        }

        print(f"{DIM}[{now}]{RESET} {RED}Cycle #{cycle}{RESET}  {MAGENTA}{attack}{RESET}")
        print(f"  >> Payload: requests={req_count}, folders={folders}, latency={latency}ms")

        try:
            resp = http_client.post(url, json=payload, timeout=5)
            data = resp.json()

            status = data.get("status", "unknown")
            risk_score = data.get("risk_score", 0)
            threat_level = data.get("threat_level", "unknown")

            # Color the threat level
            tl_color = GREEN if threat_level == "low" else YELLOW if threat_level == "moderate" else RED
            st_color = RED if status == "blocked" else YELLOW

            print(f"  << Status: {st_color}{BOLD}{status.upper()}{RESET} | "
                  f"Risk: {RED}{BOLD}{risk_score}{RESET} | "
                  f"Threat: {tl_color}{BOLD}{threat_level.upper()}{RESET}")

            # Required output label
            print(f"  {RED}{BOLD}Shadow Agent -> Threat Detected{RESET}")

            if status == "blocked":
                blocked_count += 1
                print(f"  {RED}  >> Session BLOCKED by AegisLink defense engine{RESET}")

            # Running stats
            det_rate = (blocked_count / cycle) * 100
            print(f"  {DIM}[Stats] Blocked: {blocked_count}/{cycle} | "
                  f"Detection Rate: {det_rate:.0f}%{RESET}")

        except http_client.ConnectionError:
            print(f"  {RED}[X] Connection failed -- is backend running at {url}?{RESET}")
        except http_client.Timeout:
            print(f"  {YELLOW}[!] Request timed out{RESET}")
        except Exception as e:
            print(f"  {RED}[X] Error: {e}{RESET}")

        print(f"{DIM}  {'.' * 50}{RESET}")

        # Short interval with jitter
        jitter = random.uniform(-0.3, 0.3)
        time.sleep(max(interval + jitter, 0.5))


# -- Entry Point ---------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="AegisLink Shadow AI Agent -- simulates malicious automated behavior"
    )
    parser.add_argument("--url", default=DEFAULT_URL, help="Analyze endpoint URL")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="Seconds between requests")
    args = parser.parse_args()

    try:
        simulate(args.url, args.interval)
    except KeyboardInterrupt:
        print(f"\n\n{RED}{BOLD}Shadow Agent terminated.{RESET}\n")
