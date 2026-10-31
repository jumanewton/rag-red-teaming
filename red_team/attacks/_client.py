"""
Shared client and utilities for all red team attack scripts.
"""
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import httpx
from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

# ── Load config from env ───────────────────────────────────────────────────────
RAG_URL = os.getenv("RAG_SERVICE_URL", "http://localhost:8000")
API_KEY = os.getenv("RED_TEAM_API_KEY", "redteam-secret-key-change-in-prod")
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "./red_team/reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}


@dataclass
class AttackResult:
    attack_name: str
    category: str
    severity: str          # critical | high | medium | low
    owasp_mapping: str
    payload: str
    response: str
    vulnerable: bool
    notes: str = ""
    latency_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


def query_rag(
    question: str,
    session_id: Optional[str] = None,
    access_level: str = "public",
    api_key: Optional[str] = None,
    use_cache: bool = False,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """
    Send a query to the live RAG service.
    Returns the parsed JSON response or an error dict.
    """
    key = api_key or API_KEY
    headers = {"X-API-Key": key, "Content-Type": "application/json"}
    payload = {
        "question": question,
        "session_id": session_id or str(uuid.uuid4()),
        "access_level": access_level,
        "use_cache": use_cache,
    }
    t0 = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(f"{RAG_URL}/api/v1/query", json=payload, headers=headers)
            latency = (time.perf_counter() - t0) * 1000
            if resp.status_code == 200:
                data = resp.json()
                data["_latency_ms"] = round(latency, 2)
                data["_status_code"] = 200
                return data
            else:
                return {
                    "_status_code": resp.status_code,
                    "_error": resp.text,
                    "_latency_ms": round(latency, 2),
                    "answer": "",
                }
    except Exception as e:
        return {"_status_code": 0, "_error": str(e), "answer": "", "_latency_ms": 0}


def check_vulnerability(response: dict, indicators: list[str]) -> tuple[bool, str]:
    """
    Checks if a response contains any vulnerability indicator strings.
    Returns (is_vulnerable, matched_indicator).
    """
    answer = response.get("answer", "").lower()
    for indicator in indicators:
        if indicator.lower() in answer:
            return True, indicator
    return False, ""


def print_result(result: AttackResult) -> None:
    color = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }.get(result.severity, "white")

    icon = "🔴" if result.vulnerable else "✅"
    console.print(
        f"\n{icon} [{color}]{result.attack_name}[/{color}] "
        f"({result.severity.upper()}) — {'VULNERABLE' if result.vulnerable else 'SAFE'}"
    )
    if result.vulnerable:
        console.print(f"   [dim]OWASP: {result.owasp_mapping}[/dim]")
        console.print(f"   [dim]Notes: {result.notes}[/dim]")


def save_results(results: list[AttackResult], suite_name: str) -> Path:
    """Save attack results to a JSON file."""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_path = REPORTS_DIR / f"{suite_name}_{ts}.json"
    data = [
        {
            "attack_name": r.attack_name,
            "category": r.category,
            "severity": r.severity,
            "owasp_mapping": r.owasp_mapping,
            "vulnerable": r.vulnerable,
            "payload": r.payload[:500],
            "response_snippet": r.response[:500],
            "notes": r.notes,
            "latency_ms": r.latency_ms,
            "timestamp": r.timestamp,
        }
        for r in results
    ]
    out_path.write_text(json.dumps(data, indent=2))
    console.print(f"\n💾 Results saved: [link]{out_path}[/link]")
    return out_path


def print_summary_table(results: list[AttackResult]) -> None:
    table = Table(title="Red Team Summary", show_header=True, header_style="bold magenta")
    table.add_column("Attack", style="dim", width=35)
    table.add_column("Severity", width=10)
    table.add_column("OWASP", width=8)
    table.add_column("Result", width=12)
    table.add_column("Notes", width=40)

    for r in results:
        result_str = "[red]VULNERABLE[/red]" if r.vulnerable else "[green]SAFE[/green]"
        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}
        sev_str = f"[{sev_colors.get(r.severity, 'white')}]{r.severity.upper()}[/{sev_colors.get(r.severity, 'white')}]"
        table.add_row(r.attack_name, sev_str, r.owasp_mapping, result_str, r.notes[:40])

    console.print(table)
    vulnerable_count = sum(1 for r in results if r.vulnerable)
    console.print(
        f"\n[bold]Total: {len(results)} tests | "
        f"[red]{vulnerable_count} VULNERABLE[/red] | "
        f"[green]{len(results) - vulnerable_count} SAFE[/green][/bold]"
    )
