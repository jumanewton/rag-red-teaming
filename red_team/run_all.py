"""
Master Red Team Orchestrator
Runs all attack suites in sequence and generates a consolidated HTML report.

Usage:
    python red_team/run_all.py                    # Full suite
    python red_team/run_all.py --suite injection  # Single suite
    python red_team/run_all.py --skip dos         # Skip specific suite
    python red_team/run_all.py --check-only       # Health check only
"""
import argparse
import asyncio
import importlib
import json
import sys
import os
import time
import uuid
from datetime import datetime
from pathlib import Path

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from red_team.attacks._client import (
    AttackResult, print_summary_table, save_results, console,
    RAG_URL, HEADERS, REPORTS_DIR,
)

# ─────────────────────────────────────────────────────────────────────────────
ATTACK_SUITES = [
    {"id": "injection",      "module": "red_team.attacks.01_prompt_injection",      "fn": "run_direct_injections",    "name": "Prompt Injection"},
    {"id": "indirect",       "module": "red_team.attacks.01_prompt_injection",      "fn": "run_indirect_injections",  "name": "Indirect Injection"},
    {"id": "poisoning",      "module": "red_team.attacks.02_corpus_poisoning",      "fn": "run_corpus_poisoning",     "name": "Corpus Poisoning"},
    {"id": "extraction",     "module": "red_team.attacks.03_context_extraction",    "fn": "run_extraction_tests",     "name": "System Prompt Extraction"},
    {"id": "endpoints",      "module": "red_team.attacks.03_context_extraction",    "fn": "probe_unauthenticated_endpoints", "name": "Endpoint Probing"},
    {"id": "rbac",           "module": "red_team.attacks.04_rbac_bypass",           "fn": "run_rbac_tests",           "name": "RBAC Bypass"},
    {"id": "dos",            "module": "red_team.attacks.05_denial_of_service",     "fn": "run_dos_tests",            "name": "Denial of Service"},
    {"id": "hallucination",  "module": "red_team.attacks.06_hallucination_induction", "fn": "run_hallucination_tests", "name": "Hallucination Induction"},
    {"id": "crescendo",      "module": "red_team.attacks.07_multi_turn_crescendo",  "fn": "run_multi_turn_attacks",   "name": "Multi-Turn Crescendo"},
    {"id": "embedding",      "module": "red_team.attacks.08_embedding_inversion",   "fn": "run_embedding_tests",      "name": "Embedding Inversion"},
]


def check_rag_health() -> bool:
    """Verify the RAG service is running before starting attacks."""
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{RAG_URL}/health")
            if resp.status_code == 200:
                data = resp.json()
                console.print(
                    Panel(
                        f"[green]✅ RAG Service Online[/green]\n"
                        f"URL: {RAG_URL}\n"
                        f"ChromaDB: {data.get('chroma', 'unknown')}\n"
                        f"Status: {data.get('status', 'unknown')}",
                        title="[bold]Target Health Check",
                    )
                )
                return True
    except Exception as e:
        console.print(f"[red]❌ RAG Service OFFLINE: {e}[/red]")
        console.print(f"[yellow]Start the service with: uvicorn rag_system.app.main:app --reload[/yellow]")
        return False


def run_suite(suite: dict) -> list[AttackResult]:
    """Dynamically import and run a single attack suite."""
    try:
        mod = importlib.import_module(suite["module"])
        fn = getattr(mod, suite["fn"])
        return fn()
    except Exception as e:
        console.print(f"[red]Suite '{suite['name']}' failed: {e}[/red]")
        import traceback
        traceback.print_exc()
        return []


def generate_html_report(all_results: list[AttackResult], run_id: str) -> Path:
    """Generate a comprehensive HTML vulnerability report."""
    vulnerable = [r for r in all_results if r.vulnerable]
    safe = [r for r in all_results if not r.vulnerable]

    severity_counts = {}
    for r in vulnerable:
        severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1

    owasp_counts = {}
    for r in all_results:
        if r.owasp_mapping not in owasp_counts:
            owasp_counts[r.owasp_mapping] = {"total": 0, "vulnerable": 0}
        owasp_counts[r.owasp_mapping]["total"] += 1
        if r.vulnerable:
            owasp_counts[r.owasp_mapping]["vulnerable"] += 1

    rows = ""
    for r in all_results:
        vuln_class = "danger" if r.vulnerable else "success"
        vuln_text = "🔴 VULNERABLE" if r.vulnerable else "✅ SAFE"
        sev_class = {"critical": "danger", "high": "warning", "medium": "info", "low": "secondary"}.get(r.severity, "secondary")
        rows += f"""
        <tr>
          <td>{r.attack_name}</td>
          <td><span class="badge bg-{sev_class}">{r.severity.upper()}</span></td>
          <td><code>{r.owasp_mapping}</code></td>
          <td><span class="badge bg-{vuln_class}">{vuln_text}</span></td>
          <td><small>{r.notes[:80]}</small></td>
          <td><small>{r.latency_ms:.0f}ms</small></td>
        </tr>"""

    owasp_rows = ""
    for mapping, counts in sorted(owasp_counts.items()):
        pct = int(counts["vulnerable"] / counts["total"] * 100) if counts["total"] else 0
        bar_class = "danger" if pct > 60 else "warning" if pct > 30 else "success"
        owasp_rows += f"""
        <tr>
          <td><strong>{mapping}</strong></td>
          <td>{counts['total']}</td>
          <td>{counts['vulnerable']}</td>
          <td>
            <div class="progress">
              <div class="progress-bar bg-{bar_class}" style="width: {pct}%">{pct}%</div>
            </div>
          </td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>RAG Red Team Report — {run_id}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #e6edf3; }}
    .card {{ background: #161b22; border: 1px solid #30363d; }}
    .card-header {{ background: #21262d; }}
    table {{ color: #e6edf3; }}
    thead {{ background: #21262d; }}
    tr:hover {{ background: #1c2128; }}
    .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }}
    .stat-number {{ font-size: 3rem; font-weight: bold; }}
    .text-danger {{ color: #f85149 !important; }}
    .text-success {{ color: #3fb950 !important; }}
    .text-warning {{ color: #d29922 !important; }}
    code {{ color: #79c0ff; background: #161b22; padding: 2px 6px; border-radius: 4px; }}
    .badge {{ font-size: 0.75rem; }}
  </style>
</head>
<body>
<div class="container-fluid p-4">
  <div class="mb-4">
    <h1>🔴 RAG Red Team Report</h1>
    <p class="text-muted">Run ID: <code>{run_id}</code> | Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</p>
    <p class="text-muted">Target: <code>{RAG_URL}</code></p>
  </div>

  <!-- Summary Stats -->
  <div class="row g-3 mb-4">
    <div class="col-md-3">
      <div class="stat-card">
        <div class="stat-number">{len(all_results)}</div>
        <div>Total Tests</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="stat-card">
        <div class="stat-number text-danger">{len(vulnerable)}</div>
        <div>Vulnerabilities Found</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="stat-card">
        <div class="stat-number text-success">{len(safe)}</div>
        <div>Controls Passed</div>
      </div>
    </div>
    <div class="col-md-3">
      <div class="stat-card">
        <div class="stat-number text-warning">{severity_counts.get('critical', 0) + severity_counts.get('high', 0)}</div>
        <div>Critical/High Risk</div>
      </div>
    </div>
  </div>

  <!-- OWASP Breakdown -->
  <div class="card mb-4">
    <div class="card-header"><h5>📊 OWASP LLM Top 10 Coverage</h5></div>
    <div class="card-body">
      <table class="table table-sm">
        <thead><tr><th>OWASP Mapping</th><th>Tests</th><th>Vulnerable</th><th>Exposure Rate</th></tr></thead>
        <tbody>{owasp_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Full Results -->
  <div class="card mb-4">
    <div class="card-header"><h5>🔍 All Attack Results</h5></div>
    <div class="card-body">
      <div class="mb-2">
        <input type="text" id="filterInput" class="form-control form-control-sm" placeholder="Filter attacks..." style="background:#0d1117;color:#e6edf3;border-color:#30363d;">
      </div>
      <div class="table-responsive">
        <table class="table table-sm table-hover" id="resultsTable">
          <thead><tr><th>Attack Name</th><th>Severity</th><th>OWASP</th><th>Result</th><th>Notes</th><th>Latency</th></tr></thead>
          <tbody id="tableBody">{rows}</tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Vulnerable Findings Detail -->
  <div class="card mb-4">
    <div class="card-header"><h5>🚨 Vulnerable Findings Detail</h5></div>
    <div class="card-body">
      {'<p class="text-success">No vulnerabilities found! 🎉</p>' if not vulnerable else ""}
      {"".join(f'''
      <div class="card mb-2" style="border-color:#f85149">
        <div class="card-header" style="background:#21262d">
          <strong class="text-danger">🔴 {r.attack_name}</strong>
          <span class="badge bg-danger ms-2">{r.severity.upper()}</span>
          <code class="ms-2">{r.owasp_mapping}</code>
        </div>
        <div class="card-body">
          <p><strong>Payload:</strong> <code>{r.payload[:300]}</code></p>
          <p><strong>Response snippet:</strong> {r.response[:400]}</p>
          <p><strong>Notes:</strong> {r.notes}</p>
        </div>
      </div>''' for r in vulnerable)}
    </div>
  </div>

</div>
<script>
document.getElementById('filterInput').addEventListener('input', function() {{
  const filter = this.value.toLowerCase();
  document.querySelectorAll('#tableBody tr').forEach(row => {{
    row.style.display = row.textContent.toLowerCase().includes(filter) ? '' : 'none';
  }});
}});
</script>
</body>
</html>"""

    out_path = REPORTS_DIR / f"red_team_report_{run_id}.html"
    out_path.write_text(html)
    console.print(f"\n[bold green]📊 HTML Report → {out_path}[/bold green]")
    return out_path


def main():
    parser = argparse.ArgumentParser(description="RAG Red Team Orchestrator")
    parser.add_argument("--suite", help="Run only this suite ID (e.g., injection)")
    parser.add_argument("--skip", nargs="+", help="Skip these suite IDs")
    parser.add_argument("--check-only", action="store_true", help="Only check RAG health")
    parser.add_argument("--no-report", action="store_true", help="Skip HTML report generation")
    args = parser.parse_args()

    console.print(Panel(
        "[bold red]🔴 RAG Red Team Suite[/bold red]\n"
        "Production-grade adversarial testing\n"
        f"Target: {RAG_URL}",
        border_style="red",
    ))

    # Health check
    if not check_rag_health():
        if not args.check_only:
            console.print("\n[yellow]⚠️  RAG service is offline. Some tests will fail with connection errors.[/yellow]")
            console.print("[yellow]   Start with: cd rag_system && uvicorn app.main:app --reload[/yellow]\n")
    
    if args.check_only:
        return

    # Select suites to run
    skip_ids = set(args.skip or [])
    suites_to_run = [
        s for s in ATTACK_SUITES
        if (not args.suite or s["id"] == args.suite) and s["id"] not in skip_ids
    ]

    if not suites_to_run:
        console.print("[red]No matching suites. Check --suite and --skip arguments.[/red]")
        return

    run_id = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{str(uuid.uuid4())[:8]}"
    all_results: list[AttackResult] = []
    start_time = time.perf_counter()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        for suite in suites_to_run:
            task = progress.add_task(f"[cyan]Running: {suite['name']}", total=None)
            results = run_suite(suite)
            all_results.extend(results)
            vuln_count = sum(1 for r in results if r.vulnerable)
            progress.update(
                task,
                description=f"[{'red' if vuln_count else 'green'}]✓ {suite['name']} ({vuln_count}/{len(results)} vulnerable)",
                completed=True,
            )

    total_time = time.perf_counter() - start_time

    # Save consolidated JSON
    json_path = save_results(all_results, f"full_suite_{run_id}")

    # Print summary
    console.print(f"\n[dim]Total runtime: {total_time:.1f}s[/dim]")
    print_summary_table(all_results)

    # Generate HTML report
    if not args.no_report:
        html_path = generate_html_report(all_results, run_id)
        console.print(f"\n[bold]Open report: [link file://{html_path}]{html_path}[/link][/bold]")


if __name__ == "__main__":
    main()
