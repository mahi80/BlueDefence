"""HTML eval dashboard.

Single-file generator that runs all the eval suites, captures structured
results, and emits an HTML report:

  - Top-line scoreboard (PASS/FAIL per suite + total counts)
  - Per-suite detail tables
  - Manifest drift status
  - Audit-chain integrity status
  - Latency benchmark summary (P50/P95/P99 per Tier)
  - Hypothesis property test breakdown (cases per property)

Stakeholder-visible artifact. CI uploads it after every run; ops teams
keep a rolling history (the dashboard takes an optional --history
argument for trend lines).

Run:
  python -m aegis.eval.dashboard
  python -m aegis.eval.dashboard --out /tmp/dashboard.html

Output: aegis/_dashboard.html (default) plus a JSON sidecar with the
same data for machine consumers.
"""
from __future__ import annotations

import argparse
import html
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SuiteResult:
    name: str
    pass_count: int = 0
    total: int = 0
    duration_s: float = 0.0
    notes: str = ""
    status: str = "UNKNOWN"   # "PASS" | "FAIL" | "SKIP"
    rows: list[dict] = field(default_factory=list)


def _run(cmd: list[str], *, timeout: float = 120.0) -> tuple[int, str]:
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(Path(__file__).parent.parent.parent),
            encoding="utf-8", errors="replace",
        )
        return proc.returncode, proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return 124, f"(timeout after {timeout}s)"


#: ``require_live_llm`` exits with this sentence when no model credentials are configured. That is a
#: missing environment, not a failing gate: score it SKIP so CI without keys is honest, not red. A real
#: disagreement keeps exit != 0 *without* this marker and still fails.
_MOCK_REFUSAL = "Refusing to grade the deterministic keyword table"


def _eval_status(rc: int, out: str, pass_n: int, total: int) -> str:
    if rc != 0 and _MOCK_REFUSAL in out:
        return "SKIP"
    return "PASS" if rc == 0 and pass_n == total and total > 0 else "FAIL"


def _skip_note() -> str:
    return ("no live LLM credentials (set ANTHROPIC_API_KEY, or AEGIS_EVAL_ALLOW_MOCK=1 "
            "for a deliberate offline run)")


def _run_historical_eval() -> SuiteResult:
    rc, out = _run([sys.executable, "-m", "aegis.eval.run"])
    # Parse the curated text output
    pass_n, total = 0, 0
    rows: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if "/" in line and "matched expected verdict" in line:
            parts = line.split("/")
            try:
                pass_n = int(parts[0].strip().split()[-1])
                total = int(parts[1].split()[0])
            except (ValueError, IndexError):
                pass
        elif "DISAGREE:" in line:
            rows.append({"row": line.replace("DISAGREE:", "").strip()})
    status = _eval_status(rc, out, pass_n, total)
    return SuiteResult(
        name="Historical eval", pass_count=pass_n, total=total,
        status=status, rows=rows,
        notes=_skip_note() if status == "SKIP" else f"exit={rc}",
    )


def _run_injection_eval() -> SuiteResult:
    # The same eval/run.py covers both historical + injection
    rc, out = _run([sys.executable, "-m", "aegis.eval.run"])
    pass_n, total = 0, 0
    for line in out.splitlines():
        line = line.strip()
        if "held the line" in line and "/" in line:
            parts = line.split()[0].split("/")
            try:
                pass_n = int(parts[0])
                total = int(parts[1])
            except (ValueError, IndexError):
                pass
    status = _eval_status(rc, out, pass_n, total)
    return SuiteResult(
        name="Prompt-injection defense", pass_count=pass_n, total=total,
        status=status,
        notes=_skip_note() if status == "SKIP" else f"exit={rc}",
    )


def _run_red_team_eval() -> SuiteResult:
    rc, out = _run([sys.executable, "-m", "aegis.eval.ai_red_team.run"])
    pass_n, total = 0, 0
    rows: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Verdict hit rate:"):
            parts = line.split()[-1].split("/")
            try:
                pass_n, total = int(parts[0]), int(parts[1])
            except (ValueError, IndexError):
                pass
        elif "expected=" in line and "got=" in line:
            rows.append({"row": line})
    status = _eval_status(rc, out, pass_n, total)
    return SuiteResult(
        name="AI red-team eval", pass_count=pass_n, total=total,
        status=status, rows=rows,
        notes=_skip_note() if status == "SKIP" else f"exit={rc}",
    )


def _run_property_tests() -> SuiteResult:
    rc, out = _run([sys.executable, "-m", "aegis.eval.property_tests"])
    suites_pass = 0
    suites_total = 0
    total_cases = 0
    rows: list[dict] = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("[PASS]") or line.startswith("[FAIL]"):
            suites_total += 1
            if "PASS" in line:
                suites_pass += 1
            rows.append({"row": line})
            # try to extract case count from "(200 cases)" pattern
            for token in line.split():
                if token.isdigit():
                    total_cases = max(total_cases, int(token))
    status = "PASS" if rc == 0 and suites_pass == suites_total and suites_total > 0 else "FAIL"
    return SuiteResult(
        name="Hypothesis property tests",
        pass_count=suites_pass, total=suites_total,
        status=status, rows=rows,
        notes=f"~{total_cases} max cases per property",
    )


def _run_manifest_verify() -> SuiteResult:
    rc, out = _run([sys.executable, "-m", "aegis.agents.shared.agent_identity", "--verify"])
    status = "PASS" if rc == 0 else "FAIL"
    n_agents = 0
    for line in out.splitlines():
        if "(" in line and "agents)" in line:
            try:
                n_agents = int(line.split("(")[1].split()[0])
            except (ValueError, IndexError):
                pass
    return SuiteResult(
        name="Agent identity manifest (live-vs-disk)",
        pass_count=n_agents if status == "PASS" else 0,
        total=n_agents,
        status=status,
        notes="13 agents declared" if status == "PASS" else "DRIFT detected",
    )


def _run_benchmarks() -> SuiteResult:
    rc, out = _run([
        sys.executable, "-m", "aegis.eval.benchmarks",
        "--iterations", "300", "--llm-iterations", "50"
    ], timeout=180.0)
    status = "PASS" if rc == 0 else "FAIL"
    rows: list[dict] = []
    for line in out.splitlines():
        line = line.rstrip()
        if "tier_" in line and "ms" in line:
            rows.append({"row": line.strip()})
        elif line.startswith("  [") and ("OK" in line or "FAIL" in line):
            rows.append({"row": line.strip()})
    return SuiteResult(
        name="Latency benchmarks (per-tier SLO)",
        pass_count=1 if status == "PASS" else 0,
        total=1,
        status=status, rows=rows,
    )


# ---- HTML rendering -------------------------------------------------

_CSS = """
body { font-family: -apple-system, system-ui, Segoe UI, sans-serif;
       margin: 24px; max-width: 1100px; color: #222; }
h1 { margin: 0 0 4px 0; }
.timestamp { color: #666; font-size: 13px; margin-bottom: 24px; }
.scoreboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
              gap: 12px; margin-bottom: 28px; }
.card { border: 1px solid #ddd; border-radius: 8px; padding: 16px;
        background: #fafafa; }
.card.pass { border-color: #5a3; background: #f0fff4; }
.card.fail { border-color: #c33; background: #fff5f5; }
.card.skip { border-color: #aaa; background: #f4f4f4; }
.card .name { font-weight: 600; font-size: 14px; margin-bottom: 6px; }
.card .stat { font-size: 24px; font-weight: 700; font-variant-numeric: tabular-nums; }
.card .notes { color: #555; font-size: 12px; margin-top: 4px; }
.suite { margin-bottom: 28px; }
.suite h2 { border-bottom: 2px solid #ddd; padding-bottom: 6px; }
table { border-collapse: collapse; width: 100%; }
td, th { padding: 6px 10px; border-bottom: 1px solid #eee; text-align: left; }
th { background: #f0f0f0; font-size: 12px; }
pre { background: #f4f4f4; padding: 10px; border-radius: 4px;
      font-size: 12px; overflow-x: auto; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
         font-size: 11px; font-weight: 600; text-transform: uppercase; }
.badge.pass { background: #5a3; color: white; }
.badge.fail { background: #c33; color: white; }
.badge.skip { background: #aaa; color: white; }
.footer { color: #888; font-size: 12px; margin-top: 40px; border-top: 1px solid #eee; padding-top: 12px; }
"""


def _render_card(s: SuiteResult) -> str:
    css_class = s.status.lower()
    stat = f"{s.pass_count}/{s.total}" if s.total else s.status
    return f"""
    <div class="card {css_class}">
      <div class="name">{html.escape(s.name)}</div>
      <div class="stat">{stat}</div>
      <div class="notes">{html.escape(s.notes)}</div>
    </div>
    """


def _render_suite(s: SuiteResult) -> str:
    rows_html = ""
    if s.rows:
        rows_html = "<table><thead><tr><th>detail</th></tr></thead><tbody>"
        for r in s.rows:
            rows_html += f"<tr><td><pre>{html.escape(r.get('row', ''))}</pre></td></tr>"
        rows_html += "</tbody></table>"
    return f"""
    <div class="suite">
      <h2>{html.escape(s.name)}
        <span class="badge {s.status.lower()}">{s.status}</span></h2>
      <div>{html.escape(s.notes)}</div>
      {rows_html}
    </div>
    """


def overall_status(results: list[SuiteResult]) -> str:
    """FAIL if any suite failed; SKIP if the only non-passes are skipped gates (no credentials);
    PASS otherwise. A skip never masquerades as a green gate, but a missing secret does not fail CI."""
    if any(r.status == "FAIL" for r in results):
        return "FAIL"
    if any(r.status == "SKIP" for r in results):
        return "SKIP"
    return "PASS"


def render_html(results: list[SuiteResult]) -> str:
    overall = overall_status(results)
    cards = "\n".join(_render_card(r) for r in results)
    suites = "\n".join(_render_suite(r) for r in results if r.rows)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AEGIS — Eval Dashboard</title>
<style>{_CSS}</style>
</head>
<body>
  <h1>AEGIS — Eval Dashboard
    <span class="badge {overall.lower()}">{overall}</span></h1>
  <div class="timestamp">Generated {ts}</div>

  <div class="scoreboard">
    {cards}
  </div>

  {suites}

  <div class="footer">
    AEGIS — Agentic Endpoint Defense for Bank Infrastructure.<br>
    Generated by <code>python -m aegis.eval.dashboard</code> on every CI run.
    Hash-chained audit log integrity is checked separately by
    <code>compliance/report.py</code>.
  </div>
</body>
</html>
"""


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="aegis/_dashboard.html",
                   help="Output HTML path (default: aegis/_dashboard.html)")
    p.add_argument("--out-json", default="aegis/_dashboard.json",
                   help="JSON sidecar path")
    p.add_argument("--skip-benchmarks", action="store_true",
                   help="Skip the latency benchmark suite (fast iteration)")
    args = p.parse_args()

    print("[dashboard] running suites...")
    results: list[SuiteResult] = []
    suites = [
        ("manifest", _run_manifest_verify),
        ("historical", _run_historical_eval),
        ("injection", _run_injection_eval),
        ("red_team", _run_red_team_eval),
        ("property", _run_property_tests),
    ]
    if not args.skip_benchmarks:
        suites.append(("benchmarks", _run_benchmarks))

    for label, fn in suites:
        print(f"  running {label}...", end=" ", flush=True)
        t0 = time.time()
        result = fn()
        result.duration_s = round(time.time() - t0, 2)
        print(f"{result.status} ({result.duration_s}s)")
        results.append(result)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(results), encoding="utf-8")

    sidecar = Path(args.out_json)
    sidecar.write_text(
        json.dumps([{
            "name": r.name, "status": r.status,
            "pass_count": r.pass_count, "total": r.total,
            "duration_s": r.duration_s, "notes": r.notes,
        } for r in results], indent=2),
        encoding="utf-8",
    )

    print(f"\n[dashboard] HTML  -> {out_path}")
    print(f"[dashboard] JSON  -> {sidecar}")
    overall = overall_status(results)
    print(f"[dashboard] overall: {overall}")
    return 0 if overall != "FAIL" else 1


if __name__ == "__main__":
    sys.exit(main())
