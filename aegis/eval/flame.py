"""Performance flame graphs for the AEGIS pipeline.

cProfile-based profiling of the orchestrator's hot path. Outputs:

  - aegis/_profile.pstats   — raw cProfile output, viewable in
                               snakeviz / py-spy / Pycharm profiler
  - aegis/_flame.html        — minimal self-contained HTML viz
                               (no external deps; cumulative-time
                               flat list rendered as a stacked bar)

Production teams replace this with py-spy on a live container:
   pip install py-spy
   py-spy top --pid $(pgrep -f aegis.main)
   py-spy record -o flame.svg --pid <pid>

cProfile is stdlib so this works without any extra install. The HTML
viz is intentionally minimal — for a real flame graph use
snakeviz <profile.pstats> or upload to https://flamegraph.com.

Run:
  python -m aegis.eval.flame
  python -m aegis.eval.flame --duration 5 --workers 4
"""
from __future__ import annotations

import argparse
import cProfile
import html
import io
import pstats
import random
import sys
import tempfile
import time
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _build_orchestrator(audit_path: Path):
    from aegis.agents.api_abuse.agent import APIAbuseAgent
    from aegis.agents.auth.agent import AuthAgent
    from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
    from aegis.agents.edr.agent import EDRAgent
    from aegis.agents.orchestrator.agent import SOCOrchestrator
    from aegis.agents.perimeter.agent import PerimeterAgent
    from aegis.agents.shared.audit import AuditLog
    from aegis.agents.shared.llm_client import get_client
    from aegis.agents.transaction.agent import TransactionAgent

    primary = get_client(prefer="mock")
    return SOCOrchestrator(
        primary_llm=primary, voter_llm=get_client(prefer="mock"),
        perimeter=PerimeterAgent(llm=primary),
        auth=AuthAgent(llm=primary),
        edr=EDRAgent(llm=primary),
        api_abuse=APIAbuseAgent(llm=primary),
        transaction=TransactionAgent(llm=primary),
        honeytoken=HoneytokenMonitor(),
        audit=AuditLog(audit_path),
    )


def _make_workload(n: int) -> list[dict]:
    from aegis.eval.stress import _alert_pool
    pool = _alert_pool()
    rng = random.Random(17)
    out: list[dict] = []
    for i in range(n):
        a = dict(rng.choice(pool))
        a["id"] = f"PROFILE-{i}"
        out.append(a)
    return out


def _render_flame_html(stats_buf: io.StringIO, top_n: int = 60) -> str:
    """Render cProfile stats as a stacked-bar approximation of a
    flame graph. Real flame graphs need stack samples; this gives a
    cumulative-time flat view that's still useful for spotting hot
    paths.
    """
    text = stats_buf.getvalue()
    rows: list[tuple[str, float, int]] = []   # (function, cumtime, ncalls)
    in_data = False
    for line in text.splitlines():
        if "ncalls" in line and "cumtime" in line:
            in_data = True
            continue
        if not in_data:
            continue
        line = line.rstrip()
        if not line.strip():
            continue
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        try:
            ncalls_str = parts[0].split("/")[0]
            ncalls = int(ncalls_str)
            cumtime = float(parts[3])
            func = parts[5]
        except (ValueError, IndexError):
            continue
        rows.append((func, cumtime, ncalls))
    rows.sort(key=lambda r: r[1], reverse=True)
    rows = rows[:top_n]
    if not rows:
        return "<p>No profiling data captured.</p>"
    max_time = max(r[1] for r in rows) or 1.0

    bars_html: list[str] = []
    for func, cum, ncalls in rows:
        width_pct = (cum / max_time) * 100
        # Color hot paths warmer
        hue = 30 if cum / max_time > 0.5 else (60 if cum / max_time > 0.2 else 200)
        bars_html.append(
            f'<div class="bar" style="width:{width_pct:.1f}%; background:hsl({hue},70%,55%);">'
            f'<span class="label">{html.escape(func)}</span>'
            f'<span class="time">{cum*1000:.2f}ms · {ncalls} calls</span>'
            f'</div>'
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AEGIS — Flame Profile</title>
<style>
body {{ font-family: -apple-system, system-ui, sans-serif; margin: 24px;
        max-width: 1200px; color: #222; }}
h1 {{ margin: 0 0 4px 0; }}
.timestamp {{ color: #666; font-size: 13px; margin-bottom: 24px; }}
.bar {{ height: 22px; line-height: 22px; margin: 1px 0; padding: 0 8px;
        color: white; font-size: 12px; font-family: ui-monospace, Menlo, monospace;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
        border-radius: 2px; min-width: 200px; }}
.label {{ font-weight: 600; }}
.time {{ float: right; opacity: 0.9; }}
.note {{ background: #fff3cd; border: 1px solid #ffe69c;
         padding: 12px; border-radius: 6px; margin-bottom: 20px;
         font-size: 13px; }}
</style>
</head>
<body>
  <h1>AEGIS — Flame Profile (top {top_n} by cumulative time)</h1>
  <div class="timestamp">Generated {time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}</div>
  <div class="note">
    cProfile cumulative-time view. Bar width = cumulative time as fraction
    of the slowest call. Real flame graphs (with stack samples) need py-spy
    or Austin — for production deployment, profile the running pod via:
    <code>py-spy record -o flame.svg --pid &lt;pid&gt;</code> or
    <code>snakeviz aegis/_profile.pstats</code>.
  </div>
  {"".join(bars_html)}
</body>
</html>
"""


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--alerts", type=int, default=200,
                   help="Alerts to process under profile (default 200)")
    p.add_argument("--out-html", default="aegis/_flame.html")
    p.add_argument("--out-pstats", default="aegis/_profile.pstats")
    p.add_argument("--top", type=int, default=60,
                   help="Top N functions to render (default 60)")
    args = p.parse_args()

    print(f"[flame] profiling {args.alerts} alerts through orchestrator...")
    with tempfile.TemporaryDirectory() as td:
        audit_path = Path(td) / "audit.jsonl"
        orch = _build_orchestrator(audit_path)
        alerts = _make_workload(args.alerts)

        profiler = cProfile.Profile()
        t0 = time.perf_counter()
        profiler.enable()
        for a in alerts:
            orch.handle(a)
        profiler.disable()
        elapsed = time.perf_counter() - t0

    pstats_path = Path(args.out_pstats)
    pstats_path.parent.mkdir(parents=True, exist_ok=True)
    profiler.dump_stats(str(pstats_path))

    stats_buf = io.StringIO()
    stats = pstats.Stats(profiler, stream=stats_buf).strip_dirs()
    stats.sort_stats("cumulative").print_stats(args.top * 2)

    out_html = Path(args.out_html)
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(_render_flame_html(stats_buf, top_n=args.top), encoding="utf-8")

    print(f"\n[flame] alerts processed: {args.alerts}")
    print(f"[flame] elapsed:           {elapsed:.2f}s")
    print(f"[flame] throughput:        {args.alerts/elapsed:.0f}/s")
    print(f"[flame] pstats:            {pstats_path}")
    print(f"[flame] HTML view:         {out_html}")
    print(f"[flame] inspect with:      python -m pstats {pstats_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
