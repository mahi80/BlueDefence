"""CLI — ``python -m aegis.dataset export|synth|build-public|verify|stats``.

Examples::

    # offline: eval corpora (held-out test) + local audit log + advisory text
    python -m aegis.dataset export --out datasets/aegis-triage-v1 --local-audit aegis/_audit_log.jsonl

    # with the dashboard (ACP_DASHBOARD_URL / ACP_API_KEY): + persisted chains with analyst decisions
    #                                                        + meta-agent proposals
    python -m aegis.dataset export --out datasets/aegis-triage-v1 --dashboard --since 2026-10-01T00:00:00Z

    python -m aegis.dataset verify datasets/aegis-triage-v1
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import UTC
from pathlib import Path

from .export import BuildOptions, DatasetBuilder, verify_dataset
from .scrub import scrubber_from_env
from .sources import (
    attack_profile_records,
    dashboard_records,
    env_dashboard,
    eval_records,
    local_audit_records,
    proposal_records,
)


def _bool_env(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


_IP_KINDS = ("ipv4", "ipv6")


def _privacy_gated(recs: list, *, scrub_ips: bool, where: str) -> list:
    """Records leaving for training (often a vendor GPU) pass the same privacy gate as Community bundles. It ran on
    the contribution path only: e-mails / phones as dict keys and DB users in connection URLs left with
    ``dataset export`` (review round 4 D4-12). IPs are kept unless ``--scrub-ips`` (inside the bank by design)."""
    from . import privacy_gate
    from .contrib import redact_for_contrib
    out, dropped, kinds = [], 0, {}
    for r in recs:
        # e-mail domains and hostnames the scrubber keeps on purpose are tokenised for the check only; what is still
        # found after that is a real leak (a phone in a key, an Aadhaar, a credential)
        probe = redact_for_contrib(r.to_dict() if hasattr(r, "to_dict") else r, "privacy-probe")
        f = [x for x in privacy_gate.findings(probe) if scrub_ips or x.get("kind") not in _IP_KINDS]
        if f:
            dropped += 1
            for x in f:
                kinds[x["kind"]] = kinds.get(x["kind"], 0) + 1
            continue
        out.append(r)
    if dropped:
        print(f"  privacy gate: {dropped} {where} record(s) held back ({kinds}) — fix the capture or the scrubber")
    return out


def cmd_export(args: argparse.Namespace) -> int:
    scrubber = scrubber_from_env(scrub_ips=args.scrub_ips or _bool_env("AEGIS_DATASET_SCRUB_IPS", False))
    sources: list[str] = []
    builder = DatasetBuilder(args.out, BuildOptions(
        name=args.name or Path(args.out).name, val_pct=args.val_pct, include_weak=args.include_weak,
        include_disputed=args.include_disputed, eval_split=args.eval_split, scrub_ips=scrubber.scrub_ips,
        salted=scrubber.salted, notes=args.notes or "", dpo=args.dpo,
    ))

    if not args.no_eval:
        from aegis.eval.run import _build_orchestrator
        with tempfile.TemporaryDirectory() as td:
            orch = _build_orchestrator(Path(td) / "audit.jsonl")
            recs = eval_records(orch, scrubber, split=args.eval_split)
        builder.add(recs)
        sources.append(f"eval ({len(recs)})")
        print(f"  eval corpora: {len(recs)} records → split={args.eval_split}")

    for p in args.local_audit or []:
        recs = _privacy_gated(local_audit_records(p, scrubber), scrub_ips=scrubber.scrub_ips, where="local audit")
        builder.add(recs)
        sources.append(f"local_audit:{p} ({len(recs)})")
        print(f"  local audit {p}: {len(recs)} records")

    url, key = env_dashboard()
    if args.dashboard:
        if not url:
            print("  --dashboard needs ACP_DASHBOARD_URL (and ACP_API_KEY)", file=sys.stderr)
            return 2
        recs = _privacy_gated(dashboard_records(url, key, scrubber, since=args.since), scrub_ips=scrubber.scrub_ips,
                              where="dashboard")
        builder.add(recs)
        sources.append(f"dashboard_chains ({len(recs)})")
        print(f"  dashboard chains: {len(recs)} records "
              f"({sum(1 for r in recs if r.label['source'].startswith('human'))} with analyst decisions)")
        precs = proposal_records(url, key, scrubber)
        builder.add(precs)
        sources.append(f"dashboard_proposals ({len(precs)})")
        print(f"  dashboard proposals: {len(precs)} records")

    if not args.no_profiles:
        profs = attack_profile_records(dashboard_url=url if args.dashboard else None, api_key=key)
        builder.add(profs)
        sources.append(f"attack_profiles ({len(profs)})")
        print(f"  attack profiles: {len(profs)} text records")

    builder.opt.sources = sources
    manifest = builder.build()
    c = manifest["counts"]
    print(f"\n  wrote {args.out}: {c['records']} records, {c['sft_triage_rows']} SFT triage rows "
          f"{c['sft_by_split']}, {c['sft_proposal_rows']} proposal rows, {c['attack_profiles']} profiles")
    print(f"  label sources: {c['by_label_source']}")
    print(f"  integrity: {manifest['integrity']}")
    ok, problems = verify_dataset(args.out)
    print(f"  verify: {'OK' if ok else 'FAILED'}" + ("" if ok else " — " + "; ".join(problems)))
    return 0 if ok else 1


def _validate_sft_rows(rows: list[dict]) -> list[str]:
    """Same shape checks as verify_dataset's SFT pass, plus the response-policy invariants."""
    from .synth import ALWAYS_HITL
    problems: list[str] = []
    seen: set = set()
    for row in rows:
        rid = row.get("id")
        msgs = row.get("messages") or []
        if len(msgs) != 3 or [m.get("role") for m in msgs] != ["system", "user", "assistant"]:
            problems.append(f"{rid}: not system/user/assistant"); continue
        try:
            json.loads(msgs[1]["content"]); target = json.loads(msgs[2]["content"])
        except Exception:  # noqa: BLE001
            problems.append(f"{rid}: not JSON-in/JSON-out"); continue
        if target.get("verdict") not in ("benign", "suspicious", "malicious", "uncertain"):
            problems.append(f"{rid}: bad verdict {target.get('verdict')!r}")
        for a in target.get("recommended_actions", []):
            if a["action_type"] in ALWAYS_HITL and not a.get("requires_hitl"):
                problems.append(f"{rid}: {a['action_type']} must be requires_hitl")
        if target.get("injection_detected") and any(a["action_type"] == "allow" for a in target.get("recommended_actions", [])):
            problems.append(f"{rid}: injection row recommends allow")
        if target.get("injection_detected") and target.get("verdict") == "benign":
            problems.append(f"{rid}: injection row labelled benign")
        if rid in seen:
            problems.append(f"{rid}: duplicate id")
        seen.add(rid)
    return problems


def cmd_synth(args: argparse.Namespace) -> int:
    import hashlib
    from datetime import datetime

    from .cve_calibration import calibration_from_env
    from .synth import LABEL_SOURCE, ORIGIN, SCHEMA_VERSION, generate

    cal = calibration_from_env(enabled=getattr(args, "cve_calibrate", False))
    rows = generate(args.n, seed=args.seed, injection_pct=args.injection_pct, val_pct=args.val_pct,
                    cve_pct=args.cve_pct, cve_calibration=cal)
    problems = _validate_sft_rows(rows)
    out = Path(args.out); (out / "sft").mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    # newline="\n": Windows text-mode translation to CRLF would not match the digest computed over LF
    with (out / "sft" / "triage.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            line = json.dumps(row, ensure_ascii=False, sort_keys=True)
            h.update(line.encode()); fh.write(line + "\n")
    # counts
    def tgt(row): return json.loads(row["messages"][2]["content"])
    by_split: dict = {}; by_verdict: dict = {}; inj = cve = sc = 0
    for row in rows:
        by_split[row["split"]] = by_split.get(row["split"], 0) + 1
        t = tgt(row); by_verdict[t["verdict"]] = by_verdict.get(t["verdict"], 0) + 1
        inj += 1 if t.get("injection_detected") else 0
        a = json.loads(row["messages"][1]["content"])
        cve += 1 if "cve" in a else 0
        sc += 1 if a.get("source") in ("SCA scanner", "Registry proxy", "CI/CD", "Model Registry") else 0
    manifest = {
        "name": args.name or out.name, "schema": SCHEMA_VERSION, "origin": ORIGIN, "label_source": LABEL_SOURCE,
        "generated_at": datetime.now(UTC).isoformat(), "seed": args.seed,
        "WARNING": "SYNTHETIC DATA — pipeline scaffold only. NOT human-labelled, NOT a bank's alert mix. "
                   "Do NOT use for the 3.3 accuracy gate (that runs on the held-out eval set). "
                   "aegis.finetune refuses these rows unless --allow-synthetic is set.",
        "counts": {"sft_triage_rows": len(rows), "sft_by_split": by_split, "by_verdict": by_verdict,
                   "injection_rows": inj, "cve_overlay_rows": cve, "supply_chain_rows": sc,
                   "validation_problems": len(problems)},
        "sft_triage_sha256": h.hexdigest(),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (out / "README.md").write_text(
        f"# {manifest['name']} (SYNTHETIC)\n\n{manifest['WARNING']}\n\n"
        f"- rows: {len(rows)}  splits: {by_split}  verdicts: {by_verdict}  injection: {inj}  cve-overlay: {cve}  supply-chain: {sc}\n"
        f"- seed: {args.seed}  schema: {SCHEMA_VERSION}\n\n"
        "Shape is identical to a real `sft/triage.jsonl` (system/user/assistant; JSON alert in, "
        "JSON triage out). Use it to prove the fine-tune + eval-gate pipeline end to end, then "
        "retrain on real rows once `v60.28` is live and analysts have labelled a few hundred.\n", encoding="utf-8")
    print(f"  wrote {out}/sft/triage.jsonl: {len(rows)} rows, splits {by_split}, verdicts {by_verdict}, "
          f"injection {inj}, cve-overlay {cve}, supply-chain {sc}")
    print(f"  sha256 {manifest['sft_triage_sha256'][:16]}…")
    if problems:
        print(f"  validate: FAILED — {len(problems)} problem(s):", file=sys.stderr)
        for p in problems[:10]:
            print(f"    - {p}", file=sys.stderr)
        return 1
    print("  validate: OK (shape + response-policy invariants)")
    return 0


def cmd_build_judge(args: argparse.Namespace) -> int:
    """Reviewer (judge / voter) training set from an existing triage dataset — see ``aegis.dataset.judge``."""
    import collections
    import hashlib
    from datetime import datetime

    from .judge import ORIGIN, build_judge_rows
    src = Path(args.src).expanduser()
    f = src / "sft" / "triage.jsonl" if src.is_dir() else src
    if not f.exists():
        print(f"no sft/triage.jsonl at {f}", file=sys.stderr)
        return 2

    def rows():
        with f.open(encoding="utf-8") as fh:
            for ln in fh:
                if ln.strip():
                    yield json.loads(ln)
    out_rows = build_judge_rows(rows(), seed=args.seed, context_pct=args.context_pct, max_rows=args.max_rows)
    if not out_rows:
        print("no usable triage rows to build from", file=sys.stderr)
        return 1
    out = Path(args.out); (out / "sft").mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    with (out / "sft" / "triage.jsonl").open("w", encoding="utf-8", newline="\n") as fh:  # the file name train.py loads
        for r in out_rows:
            line = json.dumps(r, ensure_ascii=False, sort_keys=True)
            h.update(line.encode()); fh.write(line + "\n")
    by_variant = collections.Counter(r["variant"] for r in out_rows)
    by_split = collections.Counter(r["split"] for r in out_rows)
    concur = sum(1 for r in out_rows if json.loads(r["messages"][2]["content"])["concur"])
    manifest = {"name": args.name or out.name, "format": "aegis-judge", "origin": ORIGIN, "source": str(f),
                "generated_at": datetime.now(UTC).isoformat(), "seed": args.seed,
                "counts": {"rows": len(out_rows), "concur": concur, "dissent": len(out_rows) - concur,
                           "by_variant": dict(by_variant), "by_split": dict(by_split)},
                "sha256": h.hexdigest(),
                "NOTE": "Reviewer rows: the runtime voter prompt and {concur, reason} answers. Train a judge/voter "
                        "adapter on this, NOT on the triage set. Label sources are inherited from the source rows."}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {out}/sft/triage.jsonl: {len(out_rows)} reviewer rows ({concur} concur / {len(out_rows) - concur} "
          f"dissent), splits {dict(by_split)}, variants {dict(by_variant)}")
    return 0


def cmd_build_public(args: argparse.Namespace) -> int:
    """Public corpora (Sigma + Security-Datasets) + synthetic + injection → one sft/triage.jsonl."""
    import hashlib
    from datetime import datetime

    from .cve_calibration import calibration_from_env
    from .importers import build_mixed, fetch_corpora
    from .synth import SCHEMA_VERSION

    if args.sigma and args.mordor:
        sigma, mordor = Path(args.sigma), Path(args.mordor)
    else:
        print(f"  fetching corpora into {args.cache} (git, GitHub) …", flush=True)
        sigma, mordor = fetch_corpora(args.cache)
    shares = {}
    for kv in (args.shares or "").split(","):
        if "=" in kv:
            k, v = kv.split("=", 1); shares[k.strip()] = int(v)
    cal = calibration_from_env(enabled=getattr(args, "cve_calibrate", False))
    rows, stats = build_mixed(sigma_root=sigma, mordor_root=mordor, total=args.n, seed=args.seed, shares=shares or None,
                              val_pct=args.val_pct, xsoar_pct=args.xsoar_pct, cve_calibration=cal)
    problems = _validate_sft_rows(rows)
    out = Path(args.out); (out / "sft").mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    with (out / "sft" / "triage.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            line = json.dumps(row, ensure_ascii=False, sort_keys=True)
            h.update(line.encode()); fh.write(line + "\n")
    manifest = {
        "name": args.name or out.name, "schema": SCHEMA_VERSION, "origin": "mixed/v1",
        "label_sources": sorted(stats["by_source"]), "generated_at": datetime.now(UTC).isoformat(), "seed": args.seed,
        "WARNING": "PUBLIC + SYNTHETIC DATA — realistic shapes (SigmaHQ rules in product-native envelopes, OTRF "
                   "Security-Datasets scenarios) but NOT this bank's alert mix and NOT analyst-labelled. "
                   "Use to pre-train the triage first-pass; the 3.3 gate still runs on the held-out eval set and "
                   "promotion still needs the analyst-labelled export. aegis.finetune accepts these rows with --allow-synthetic.",
        "counts": {"sft_triage_rows": stats["rows"], "sft_by_split": stats["by_split"], "by_verdict": stats["by_verdict"],
                   "by_source": stats["by_source"], "by_product": stats["by_product"], "sigma_rules": stats["rules"],
                   "mordor_scenarios": stats["scenarios"], "deduped": stats["deduped"], "validation_problems": len(problems)},
        "sft_triage_sha256": h.hexdigest(),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (out / "README.md").write_text(
        f"# {manifest['name']} (PUBLIC + SYNTHETIC, mixed/v1)\n\n{manifest['WARNING']}\n\n"
        f"- rows: {stats['rows']}  splits: {stats['by_split']}\n- verdicts: {stats['by_verdict']}\n"
        f"- sources: {stats['by_source']}\n- products: {stats['by_product']}\n- seed: {args.seed}  schema: {SCHEMA_VERSION}\n",
        encoding="utf-8")
    print(f"wrote {stats['rows']} rows → {out / 'sft' / 'triage.jsonl'}")
    print(f"  sources:  {stats['by_source']}")
    print(f"  verdicts: {stats['by_verdict']}")
    print(f"  products: {dict(list(stats['by_product'].items())[:8])} …")
    if problems:
        print(f"  ⚠ {len(problems)} validation problems (first: {problems[0]})")
    print(f"\nnext: PRESET=qwen3-8b DATA={out} OUT=~/aegis-runs/triage-qwen3-8b-public bash aegis/finetune/run_local.sh")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    ok, problems = verify_dataset(args.dir)
    print(f"{args.dir}: {'OK' if ok else 'FAILED'}")
    for p in problems:
        print(f"  - {p}")
    return 0 if ok else 1


def cmd_contrib(args: argparse.Namespace) -> int:
    """Build (and push or write) this installation's community contribution bundle."""
    from aegis import license as licensing
    from .contrib import contribute
    st = licensing.check()
    token = ""
    if args.push:
        # the same lookup the licence check uses (AEGIS_LICENSE, then /var/lib/aegis, then /etc/aegis — #126)
        token, _why = licensing._read_token(os.environ)
    res = contribute(audit_path=args.audit, installation_id=st.installation_id, license_token=token,
                     license_id=(st.license.license_id if st.license else ""), hitl_dir=args.hitl_dir,
                     cursor_path=args.cursor, server=args.push, out=args.out, min_records=args.min_records)
    if res.get("reason") == "privacy gate":
        print(f"REFUSED by the privacy gate — nothing left this host. {len(res['findings'])} finding(s):")
        for f in res["findings"][:10]:
            print(f"  {f['kind']:8s} at {f['path']}  ({f['sample']})")
        return 2
    if not res.get("records"):
        print("nothing new since the last contribution")
        return 0
    c = res.get("counts", {})
    print(f"{res['records']} record(s): {c.get('human_decided', 0)} with analyst decisions, {c.get('human_corrected', 0)} corrected; "
          f"verdicts {c.get('by_verdict')}")
    if res.get("file"):
        print(f"bundle → {res['file']}  (air-gapped: e-mail this file to BlueDefence)")
    if res.get("sent"):
        print(f"pushed to {args.push}: {res['server']}")
    return 0


def cmd_import_contrib(args: argparse.Namespace) -> int:
    """Fold a folder of community bundles into a versioned training dataset."""
    from .contrib import records_from_bundles
    recs, report = records_from_bundles(args.src, gate=not args.no_gate)
    print(f"{report['bundles']} bundle(s), {len(recs)} record(s) from {len(report['by_installation'])} installation(s)")
    for inst, n in sorted(report["by_installation"].items(), key=lambda kv: -kv[1])[:20]:
        print(f"  {inst:28s} {n:>7,d}")
    if report["skipped_gate"]:
        print(f"  ⚠ {len(report['skipped_gate'])} bundle(s) skipped by the privacy gate (first: {report['skipped_gate'][0]['file']})")
    if not recs:
        return 1
    b = DatasetBuilder(args.out, BuildOptions(name=args.name or Path(args.out).name, val_pct=args.val_pct, include_weak=args.include_weak,
                                               include_disputed=False, dpo=True, scrub_ips=True, salted=True,
                                               notes=f"community contributions from {report['bundles']} bundle(s); {args.notes}".strip("; ")))
    b.add(recs)
    m = b.build()
    print(f"dataset → {args.out}: {json.dumps(m['counts'], sort_keys=True)}")
    print(f"next: python -m aegis.finetune.train --data {args.out} --vram <GB>   |   python -m aegis.finetune.dpo --data {args.out} --vram <GB>")
    return 0


def cmd_stats(args: argparse.Namespace) -> int:
    m = json.loads((Path(args.dir) / "manifest.json").read_text(encoding="utf-8"))
    print(json.dumps(m["counts"], indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.dataset", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    ex = sub.add_parser("export", help="build a dataset directory")
    ex.add_argument("--out", required=True, help="output directory (created)")
    ex.add_argument("--name", default="", help="dataset name (default: directory name)")
    ex.add_argument("--no-eval", action="store_true", help="skip the eval corpora")
    ex.add_argument("--eval-split", default="test", choices=("test", "val", "train"),
                    help="where eval records go (default test = held out)")
    ex.add_argument("--local-audit", action="append", help="AuditLog JSONL path (repeatable)")
    ex.add_argument("--dashboard", action="store_true", help="pull chains + decisions + proposals from ACP_DASHBOARD_URL")
    ex.add_argument("--since", default=None, help="ISO timestamp; only dashboard chains created after it")
    ex.add_argument("--no-profiles", action="store_true", help="skip advisory / scenario / technique text")
    ex.add_argument("--val-pct", type=int, default=10, help="validation share of non-eval records (default 10)")
    ex.add_argument("--include-weak", action="store_true", help="put model-labelled (unchecked) rows in sft/triage.jsonl")
    ex.add_argument("--include-disputed", action="store_true", help="put human_disputed rows in sft/triage.jsonl")
    ex.add_argument("--dpo", action="store_true",
                    help="also emit dpo/preferences.jsonl (preference pairs from analyst-overruled decisions)")
    ex.add_argument("--scrub-ips", action="store_true", help="also pseudonymise public IPv4 addresses")
    ex.add_argument("--notes", default="", help="free text recorded in the manifest")
    ex.set_defaults(fn=cmd_export)

    sy = sub.add_parser("synth", help="generate a SYNTHETIC sft/triage.jsonl to prove the fine-tune pipeline")
    sy.add_argument("--out", required=True, help="output directory (created)")
    sy.add_argument("--name", default="", help="dataset name (default: directory name)")
    sy.add_argument("--n", type=int, default=600, help="number of rows (default 600)")
    sy.add_argument("--seed", type=int, default=7, help="RNG seed for reproducibility")
    sy.add_argument("--injection-pct", type=int, default=15, help="share of injection rows (default 15)")
    sy.add_argument("--val-pct", type=int, default=15, help="validation share by fingerprint (default 15)")
    sy.add_argument("--cve-pct", type=int, default=35, help="share of exploit-relevant rows that carry CVE-shaped signals (default 35)")
    sy.add_argument("--cve-calibrate", action="store_true", help="calibrate the CVE overlay to real KEV/NVD/EPSS distributions from the threat-intel cache (abstract stats only, no real ids)")
    sy.set_defaults(fn=cmd_synth)

    bp = sub.add_parser("build-public", help="realistic training set: SigmaHQ rules + OTRF Security-Datasets + synthetic + injection")
    bp.add_argument("--out", required=True, help="output directory (created)")
    bp.add_argument("--name", default="", help="dataset name (default: directory name)")
    bp.add_argument("--n", type=int, default=50000, help="target rows (default 50000; 1M works but see README)")
    bp.add_argument("--seed", type=int, default=7)
    bp.add_argument("--cache", default=str(Path.home() / ".cache" / "aegis-corpora"), help="where the corpora are cloned")
    bp.add_argument("--sigma", default="", help="existing SigmaHQ checkout (skips clone)")
    bp.add_argument("--mordor", default="", help="existing Security-Datasets checkout (skips clone)")
    bp.add_argument("--shares", default="", help="override shares, e.g. sigma=60,mordor=5,synth=20,inject=15")
    bp.add_argument("--val-pct", type=int, default=15)
    bp.add_argument("--xsoar-pct", type=int, default=20, help="share of rows wrapped in a Cortex XSOAR incident envelope")
    bp.add_argument("--cve-calibrate", action="store_true", help="calibrate the synthetic CVE overlay to real KEV/NVD/EPSS distributions from the threat-intel cache (abstract stats only, no real ids)")
    bp.set_defaults(fn=cmd_build_public)

    bj = sub.add_parser("build-judge", help="reviewer (judge/voter) training set from a triage dataset: concur/dissent on finished verdicts")
    bj.add_argument("src", help="a triage dataset directory (with sft/triage.jsonl), e.g. ~/aegis-runs/data-v6-public-20261024")
    bj.add_argument("--out", required=True, help="output directory (created)")
    bj.add_argument("--name", default="")
    bj.add_argument("--seed", type=int, default=7)
    bj.add_argument("--context-pct", type=float, default=15.0, help="share of rows that also show the alert (the auto-close vote)")
    bj.add_argument("--max-rows", type=int, default=0, help="stop after this many reviewer rows (0 = all)")
    bj.set_defaults(fn=cmd_build_judge)

    ve = sub.add_parser("verify", help="re-hash a dataset directory and check the split invariant")
    ve.add_argument("dir")
    ve.set_defaults(fn=cmd_verify)

    co = sub.add_parser("contrib", help="community licence: build this installation's scrubbed contribution bundle and push or write it")
    co.add_argument("--audit", default=os.environ.get("AEGIS_AUDIT_PATH", "aegis/_audit_log.jsonl"))
    co.add_argument("--hitl-dir", default=os.environ.get("AEGIS_HITL_DIR", ""), help="file-transport HITL dir (cards + decisions)")
    co.add_argument("--cursor", default=os.environ.get("AEGIS_CONTRIB_CURSOR", ".aegis-contrib.cursor"))
    co.add_argument("--push", default=os.environ.get("AEGIS_LICENSE_SERVER", ""), help="licence service URL (POST /contrib); empty = do not push")
    co.add_argument("--out", default="", help="also/instead write bundle.json.gz here (air-gapped hosts)")
    co.add_argument("--min-records", type=int, default=1)
    co.set_defaults(fn=cmd_contrib)

    ic = sub.add_parser("import-contrib", help="BlueDefence side: fold downloaded community bundles into a training dataset (SFT + DPO views)")
    ic.add_argument("src", help="folder of *.json.gz bundles (e.g. aws s3 sync s3://<contrib-bucket>/contrib ./contrib)")
    ic.add_argument("--out", required=True)
    ic.add_argument("--name", default="")
    ic.add_argument("--val-pct", type=int, default=10)
    ic.add_argument("--include-weak", action="store_true", help="also train on model-only labels (no analyst decision)")
    ic.add_argument("--no-gate", action="store_true", help="skip the privacy gate (never for real data)")
    ic.add_argument("--notes", default="")
    ic.set_defaults(fn=cmd_import_contrib)

    st = sub.add_parser("stats", help="print the manifest counts")
    st.add_argument("dir")
    st.set_defaults(fn=cmd_stats)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
