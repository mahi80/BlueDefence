"""Egress benchmark: a simulated office network's TLS metadata vs. AEGIS, measured.

``python -m aegis.eval.egress_bench`` builds a deterministic world:
- 40 workstations and two servers;
- three hours of TLS metadata, in the shape a Zeek sensor logs it (``ssl`` / ``conn`` /
  ``x509`` JSON).

It feeds that through the real NDR consumer, egress detector, orchestrator and response
agent, then prints what was found, when, and how it was judged.

Everyone beacons: OS updates, EDR telemetry and chat presence call home from every host on a
timer. A trader's browser tab polls a niche quote site every 30 s. Uploads go to the corporate
file share, and the bank's registered AI system calls its Azure OpenAI tenant. Against that
background the threats run:

    implant_c2_beacon       60 s ±6 % to a rare name, TLS 1.2, self-signed, tool-default subject, days old
    tls13_beacon            300 s ±10 % to a rare name over TLS 1.3 (no certificate visible)
    slow_exfil              ~4 MB every few minutes, irregular, to a rare storage host
    known_bad_certificate   one connection to a server whose certificate is on the IOC list
    shadow_ai_upload        an unregistered desktop calling a public AI API, ~15 MB in an hour
    unapproved_ai_provider  a registered AI system calling a provider outside its approval

Reported, not gated (known gaps, shown so nobody assumes otherwise):

    jittery_beacon          120 s ±60 %: jitter above the threshold
    c2_on_popular_name      C2 fronted behind a name every host already uses: prevalence hides it
    long_connection_c2      one TLS connection held open, talking inside it: no new handshakes

The gate fails CI when:
- a gated threat is missed, judged below its expected verdict, or found late;
- any benign host gets a ``malicious`` verdict or an isolation / egress-block proposal;
- registered or approved AI use is reported as shadow AI.

The trader's polling tab is the honest false-positive case. It is reported as a
``suspicious`` beacon at 0.60 ("browser-shaped client: often a polling tab").

``--write-fixtures DIR`` writes a small slice of the same world (6 hosts, 30 minutes) as Zeek
and Suricata sample logs, with the matching IOC list and AI register. Every value is invented:
RFC 1918 / RFC 5737 addresses, ``.example`` names, made-up fingerprints and hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

T0 = datetime(2026, 10, 22, 6, 0, 0, tzinfo=UTC)

BROWSER_JA4 = "t13d1516h2_000000000001_000000000a01"
AGENT_SVC_JA4 = "t13d1611h2_00000000000b_000000000a0b"       # OS / EDR / chat agents
IMPLANT_JA4 = "t12d0807h1_00000000000c_000000000a0c"         # TLS 1.2 only, few extensions
IMPLANT2_JA4 = "t13d1009h1_00000000000d_000000000a0d"
PYTHON_JA4 = "t13d1312h2_e8f1e7e78f70_0aaa1111bbbb"
DEFAULT_SUBJECT = "CN=cdn-sync.update-check.example,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"


def cert_ids(name: str) -> tuple[str, str]:
    """Deterministic, invented certificate fingerprints (sha1, sha256) for a sample server."""
    raw = f"sample-cert:{name}".encode()
    return hashlib.sha1(raw).hexdigest(), hashlib.sha256(raw).hexdigest()


@dataclass
class Actor:
    name: str
    hosts: list[str]
    sni: str
    dst: str
    interval: float = 0.0               # periodic when > 0
    jitter: float = 0.0                 # uniform ± fraction of the interval
    mean_gap: float = 0.0               # irregular (exponential gaps) when > 0
    out_bytes: tuple[int, int] = (800, 1500)
    in_bytes: tuple[int, int] = (2000, 9000)
    ja4: str = AGENT_SVC_JA4
    tls12_cert: dict | None = None      # TLS 1.2: the certificate is visible to the sensor
    start: float = 0.0
    end: float | None = None
    once: bool = False
    threat: str = ""                    # scenario name (gated or reported)
    long_conn: bool = False             # one connection held for the whole run


@dataclass
class World:
    hosts: list[str]
    minutes: int
    actors: list[Actor]
    gated: dict[str, str]               # threat → minimum expected verdict
    deadline_min: dict[str, float]      # threat → found within (sim minutes)
    reported: tuple[str, ...]
    register_rows: list[dict]
    ioc_rows: list[dict]
    records: list[dict] = field(default_factory=list)


def build_world(preset: str = "bench", seed: int = 7) -> World:
    rng = random.Random(seed)
    if preset == "fixture":
        hosts, minutes = [f"10.20.0.{10 + i}" for i in range(6)], 30
    else:
        hosts, minutes = [f"10.20.0.{10 + i}" for i in range(40)], 180
    ws = hosts
    roles = ("trader", "implant", "implant2", "exfil", "badcert", "shadow") + (("jittery", "fronted", "longconn") if preset != "fixture" else ())
    h = {name: hosts[(i + (7 if preset != "fixture" else 0)) % len(hosts)] for i, name in enumerate(roles)}
    servers = ["10.30.0.5", "10.30.0.6"]
    end = minutes * 60.0
    now = T0.timestamp()
    actors: list[Actor] = [
        Actor("os_update", ws, "update.os-vendor.example", "198.51.100.20", interval=900, jitter=0.05, in_bytes=(40_000, 90_000)),
        Actor("edr_telemetry", ws, "telemetry.edr-vendor.example", "198.51.100.21", interval=60 if preset != "fixture" else 180, jitter=0.03),
        Actor("chat_presence", ws, "presence.collab.example", "198.51.100.22", interval=30 if preset != "fixture" else 120, jitter=0.10),
        Actor("file_share", ws[: max(4, len(ws) * 3 // 4)], "files.corp-share.example", "198.51.100.23", mean_gap=1800,
              out_bytes=(5_000_000, 25_000_000), in_bytes=(20_000, 60_000)),
        Actor("trader_tab", [h["trader"]], "quotes.niche-market.example", "203.0.113.80", interval=30, jitter=0.02, ja4=BROWSER_JA4),
        Actor("registered_ai", [servers[0]], "acmebank-prod.openai.azure.com", "198.51.100.40", mean_gap=20, ja4=PYTHON_JA4,
              out_bytes=(20_000, 40_000), in_bytes=(2_000, 8_000)),
        Actor("approved_ai_desktops", ws[:3], "acmebank-prod.openai.azure.com", "198.51.100.40", mean_gap=900, ja4=BROWSER_JA4),
        # threats
        Actor("implant_c2_beacon", [h["implant"]], "cdn-sync.update-check.example", "203.0.113.66", interval=60, jitter=0.06,
              out_bytes=(600, 700), in_bytes=(250, 350), ja4=IMPLANT_JA4, threat="implant_c2_beacon", start=120,
              tls12_cert={"subject": DEFAULT_SUBJECT, "issuer": DEFAULT_SUBJECT, "age_days": 2, "validity_days": 3650,
                          "validation": "self signed certificate"}),
        Actor("tls13_beacon", [h["implant2"]], "api.metrics-cloud.example", "203.0.113.67", interval=300 if preset != "fixture" else 120,
              jitter=0.10, out_bytes=(900, 1100), in_bytes=(400, 600), ja4=IMPLANT2_JA4, threat="tls13_beacon", start=60),
        Actor("slow_exfil", [h["exfil"]], "backup-store.example", "203.0.113.68",
              mean_gap=240 if preset != "fixture" else 90, out_bytes=(3_500_000, 4_500_000) if preset != "fixture" else (7_000_000, 9_000_000),
              in_bytes=(10_000, 30_000), ja4=PYTHON_JA4, threat="slow_exfil", start=300,
              tls12_cert={"subject": "CN=backup-store.example", "issuer": "CN=Sample Issuing CA,O=Sample CA", "age_days": 3,
                          "validity_days": 90, "validation": "ok"}),
        Actor("known_bad_certificate", [h["badcert"]], "login-verify.example", "203.0.113.69", once=True, ja4=IMPLANT_JA4,
              threat="known_bad_certificate", start=600,
              tls12_cert={"subject": "CN=login-verify.example", "issuer": "CN=login-verify.example", "age_days": 20,
                          "validity_days": 365, "validation": "self signed certificate"}),
        Actor("shadow_ai_upload", [h["shadow"]], "api.openai.com", "198.51.100.50", interval=120 if preset != "fixture" else 60,
              jitter=0.5, out_bytes=(400_000, 600_000) if preset != "fixture" else (900_000, 1_100_000), in_bytes=(5_000, 15_000),
              ja4=PYTHON_JA4, threat="shadow_ai_upload", start=900),
        Actor("unapproved_ai_provider", [servers[1]], "api.anthropic.com", "198.51.100.51", mean_gap=600 if preset != "fixture" else 300,
              ja4=PYTHON_JA4, threat="unapproved_ai_provider", start=1200 if preset != "fixture" else 300),
    ]
    if preset != "fixture":
        actors += [                       # reported gaps — not in the sample logs, which stay focused
        Actor("jittery_beacon", [h["jittery"]], "cfg.sync-node.example", "203.0.113.70", interval=120, jitter=0.6,
              ja4=IMPLANT2_JA4, threat="jittery_beacon"),
        Actor("c2_on_popular_name", [h["fronted"]], "presence.collab.example", "203.0.113.71", interval=45, jitter=0.05,
              ja4=IMPLANT_JA4, threat="c2_on_popular_name"),
        Actor("long_connection_c2", [h["longconn"]], "relay.long-haul.example", "203.0.113.72", once=True, long_conn=True,
              out_bytes=(2_000_000, 3_000_000), ja4=IMPLANT2_JA4, threat="long_connection_c2", start=60),
        ]
    if preset != "fixture":
        sites = [f"site-{k}.example" for k in range(300)]
        for host in ws:
            for _ in range(rng.randint(40, 90)):
                k = int(rng.paretovariate(1.2)) % len(sites)
                actors.append(Actor("browsing", [host], sites[k], f"192.0.2.{(k % 250) + 1}", once=True, ja4=BROWSER_JA4,
                                    start=rng.uniform(0, end), in_bytes=(20_000, 400_000)))
    register = [
        {"host": "", "system": "AcmeBank enterprise Azure OpenAI tenant", "endpoints": "acmebank-prod.openai.azure.com"},
        {"host": servers[0], "system": "SOC-AGENTQ-01", "endpoints": "acmebank-prod.openai.azure.com"},
        {"host": servers[1], "system": "LEN-LOA-01", "endpoints": "acmebank-prod.openai.azure.com"},
    ]
    bad_sha1, _ = cert_ids("login-verify.example")
    iocs = [
        {"kind": "cert_sha1", "value": bad_sha1, "name": "sample C2 certificate (invented)", "confidence": 0.95, "source": "sample"},
        {"kind": "ja3", "value": "00000000000000000000000000000bad", "name": "sample client fingerprint (invented)", "confidence": 0.6,
         "source": "sample"},
        {"kind": "domain", "value": "phish-kit.example", "name": "sample phishing kit domain (invented)", "source": "sample"},
    ]
    world = World(hosts=hosts + servers, minutes=minutes, actors=actors,
                  gated={"implant_c2_beacon": "malicious", "tls13_beacon": "suspicious", "slow_exfil": "suspicious",
                         "known_bad_certificate": "malicious", "shadow_ai_upload": "suspicious", "unapproved_ai_provider": "suspicious"},
                  deadline_min={"implant_c2_beacon": 16, "tls13_beacon": 55 if preset != "fixture" else 25, "slow_exfil": 90,
                                "known_bad_certificate": 11, "shadow_ai_upload": 75, "unapproved_ai_provider": 60},
                  reported=("jittery_beacon", "c2_on_popular_name", "long_connection_c2") if preset != "fixture" else (),
                  register_rows=register, ioc_rows=iocs)
    world.records = _records(world, rng, now, end)
    return world


def _records(world: World, rng: random.Random, now: float, end: float) -> list[dict]:
    """Zeek-shaped records (``_path`` ssl / conn / x509), in the order a sensor writes them."""
    out: list[tuple[float, int, dict]] = []
    n = 0
    seen_certs: set[str] = set()
    for a in world.actors:
        for host in a.hosts:
            times: list[float] = []
            if a.once:
                times = [a.start + (rng.uniform(0, 30) if not a.threat else 0.0)]
            elif a.interval > 0:
                t = a.start + rng.uniform(0, a.interval)
                while t < (a.end or end):
                    times.append(t)
                    t += a.interval * (1 + rng.uniform(-a.jitter, a.jitter))
            elif a.mean_gap > 0:
                t = a.start + rng.expovariate(1 / a.mean_gap)
                while t < (a.end or end):
                    times.append(t)
                    t += rng.expovariate(1 / a.mean_gap)
            for t in times:
                n += 1
                uid = f"C{n:09x}s"
                ts = now + t
                sport = 49152 + (n % 16000)
                base = {"ts": round(ts, 6), "uid": uid, "id.orig_h": host, "id.orig_p": sport, "id.resp_h": a.dst, "id.resp_p": 443}
                ssl: dict[str, Any] = {"_path": "ssl", **base, "version": "TLSv12" if a.tls12_cert else "TLSv13",
                                       "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" if a.tls12_cert else "TLS_AES_128_GCM_SHA256",
                                       "server_name": a.sni, "established": True, "ja4": a.ja4}
                if a.tls12_cert:
                    sha1, sha256 = cert_ids(a.sni)
                    ssl["cert_chain_fps"] = [sha256]
                    ssl["validation_status"] = a.tls12_cert.get("validation", "ok")
                    if sha256 not in seen_certs:
                        seen_certs.add(sha256)
                        nb = now - a.tls12_cert["age_days"] * 86400
                        out.append((ts, 0, {"_path": "x509", "ts": round(ts, 6), "fingerprint": sha256, "sha1": sha1,
                                            "certificate.version": 3, "certificate.serial": sha1[:16].upper(),
                                            "certificate.subject": a.tls12_cert["subject"], "certificate.issuer": a.tls12_cert["issuer"],
                                            "certificate.not_valid_before": round(nb, 0),
                                            "certificate.not_valid_after": round(nb + a.tls12_cert["validity_days"] * 86400, 0),
                                            "certificate.key_alg": "rsaEncryption", "certificate.key_length": 2048,
                                            "san.dns": [a.sni], "host_cert": True}))
                dur = (end - t) if a.long_conn else rng.uniform(0.2, 2.0)
                conn = {"_path": "conn", **base, "proto": "tcp", "service": "ssl", "duration": round(dur, 3),
                        "orig_bytes": rng.randint(*a.out_bytes), "resp_bytes": rng.randint(*a.in_bytes), "conn_state": "SF",
                        "history": "ShADadfF"}
                out.append((ts + 0.02, 1, ssl))
                out.append((ts + dur, 2, conn))
    out.sort(key=lambda x: (x[0], x[1]))
    return [r for _, _, r in out]


# ------------------------------------------------------------------- run --

@dataclass
class ScenarioResult:
    name: str
    expected: str
    gated: bool
    first_finding: str = ""
    first_at_min: float | None = None
    verdict: str = ""
    best_verdict: str = ""
    confidence: float = 0.0
    findings: dict[str, int] = field(default_factory=dict)
    gate_pass: bool | None = None
    reasons: list[str] = field(default_factory=list)


_RANK = {"": 0, "benign": 1, "suspicious": 2, "malicious": 3}


def run(preset: str = "bench", *, verbose: bool = False, seed: int = 7) -> dict:
    from ..agents.ndr.egress import EgressDetector
    from ..ingest.base import CONSUMED, AlertCheckpoint
    from ..ingest.ndr import NdrConsumer
    from .fault_injection import _env

    world = build_world(preset, seed=seed)
    host_actor: dict[tuple[str, str], str] = {}
    for a in world.actors:
        for host in a.hosts:
            host_actor[(host, a.sni)] = a.threat or a.name
    threats = {a.threat for a in world.actors if a.threat}
    results = {t: ScenarioResult(t, world.gated.get(t, ""), t in world.gated) for t in sorted(threats)}
    benign = {"malicious": 0, "containment_proposals": 0, "suspicious_beacons": 0, "shadow_ai_on_registered": 0,
              "other_findings": 0, "examples": []}
    start = T0.timestamp()
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "ioc.jsonl").write_text("\n".join(json.dumps(r) for r in world.ioc_rows) + "\n", encoding="utf-8")
        _write_register(tdp / "ai_register.csv", world.register_rows)
        env = {"AEGIS_EDITION": "external", "ACP_DASHBOARD_URL": None, "ACP_API_KEY": None, "ACP_GOVERN": None,
               "AEGIS_PERSIST": None, "AEGIS_RULE_FEED": None, "AEGIS_SWARM": "0", "AEGIS_INVESTIGATE": "0",
               "AEGIS_CAMPAIGN_CONTEXT": "1", "AEGIS_CVE_INTEL": "0", "AEGIS_DATASET_CAPTURE": "0", "AEGIS_INTEL_MOCK": "0",
               "AEGIS_HITL_TRANSPORT": "file", "AEGIS_HITL_DIR": str(tdp / "hitl"), "AEGIS_HITL_STATE": str(tdp / "hitl.jsonl"),
               "AEGIS_CHECKPOINT": str(tdp / "cp.json"), "AEGIS_RECEIPTS_DIR": td, "AEGIS_TI_CACHE": td, "ACP_HOME": td,
               "AEGIS_WAF_VENDOR": None, "AEGIS_SOAR_VENDOR": None, "AEGIS_ENFORCEMENT_MODE": "shadow", "AEGIS_SOURCES": "sample",
               "AEGIS_INGEST_HTTP": None, "AEGIS_INGEST_BIND": None,
               "AEGIS_TLS_IOC_FILE": str(tdp / "ioc.jsonl"), "AEGIS_AI_REGISTER": str(tdp / "ai_register.csv"),
               "AEGIS_SHADOW_AI_REGISTER": str(tdp / "shadow_ai.json"), "AEGIS_INTERNAL_NETS": None,
               "AEGIS_NDR_ALLOW_DOMAINS": None, "AEGIS_NDR_ALLOW_HOSTS": None, "LLM_BACKEND": "mock"}
        with _env(env):
            from ..service import build_pipeline
            p = build_pipeline(tdp / "audit.jsonl", fresh=True, include_mock_intel=False)
            import io
            p.response._hitl_stream = io.StringIO()
            detector = EgressDetector.from_env()
            consumer = NdrConsumer(detector=detector, checkpoint=AlertCheckpoint())
            try:
                for rec in world.records:
                    got = consumer.normalize(rec)
                    if got is CONSUMED or not got:
                        continue
                    for alert in got:
                        chain = p.orch.handle(alert)
                        p.response.execute(chain)
                        who = host_actor.get((alert["source_ip"], alert["egress"]["destination"]), "?")
                        at = (datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00")).timestamp() - start) / 60
                        if verbose:
                            print(f"  {at:6.1f} min  {who:24s} {alert['alert_type']:14s} → {chain.verdict} {chain.confidence:.2f}")
                        r = results.get(who)
                        if r is not None:
                            r.findings[alert["alert_type"]] = r.findings.get(alert["alert_type"], 0) + 1
                            if not r.first_finding:
                                r.first_finding, r.first_at_min, r.verdict = alert["alert_type"], round(at, 1), chain.verdict
                            if (_RANK[chain.verdict], chain.confidence) > (_RANK[r.best_verdict], r.confidence):
                                r.best_verdict, r.confidence = chain.verdict, chain.confidence
                            continue
                        if chain.verdict == "malicious":
                            benign["malicious"] += 1
                        if any(x.action_type in ("isolate", "block_egress") for x in chain.recommended_actions):
                            benign["containment_proposals"] += 1
                        if alert["alert_type"] == "tls_beacon":
                            benign["suspicious_beacons"] += 1
                        elif alert["alert_type"] == "shadow_ai":
                            benign["shadow_ai_on_registered"] += 1
                        else:
                            benign["other_findings"] += 1
                        if len(benign["examples"]) < 5:
                            benign["examples"].append(f"{who}: {alert['note']} → {chain.verdict} {chain.confidence:.2f}")
            finally:
                detector.usage.write()
                p.close()
            shadow = json.loads((tdp / "shadow_ai.json").read_text()) if (tdp / "shadow_ai.json").exists() else {}
    for r in results.values():
        if not r.gated:
            continue
        if not r.first_finding:
            r.reasons.append("never found")
        else:
            if _RANK[r.best_verdict] < _RANK[r.expected]:
                r.reasons.append(f"judged {r.best_verdict}, expected {r.expected}")
            if r.first_at_min is not None and r.first_at_min > world.deadline_min.get(r.name, 1e9):
                r.reasons.append(f"found at {r.first_at_min} min > {world.deadline_min[r.name]} min")
        r.gate_pass = not r.reasons
    benign_reasons = []
    if benign["malicious"]:
        benign_reasons.append(f"{benign['malicious']} malicious verdicts on benign hosts")
    if benign["containment_proposals"]:
        benign_reasons.append(f"{benign['containment_proposals']} isolation / egress-block proposals on benign hosts")
    if benign["shadow_ai_on_registered"]:
        benign_reasons.append(f"{benign['shadow_ai_on_registered']} shadow-AI findings on registered / approved use")
    return {"preset": preset, "hosts": len(world.hosts), "minutes": world.minutes, "records": len(world.records),
            "scenarios": [r.__dict__ for r in results.values()], "benign": benign, "benign_reasons": benign_reasons,
            "shadow_ai_register": shadow.get("summary", {}),
            "pass": all(r.gate_pass for r in results.values() if r.gated) and not benign_reasons}


def _write_register(path: Path, rows: list[dict]) -> None:
    lines = ["host,system,endpoints"] + [f"{r['host']},{r['system']},{r['endpoints']}" for r in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render(rep: dict) -> str:
    lines = [(f"=== Egress benchmark: network-sensor TLS metadata vs AEGIS — {rep['hosts']} hosts, {rep['minutes']} min, "
              f"{rep['records']} sensor records ==="),
             f"  {'scenario':<24} {'expected':<11} {'first finding':<15} {'at':>9}  {'judged':<11} {'conf':>5}  gate"]
    for r in rep["scenarios"]:
        at = f"{r['first_at_min']:.1f} min" if r["first_at_min"] is not None else "—"
        gate = "PASS" if r["gate_pass"] else ("FAIL" if r["gate_pass"] is False else "report")
        lines.append(f"  {r['name']:<24} {r['expected'] or '—':<11} {r['first_finding'] or '—':<15} {at:>9}  "
                     f"{r['best_verdict'] or '—':<11} {r['confidence']:>5.2f}  {gate}")
        for why in r["reasons"]:
            lines.append(f"      ✗ {why}")
    b = rep["benign"]
    lines.append(f"  benign traffic: malicious {b['malicious']} · isolation / block proposals {b['containment_proposals']} · "
                 f"shadow AI on registered use {b['shadow_ai_on_registered']} · suspicious beacons {b['suspicious_beacons']} "
                 f"(polling tabs) · other {b['other_findings']}")
    for ex in b["examples"]:
        lines.append(f"      · {ex}")
    for why in rep["benign_reasons"]:
        lines.append(f"      ✗ {why}")
    if rep.get("shadow_ai_register"):
        lines.append(f"  shadow-AI register: {rep['shadow_ai_register']}")
    gated = [r for r in rep["scenarios"] if r["gate_pass"] is not None]
    ok = sum(1 for r in gated if r["gate_pass"])
    lines.append(f"  {ok}/{len(gated)} gated scenarios pass; {len(rep['scenarios']) - len(gated)} reported only; "
                 f"benign {'clean' if not rep['benign_reasons'] else 'FAIL'}")
    return "\n".join(lines)


def write_fixtures(out_dir: str | Path) -> list[Path]:
    """A 30-minute, 6-host slice as Zeek and Suricata sample logs, plus its IOC list and AI register."""
    world = build_world("fixture")
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    banner = "SAMPLE DATA: a simulated office network from aegis/eval/egress_bench.py; every value is invented"
    zeek = d / "zeek_tls.sample.jsonl"
    zeek.write_text(f"# {banner}\n" + "\n".join(json.dumps(r) for r in world.records) + "\n", encoding="utf-8")
    eve = d / "suricata_eve.sample.jsonl"
    eve.write_text(f"# {banner}\n" + "\n".join(json.dumps(r) for r in _to_eve(world.records)) + "\n", encoding="utf-8")
    ioc = d / "tls_ioc.sample.jsonl"
    ioc.write_text(f"# {banner}\n" + "\n".join(json.dumps(r) for r in world.ioc_rows) + "\n", encoding="utf-8")
    sslbl = d / "sslbl.sample.csv"
    bad_sha1 = next(r["value"] for r in world.ioc_rows if r["kind"] == "cert_sha1")
    sslbl.write_text("################################################################\n"
                     f"# {banner} (abuse.ch SSLBL export format)\n"
                     "# Listingdate,SHA1,Listingreason\n"
                     f"2026-10-20 08:00:00,{bad_sha1},Sample C2 (invented)\n", encoding="utf-8")
    reg = d / "ai_register.sample.csv"
    _write_register(reg, world.register_rows)
    reg.write_text(f"# {banner}\n" + reg.read_text(encoding="utf-8"), encoding="utf-8")
    return [zeek, eve, ioc, sslbl, reg]


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _to_eve(records: list[dict]) -> list[dict]:
    """The same connections as Suricata EVE ``tls`` + ``flow`` events (x509 folded into ``tls``)."""
    certs = {r["fingerprint"]: r for r in records if r.get("_path") == "x509"}
    out: list[dict] = []
    for i, r in enumerate(records):
        flow_id = int(hashlib.sha1(r.get("uid", str(i)).encode()).hexdigest()[:12], 16)
        base = {"flow_id": flow_id, "src_ip": r.get("id.orig_h"), "src_port": r.get("id.orig_p"), "dest_ip": r.get("id.resp_h"),
                "dest_port": r.get("id.resp_p"), "proto": "TCP"}
        if r.get("_path") == "ssl":
            tls: dict[str, Any] = {"sni": r.get("server_name"), "version": "TLS 1.2" if r.get("version") == "TLSv12" else "TLS 1.3",
                                   "ja4": r.get("ja4")}
            fp = (r.get("cert_chain_fps") or [None])[0]
            c = certs.get(fp) if fp else None
            if c:
                tls.update({"subject": c["certificate.subject"], "issuerdn": c["certificate.issuer"],
                            "fingerprint": ":".join(c["sha1"][k:k + 2] for k in range(0, 40, 2)),
                            "notbefore": datetime.fromtimestamp(c["certificate.not_valid_before"], UTC).strftime("%Y-%m-%dT%H:%M:%S"),
                            "notafter": datetime.fromtimestamp(c["certificate.not_valid_after"], UTC).strftime("%Y-%m-%dT%H:%M:%S")})
            out.append({"timestamp": _iso(r["ts"]), "event_type": "tls", **base, "tls": tls})
        elif r.get("_path") == "conn":
            out.append({"timestamp": _iso(r["ts"] + r["duration"]), "event_type": "flow", **base, "app_proto": "tls",
                        "flow": {"pkts_toserver": 8, "pkts_toclient": 7, "bytes_toserver": r["orig_bytes"],
                                 "bytes_toclient": r["resp_bytes"], "start": _iso(r["ts"]), "end": _iso(r["ts"] + r["duration"]),
                                 "age": int(r["duration"]), "state": "closed", "reason": "shutdown"}})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--preset", choices=("bench", "fixture"), default="bench")
    ap.add_argument("--json", help="write the full report here")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--seed", type=int, default=7, help="world seed (the CI gate uses the default)")
    ap.add_argument("--write-fixtures", metavar="DIR", help="write the sample Zeek / Suricata logs and exit")
    a = ap.parse_args(argv)
    if a.write_fixtures:
        for f in write_fixtures(a.write_fixtures):
            print(f"wrote {f}")
        return 0
    rep = run(a.preset, verbose=a.verbose, seed=a.seed)
    print(render(rep))
    if a.json:
        Path(a.json).write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    return 0 if rep["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
