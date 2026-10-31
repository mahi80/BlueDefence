"""Purple-team harness: adaptive attacker vs. the real AEGIS pipeline, measured.

The attacker is a small state machine (``Attacker``) that pursues a campaign's goals and
adapts to being stopped. Every attempt becomes a Cloudflare-shaped log record, is normalised
by the real ``WafConsumer`` (so fingerprints, blocked flags and timestamps flow exactly as in
production), handled by the real orchestrator (campaign context, fast paths, specialists,
voter) and acted on by the real ``ResponseAgent`` through the mock Cloudflare tenant in
**live** enforcement. Two response modes are compared:

    auto     ``AEGIS_AUTO_BLOCK=live`` — tiered autonomy blocks narrow external targets itself
    human    ``AEGIS_AUTO_BLOCK=shadow`` + a simulated analyst who approves every pending block
             ``approval_latency_s`` of *simulated* time after it was filed

Time is simulated for the attacker (request gaps, retry gaps, approval latency) so a campaign
that takes an hour of attacker time runs in seconds; wall-clock is measured only for what the
pipeline itself costs per event (``handle_ms``).

Containment means the attacker can no longer get a request through: its *next* attempt is
denied by AEGIS enforcement (not by the WAF rule it is mutating around), and it never gets
another success. Collateral is any benign customer in the same traffic whose request is
blocked or challenged by an AEGIS action.
"""

from __future__ import annotations

import json
import logging
import statistics
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from ...agents.shared.fingerprint import is_fingerprint_target, parse_target
from ...ingest.waf import WafConsumer
from ..fault_injection import _env
from .scenarios import CAMPAIGNS, BenignClient, Campaign, Goal, benign_crowd, ownership_map

logger = logging.getLogger("aegis.eval.purple_team")

T0 = datetime(2026, 10, 22, 9, 0, 0, tzinfo=timezone.utc)
HOST = "netbanking.bank.example"
MAX_STEPS = 80
GIVE_UP_AFTER = 10            # consecutive AEGIS denials before the attacker abandons the campaign
WARMUP_ROUNDS = 2             # rounds of customer traffic before the attacker arrives (the bank has history)
WARMUP_S = 300.0              # … spread over the five minutes before it

#: model selection is taken from the caller's environment (``LLM_BACKEND=local AEGIS_MODEL=<adapter>``
#: to measure a fine-tuned first pass); with no ``LLM_BACKEND`` set the run is the deterministic mock
MODEL_KEYS = ("LLM_BACKEND", "AEGIS_MODEL", "AEGIS_LOCAL_4BIT", "AEGIS_MODEL_POINTER", "AEGIS_VOTER_BACKEND",
              "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_MODEL")

BASE_ENV: dict[str, Any] = {
    "AEGIS_EDITION": "external",
    "ACP_DASHBOARD_URL": None, "ACP_API_KEY": None, "ACP_GOVERN": None, "AEGIS_PERSIST": None, "AEGIS_RULE_FEED": None,
    "AEGIS_HITL_TRANSPORT": "file", "AEGIS_SWARM": "0", "AEGIS_INVESTIGATE": "0", "AEGIS_TWIN": "0",
    "AEGIS_CAMPAIGN_CONTEXT": "1", "AEGIS_CVE_INTEL": "0", "AEGIS_INTEL_MOCK": "1", "AEGIS_PII_TOKENIZATION": "0",
    "AEGIS_DATASET_CAPTURE": "0", "AEGIS_WAF_VENDOR": "mock-cloudflare", "AEGIS_SOAR_VENDOR": None,
    "AEGIS_ENFORCEMENT_MODE": "live", "AEGIS_INGEST_HTTP": None, "AEGIS_INGEST_BIND": None, "AEGIS_SOURCES": "sample",
    "AEGIS_FP_ALLOW": None, "AEGIS_PROTECTED_TARGETS": None,
}


# ------------------------------------------------------------- attacker --

@dataclass
class Attempt:
    step: int
    sim_t: float
    goal: str
    variant: str
    ip: str
    ua: str
    ja4: Optional[str]
    path: str
    method: str
    is_retry: bool
    waf_caught: bool = False
    aegis_denied: str = ""            # "" | block | challenge
    reached_app: bool = False
    sensitive: bool = False
    verdict: str = ""
    investigated_by: str = ""
    handle_ms: float = 0.0


class Attacker:
    """Pursues goals in order; on a stop, rotates IP (and UA when it has several), moves to the
    next payload variant and retries after ``retry_gap_s``; gives up on a goal after
    ``max_retries`` and on the campaign after ``GIVE_UP_AFTER`` consecutive AEGIS denials."""

    def __init__(self, c: Campaign):
        self.c = c
        self.ip_i = self.ua_i = 0
        self.goal_i = 0
        self.variant_i = 0
        self.retries = 0
        self.repeat_i = 0
        self.consecutive_denials = 0
        self.ips_used: set[str] = set()
        self.done = not c.goals
        self.gave_up = False

    @property
    def goal(self) -> Goal:
        return self.c.goals[self.goal_i]

    def identity(self) -> tuple[str, str, Optional[str]]:
        return self.c.ip_pool[self.ip_i % len(self.c.ip_pool)], self.c.user_agents[self.ua_i % len(self.c.user_agents)], self.c.ja4

    def next_attempt(self, step: int, sim_t: float) -> Attempt:
        g = self.goal
        ip, ua, ja4 = self.identity()
        self.ips_used.add(ip)
        v = g.variants[min(self.variant_i, len(g.variants) - 1)]
        path = g.path.replace("{id}", str(1000 + self.repeat_i))
        return Attempt(step=step, sim_t=sim_t, goal=g.name, variant=v, ip=ip, ua=ua, ja4=ja4, path=path,
                       method=g.method, is_retry=self.retries > 0, sensitive=g.sensitive,
                       waf_caught=g.waf_catches[min(self.variant_i, len(g.waf_catches) - 1)])

    def observe(self, a: Attempt) -> float:
        """Update state from the outcome; return the simulated gap before the next request."""
        if a.aegis_denied:
            self.consecutive_denials += 1
            if self.consecutive_denials >= GIVE_UP_AFTER:
                self.gave_up = self.done = True
                return 0.0
        else:
            self.consecutive_denials = 0
        if a.reached_app:
            self.repeat_i += 1
            if self.repeat_i >= self.goal.repeat:
                self._advance_goal()
            return self.c.gap_s
        # stopped (by the WAF rule or by AEGIS): adapt
        self.ip_i += 1
        if len(self.c.user_agents) > 1:
            self.ua_i += 1
        self.variant_i += 1
        self.retries += 1
        if self.retries > self.c.max_retries:
            self._advance_goal()
        return self.c.retry_gap_s

    def _advance_goal(self) -> None:
        self.goal_i += 1
        self.variant_i = self.retries = self.repeat_i = 0
        if self.goal_i >= len(self.c.goals):
            self.done = True


# ---------------------------------------------------------- enforcement --

def _denied_by_aegis(receipts: list[Any], ip: str, ja4: Optional[str], ua: str) -> str:
    """What AEGIS's active enforcement does to this client: '' | block | challenge."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        addr = None
    worst = ""
    for r in receipts:
        if r.dry_run or r.connector == "log" or r.action_type not in ("block", "challenge"):
            continue
        t = str(r.target)
        hit = False
        if is_fingerprint_target(t):
            try:
                kind, value, t_ua = parse_target(t)
            except ValueError:
                continue
            hit = ja4 is not None and kind == "ja4" and value == ja4 and (not t_ua or t_ua == ua)
        elif addr is not None:
            try:
                hit = addr in ipaddress.ip_network(t, strict=False)
            except ValueError:
                hit = False
        if hit and (r.action_type == "block" or not worst):
            worst = r.action_type
    return worst


# ---------------------------------------------------------- log records --

def _ray(n: int) -> str:
    return f"8f{n:014x}"


def _record(n: int, *, ip: str, ua: str, ja4: Optional[str], path: str, method: str, query: str, at: datetime,
            waf_caught: bool, description: str, aegis_denied: str, status: int) -> str:
    rec: dict[str, Any] = {
        "RayID": _ray(n), "ClientIP": ip, "ClientRequestHost": HOST, "ClientRequestMethod": method,
        "ClientRequestPath": path, "ClientRequestQuery": query, "ClientRequestUserAgent": ua,
        "Datetime": at.isoformat().replace("+00:00", "Z"), "EdgeResponseStatus": status,
    }
    if ja4:
        rec["JA4"] = ja4
    if aegis_denied:
        rec.update({"Action": "block" if aegis_denied == "block" else "managed_challenge", "Source": "firewallCustom",
                    "Description": "aegis enforcement", "RuleID": "aegis"})
    elif waf_caught:
        rec.update({"Action": "block", "Source": "firewallManaged", "Description": description, "RuleID": "managed-1"})
    else:
        rec.update({"Action": "allow", "Source": "", "Description": "", "RuleID": ""})
    return json.dumps(rec)


def _apim_record(n: int, *, principal: str, ip: str, ua: str, path: str, method: str, status: int, at: datetime) -> dict:
    """An Azure API Management GatewayLogs diagnostic record (the subject logged via policy as userId)."""
    return {"time": at.isoformat().replace("+00:00", "Z"), "category": "GatewayLogs", "callerIpAddress": ip,
            "correlationId": f"apim-{n:08d}",
            "properties": {"method": method, "url": f"https://api.bank.example{path}", "responseCode": status,
                           "userId": principal, "apimSubscriptionId": "mobile-app", "userAgent": ua}}


# ------------------------------------------------------------- results --

@dataclass
class CampaignResult:
    campaign: str
    mode: str
    approval_latency_s: float
    attempts: list[Attempt] = field(default_factory=list)
    benign_requests: int = 0
    benign_blocked: set[str] = field(default_factory=set)
    benign_challenged: set[str] = field(default_factory=set)
    verdicts: dict[str, int] = field(default_factory=dict)
    first_suspicious: Optional[Attempt] = None
    first_malicious: Optional[Attempt] = None
    contained_at: Optional[Attempt] = None
    gave_up: bool = False
    ips_used: int = 0
    enforced_targets: list[str] = field(default_factory=list)
    handle_ms: list[float] = field(default_factory=list)
    notes: str = ""
    gate_pass: Optional[bool] = None
    gate_reasons: list[str] = field(default_factory=list)

    @property
    def successes(self) -> list[Attempt]:
        return [a for a in self.attempts if a.reached_app]

    @property
    def successes_after_detection(self) -> int:
        if self.first_malicious is None:
            return len(self.successes)
        return sum(1 for a in self.successes if a.step > self.first_malicious.step)

    @property
    def sensitive_reached(self) -> int:
        return sum(1 for a in self.successes if a.sensitive)

    def finish(self) -> None:
        aegis_denials = [a for a in self.attempts if a.aegis_denied]
        last_success = max((a.step for a in self.successes), default=0)
        after = [a for a in aegis_denials if a.step > last_success]
        self.contained_at = after[0] if after else None

    def p50_ms(self) -> float:
        return statistics.median(self.handle_ms) if self.handle_ms else 0.0

    def p95_ms(self) -> float:
        if not self.handle_ms:
            return 0.0
        xs = sorted(self.handle_ms)
        return xs[min(len(xs) - 1, int(0.95 * len(xs)))]

    def to_dict(self) -> dict:
        return {
            "campaign": self.campaign, "mode": self.mode, "approval_latency_s": self.approval_latency_s,
            "steps": len(self.attempts), "ips_used": self.ips_used, "gave_up": self.gave_up,
            "detected_step": self.first_malicious.step if self.first_malicious else None,
            "detected_sim_s": self.first_malicious.sim_t if self.first_malicious else None,
            "detected_by": self.first_malicious.investigated_by if self.first_malicious else None,
            "suspicious_step": self.first_suspicious.step if self.first_suspicious else None,
            "contained_step": self.contained_at.step if self.contained_at else None,
            "contained_sim_s": self.contained_at.sim_t if self.contained_at else None,
            "successes": len(self.successes), "successes_after_detection": self.successes_after_detection,
            "sensitive_reached": self.sensitive_reached, "waf_caught": sum(1 for a in self.attempts if a.waf_caught),
            "aegis_denied": sum(1 for a in self.attempts if a.aegis_denied),
            "benign_requests": self.benign_requests, "benign_blocked": sorted(self.benign_blocked),
            "benign_challenged": sorted(self.benign_challenged), "verdicts": dict(self.verdicts),
            "enforced_targets": self.enforced_targets, "handle_ms_p50": round(self.p50_ms(), 1),
            "handle_ms_p95": round(self.p95_ms(), 1), "gate_pass": self.gate_pass, "gate_reasons": self.gate_reasons,
            "notes": self.notes,
        }


# -------------------------------------------------------------- harness --

def model_env() -> dict[str, Any]:
    """The model the caller asked for, or the mock (with cloud keys blanked so nothing leaves the box)."""
    import os
    chosen = {k: os.environ[k] for k in MODEL_KEYS if os.environ.get(k)}
    if chosen.get("LLM_BACKEND", "mock").strip().lower() == "mock":
        return {"LLM_BACKEND": "mock", "ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": ""}
    return chosen


def model_label() -> str:
    env = model_env()
    backend = env.get("LLM_BACKEND", "mock")
    return backend if backend == "mock" else f"{backend}:{env.get('AEGIS_MODEL') or env.get('ANTHROPIC_MODEL') or 'default'}"


class Harness:
    def __init__(self, *, mode: str = "auto", approval_latency_s: float = 300.0, benign: bool = True,
                 env: Optional[dict[str, Any]] = None, verbose: bool = False):
        if mode not in ("auto", "human"):
            raise ValueError("mode must be auto or human")
        self.mode = mode
        self.approval_latency_s = approval_latency_s
        self.benign = benign
        self.env_extra = dict(env or {})
        self.verbose = verbose
        self._n = 0
        self._gw: Any = None
        self._principal = ""

    def run(self, campaign: Campaign) -> CampaignResult:
        env = {**BASE_ENV, **model_env(), "AEGIS_AUTO_BLOCK": "live" if self.mode == "auto" else "shadow", **self.env_extra}
        res = CampaignResult(campaign=campaign.name, mode=self.mode, approval_latency_s=self.approval_latency_s,
                             notes=campaign.notes)
        with tempfile.TemporaryDirectory() as td, _env({**env, "AEGIS_HITL_DIR": str(Path(td) / "hitl"),
                                                        "AEGIS_CHECKPOINT": str(Path(td) / "cp.json"), "AEGIS_HITL_STATE": str(Path(td) / "hitl.jsonl"),
                                                        "AEGIS_RECEIPTS_DIR": td, "AEGIS_TI_CACHE": td,
                                                        "ACP_HOME": td}):
            from ...service import build_pipeline
            from ...ingest.stream import reset_stream
            reset_stream()
            p = build_pipeline(Path(td) / "audit.jsonl", fresh=True, include_mock_intel=True)
            try:
                self._drive(p, campaign, res)
            finally:
                p.close()
        res.finish()
        _judge(campaign, res)
        return res

    # -- one campaign
    def _drive(self, p: Any, c: Campaign, res: CampaignResult) -> None:
        import io
        p.response._hitl_stream = io.StringIO()
        waf = WafConsumer()
        attacker = Attacker(c)
        crowd = benign_crowd() if (self.benign and c.benign_traffic) else []
        self._gw = None
        if c.channel == "apigw":
            from ...agents.api_abuse.object_walk import ObjectWalkDetector
            from ...agents.api_abuse.ownership import DictOwnership
            from ...ingest.apigw import ApiGatewayConsumer
            from ...ingest.base import AlertCheckpoint
            owners = ownership_map(crowd or benign_crowd())
            self._gw = ApiGatewayConsumer(detector=ObjectWalkDetector(DictOwnership(owners), exempt=[]),
                                          checkpoint=AlertCheckpoint())
            self._principal = c.principal or ""
        sim_t = 0.0
        step = 0
        hitl = getattr(p.response, "_hitl", None)
        filed_at: dict[str, float] = {}
        benign_i = 0
        if crowd:
            # ordinary traffic first: the estate learns what its customers, partners and their
            # proxies look like before anyone attacks (as it would have in production)
            n = WARMUP_ROUNDS * len(crowd)
            for k in range(n):
                client = crowd[k % len(crowd)]
                self._benign_request(p, waf, client, -WARMUP_S + k * (WARMUP_S / n) - client.history_s, res)
        while step < MAX_STEPS and (not attacker.done or (not c.goals and step < 40)):
            step += 1
            # a customer request in between (collateral measurement)
            if crowd:
                client = crowd[benign_i % len(crowd)]
                benign_i += 1
                self._benign_request(p, waf, client, sim_t + 0.5, res)
            if not c.goals:
                sim_t += 3.0
                self._simulated_analyst(p, hitl, filed_at, sim_t)
                continue
            a = attacker.next_attempt(step, sim_t)
            denied = _denied_by_aegis(p.connectors.active_receipts, a.ip, a.ja4, a.ua)
            a.aegis_denied = denied
            a.reached_app = not denied and not a.waf_caught
            if self._gw is not None:
                if not denied:                       # a request the edge denied never reaches the gateway
                    self._handle_gw(p, _apim_record(self._next(), principal=self._principal, ip=a.ip, ua=a.ua, path=a.path,
                                                    method=a.method, status=403 if a.waf_caught else 200,
                                                    at=T0 + timedelta(seconds=sim_t)), res, a)
            else:
                line = _record(self._next(), ip=a.ip, ua=a.ua, ja4=a.ja4, path=a.path, method=a.method, query=f"?v={a.variant}",
                               at=T0 + timedelta(seconds=sim_t), waf_caught=a.waf_caught and not denied,
                               description=attacker.goal.description, aegis_denied=denied, status=403 if (denied or a.waf_caught) else 200)
                self._handle(p, waf, line, res, a)
            res.attempts.append(a)
            if a.verdict == "malicious" and res.first_malicious is None:
                res.first_malicious = a
            if a.verdict in ("malicious", "suspicious") and res.first_suspicious is None:
                res.first_suspicious = a
            if self.verbose:
                print(f"  [{c.name}] step {step:2d} t={sim_t:6.0f}s {a.ip:15s} {a.goal:18s} {a.variant:8s} "
                      f"{'WAF' if a.waf_caught else ('AEGIS ' + denied) if denied else 'reached app':12s} → "
                      f"{(a.verdict + '/' + a.investigated_by) if a.verdict else '(no alert)'}")
            sim_t += attacker.observe(a)
            self._simulated_analyst(p, hitl, filed_at, sim_t)
        res.gave_up = attacker.gave_up
        res.ips_used = len(attacker.ips_used)
        res.enforced_targets = sorted({str(r.target) for r in p.connectors.active_receipts
                                       if not r.dry_run and r.connector != "log" and r.action_type in ("block", "challenge")})

    def _handle(self, p: Any, waf: WafConsumer, line: str, res: CampaignResult, a: Optional[Attempt]) -> Any:
        alert = waf.normalize(line)
        assert alert is not None
        t0 = time.time()
        chain = p.orch.handle(alert)
        p.response.execute(chain)
        ms = (time.time() - t0) * 1000
        res.handle_ms.append(ms)
        res.verdicts[chain.verdict] = res.verdicts.get(chain.verdict, 0) + 1
        if a is not None:
            a.verdict, a.investigated_by, a.handle_ms = chain.verdict, chain.investigated_by, ms
        return chain

    def _handle_gw(self, p: Any, record: dict, res: CampaignResult, a: Optional[Attempt]) -> None:
        """API-gateway channel: the record feeds the object-walk detector; only its alerts reach the brain."""
        t0 = time.time()
        alert = self._gw.normalize(record)
        if alert:
            chain = p.orch.handle(alert)
            p.response.execute(chain)
            res.verdicts[chain.verdict] = res.verdicts.get(chain.verdict, 0) + 1
            if a is not None:
                a.verdict, a.investigated_by = chain.verdict, chain.investigated_by
        ms = (time.time() - t0) * 1000
        res.handle_ms.append(ms)
        if a is not None:
            a.handle_ms = ms

    def _benign_request(self, p: Any, waf: WafConsumer, client: BenignClient, sim_t: float, res: CampaignResult) -> None:
        client.requests += 1
        denied = _denied_by_aegis(p.connectors.active_receipts, client.ip, client.ja4, client.user_agent)
        if denied == "block":
            res.benign_blocked.add(client.ip)
        elif denied == "challenge":
            res.benign_challenged.add(client.ip)
        if self._gw is not None:
            res.benign_requests += 1
            if not denied and client.accounts:
                acct = client.accounts[client.requests % len(client.accounts)]
                self._handle_gw(p, _apim_record(self._next(), principal=client.principal, ip=client.ip, ua=client.user_agent,
                                                path=f"/api/v1/accounts/{acct}", method="GET", status=200,
                                                at=T0 + timedelta(seconds=sim_t)), res, None)
            return
        fp = client.false_positive_every and client.requests % client.false_positive_every == 0
        path = client.paths[client.requests % len(client.paths)]
        method = "GET"
        if " " in path:                                      # "POST /login": a form submission
            method, path = path.split(" ", 1)
        line = _record(self._next(), ip=client.ip, ua=client.user_agent, ja4=client.ja4, path=path, method=method, query="",
                       at=T0 + timedelta(seconds=sim_t), waf_caught=bool(fp) and not denied, description="XSS (managed rule)",
                       aegis_denied=denied, status=403 if (denied or fp) else 200)
        self._handle(p, waf, line, res, None)
        res.benign_requests += 1

    def _simulated_analyst(self, p: Any, hitl: Any, filed_at: dict[str, float], sim_t: float) -> None:
        """In ``human`` mode: approve each pending block ``approval_latency_s`` after it was filed."""
        if self.mode != "human" or hitl is None or not hasattr(hitl, "decisions_file"):
            return
        due = []
        for pa in hitl.pending:
            t = filed_at.setdefault(pa.approval_id, sim_t)
            if pa.action.action_type == "block" and sim_t - t >= self.approval_latency_s:
                due.append(pa.approval_id)
        if not due:
            return
        with open(hitl.decisions_file, "a", encoding="utf-8") as fh:
            for aid in due:
                fh.write(json.dumps({"approval_id": aid, "status": "approved", "decided_by": "sim-analyst"}) + "\n")
        p.response.sync_hitl()

    def _next(self) -> int:
        self._n += 1
        return self._n


def _judge(c: Campaign, res: CampaignResult) -> None:
    g = c.gate
    if g is None or res.mode != "auto":
        res.gate_pass = None
        return
    reasons: list[str] = []
    if not c.goals:
        if res.verdicts.get("malicious", 0):
            reasons.append(f"{res.verdicts['malicious']} malicious verdicts on customer-only traffic")
        if res.enforced_targets:
            reasons.append(f"enforcement on customer traffic: {res.enforced_targets}")
    else:
        if res.first_malicious is None:
            reasons.append("never detected")
        elif res.first_malicious.step > g.detect_within_steps:
            reasons.append(f"detected at step {res.first_malicious.step} > {g.detect_within_steps}")
        if g.contain and res.contained_at is None:
            reasons.append("never contained")
        if len(res.successes) > g.max_successes:
            reasons.append(f"{len(res.successes)} requests reached the app > {g.max_successes}")
    if g.zero_collateral and (res.benign_blocked or res.benign_challenged):
        reasons.append(f"collateral: blocked {sorted(res.benign_blocked)} challenged {sorted(res.benign_challenged)}")
    res.gate_pass = not reasons
    res.gate_reasons = reasons


def run_all(*, modes: tuple[str, ...] = ("auto", "human"), approval_latency_s: float = 300.0, only: Optional[set[str]] = None,
            benign: bool = True, verbose: bool = False, env: Optional[dict[str, Any]] = None) -> list[CampaignResult]:
    out: list[CampaignResult] = []
    for c in CAMPAIGNS:
        if only and c.name not in only:
            continue
        for mode in modes:
            if not c.goals and mode == "human":
                continue
            out.append(Harness(mode=mode, approval_latency_s=approval_latency_s, benign=benign, env=env, verbose=verbose).run(c))
    return out


def _fmt_step(a: Optional[Attempt]) -> str:
    return f"{a.step} ({a.sim_t:.0f}s)" if a else "—"


def render(results: list[CampaignResult]) -> str:
    header = (f"  {'campaign':<22} {'mode':<11} {'detect@step':<12} {'by':<18} {'contain@step':<13} {'reached app':<12} "
              f"{'sensitive':>9} {'collateral':>10} {'p50 ms':>7}  gate")
    lines = [f"=== Purple team: adaptive attacker vs AEGIS — model {model_label()} ===", header]
    for r in results:
        mode = "auto-block" if r.mode == "auto" else f"human@{r.approval_latency_s:.0f}s"
        coll = len(r.benign_blocked) + len(r.benign_challenged)
        reached = f"{len(r.successes)} ({r.successes_after_detection} post)" if r.attempts else "—"
        gate = "PASS" if r.gate_pass else ("FAIL" if r.gate_pass is False else "report")
        by = (r.first_malicious.investigated_by if r.first_malicious else "—")[:18]
        lines.append(f"  {r.campaign:<22} {mode:<11} {_fmt_step(r.first_malicious):<12} {by:<18} {_fmt_step(r.contained_at):<13} "
                     f"{reached:<12} {r.sensitive_reached:>9} {coll:>10} {r.p50_ms():>7.0f}  {gate}")
        for why in r.gate_reasons:
            lines.append(f"      ✗ {why}")
    failed = [r for r in results if r.gate_pass is False]
    gated = [r for r in results if r.gate_pass is not None]
    lines.append(f"  {len(gated) - len(failed)}/{len(gated)} gated campaigns pass; {len(results) - len(gated)} reported only")
    return "\n".join(lines)


__all__ = ["Harness", "CampaignResult", "Attempt", "Attacker", "run_all", "render", "BASE_ENV"]
