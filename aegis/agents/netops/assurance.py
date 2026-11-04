"""Network assurance — faults, topology-aware root cause, alarm suppression, drift. No LLM.

A network outage is one fault and a storm of alarms. A fibre cut on a distribution uplink takes
every access switch behind it off the air: each one reports its uplink down, its neighbours
report adjacency loss, monitoring reports them unreachable — forty alarms for one cause. The
operator needs the one, with the forty folded into it as impact, and the remediation that fixes
the one. That is what this detector does, on the records ``aegis.ingest.netops`` normalises:

  topology    LLDP/CDP rows build the graph; ``role`` (core / distribution / access / wan-edge) comes
              from the row, the inventory, or the hostname (``CORE-``, ``DIST-``, ``ACC-``, ``WAN-``).
              A device's *uplink path* is its shortest path to any core.
  link down   LINK/LINEPROTO/ETHPORT down, or a linkDown trap, on a link the topology knows →
              every device whose uplink path crosses that link is **downstream**. The first alarm is
              the root cause (``link_down``); alarms from downstream devices inside the correlation
              window are **suppressed** into it (counted, sampled), not raised on their own.
  flap        ≥ AEGIS_NET_FLAP_N (5) up/down transitions on one interface inside
              AEGIS_NET_FLAP_WINDOW_S (300) → ``link_flap``, once per episode.
  adjacency   BGP-5-ADJCHANGE / OSPF-5-ADJCHG down (or the traps) → ``adjacency_loss``, unless it is a
              symptom of a link already down or a device already unreachable.
  errors      telemetry: CRC / input-error rate above AEGIS_NET_ERR_PER_MIN (100) over two samples →
              ``interface_errors`` (a dirty optic or bad cable: fix before it flaps).
  congestion  telemetry utilisation ≥ AEGIS_NET_UTIL_PCT (90) on AEGIS_NET_UTIL_SAMPLES (3) consecutive
              samples, or output discards rising with it → ``congestion``.
  unreachable a device whose telemetry stops for AEGIS_NET_SILENT_S (180) → ``device_unreachable``;
              its downstream devices are suppressed the same way. (The service's feed watchdog
              covers "the whole feed went quiet"; this is one device going quiet inside a live feed.)
  drift       a config whose hash differs from the golden (``AEGIS_NET_GOLDEN`` JSON {device: hash},
              or the first config seen when AEGIS_NET_GOLDEN_FIRST_SEEN=1) → ``config_drift``, with
              the change ticket if the record carried one. A change with **no ticket** followed inside
              AEGIS_NET_BAD_PUSH_S (600) by adjacency loss or a link down on the same device →
              ``bad_config_push``: the change is the root cause, the loss is its symptom.

Every alert carries ``netops`` = {fault, device, iface, root_cause, downstream[], suppressed,
symptoms[], users_affected, golden_hash, change_ticket …} for the orchestrator's fast path
(``aegis.agents.orchestrator.netops``), which turns it into a chain with closed-loop remediation
proposals — shadow first, a human approves.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..shared.bounded import BoundedDict

_ROLE_RX = (
    ("core", re.compile(r"\b(core|cr|spine)\b|^core-|^cr\d|-core\d*$", re.I)),
    ("distribution", re.compile(r"\b(dist|distribution|agg|aggregation|leaf)\b|^dist-|^dsw|-dist\d*$", re.I)),
    ("wan-edge", re.compile(r"\b(wan|edge|border|pe|ce|br)\b|^wan-|^edge-|-wan\d*$", re.I)),
    ("access", re.compile(r"\b(acc|access|asw|sw|tor)\b|^acc-|^asw|^sw\d", re.I)),
)
_DOWN_MNEMONICS = {"LINK-3-UPDOWN", "LINEPROTO-5-UPDOWN", "ETHPORT-5-IF_DOWN_LINK_FAILURE", "ETHPORT-5-IF_DOWN_ADMIN_DOWN",
                   "ETHPORT-5-IF_DOWN_ERROR_DISABLED", "PM-4-ERR_DISABLE", "ETHPORT-3-IF_DOWN"}
_ADJ_MNEMONICS = {"BGP-5-ADJCHANGE", "OSPF-5-ADJCHG", "OSPF-5-ADJCHANGE", "ISIS-4-ADJCHANGE", "EIGRP-5-NBRCHANGE", "DUAL-5-NBRCHANGE"}
_RESTART_MNEMONICS = {"SYS-5-RESTART", "SYS-5-RELOAD", "PLATFORM-2-FRU_REMOVED", "ENVM-2-TEMP", "ENVM-2-FAN", "PLATFORM-2-SENSOR"}
_CONFIG_MNEMONICS = {"SYS-5-CONFIG_I", "PARSER-5-CFGLOG_LOGGEDCMD", "VSHD-5-VSHD_SYSLOG_CONFIG_I"}
# %SYS-5-CONFIG_I: Configured from console by rverma on vty0 (10.1.2.3)
_CONFIG_BY_RX = re.compile(r"\bby\s+(?P<user>[A-Za-z0-9._\\@-]+)(?:\s+on\s+\S+)?(?:\s*\((?P<ip>[0-9a-fA-F.:]+)\))?")


def _env_f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def role_of(device: str, hint: str | None = None) -> str:
    if hint:
        h = str(hint).lower()
        for role, _ in _ROLE_RX:
            if role.split("-")[0] in h:
                return role
    for role, rx in _ROLE_RX:
        if rx.search(device or ""):
            return role
    return "unknown"


_TRANSIT_ROLES = {"core", "distribution", "unknown"}     # leaves (access, wan-edge) never forward between others


@dataclass
class _Link:
    a: str
    a_if: str | None
    b: str
    b_if: str | None
    state: str = "up"
    down_since: float | None = None
    transitions: deque = field(default_factory=lambda: deque(maxlen=64))   # (ts, state)
    flap_open_until: float = 0.0

    @property
    def key(self) -> tuple[str, str]:
        return (self.a, self.b) if self.a <= self.b else (self.b, self.a)

    def iface_on(self, device: str) -> str | None:
        return self.a_if if device == self.a else self.b_if if device == self.b else None


@dataclass
class _Incident:
    """One root cause and the symptoms folded into it."""
    fault: str
    device: str
    iface: str | None
    opened: float
    downstream: set[str]
    suppressed: int = 0
    symptoms: list[str] = field(default_factory=list)
    alert_id: str = ""
    closed: float | None = None          # a link_down incident stays open until its link comes back

    def covers(self, device: str, ts: float, window: float) -> bool:
        if device != self.device and device not in self.downstream:
            return False
        if self.fault == "link_down" and self.closed is None:
            return True                  # the link is still down: everything behind it is still a symptom
        return ts <= (self.closed if self.closed is not None else self.opened) + window


def _note_transition(link: "_Link", ts: float, state: str) -> None:
    """Cisco emits %LINK-3-UPDOWN and %LINEPROTO-5-UPDOWN for the same physical transition; count it once."""
    if link.transitions:
        pts, pstate = link.transitions[-1]
        if pstate == state and abs(ts - pts) <= 2.0:
            return
    link.transitions.append((ts, state))


class NetworkAssurance:
    def __init__(self, *, flap_n: int = 5, flap_window_s: float = 300.0, corr_window_s: float = 900.0,
                 err_per_min: float = 100.0, util_pct: float = 90.0, util_samples: int = 3, silent_s: float = 180.0,
                 bad_push_s: float = 600.0, golden: dict[str, str] | None = None, golden_first_seen: bool = False,
                 inventory: dict[str, dict] | None = None, clock: Any = time.time):
        self.flap_n, self.flap_window_s, self.corr_window_s = flap_n, flap_window_s, corr_window_s
        self.err_per_min, self.util_pct, self.util_samples, self.silent_s = err_per_min, util_pct, util_samples, silent_s
        self.bad_push_s, self.golden, self.golden_first_seen = bad_push_s, dict(golden or {}), golden_first_seen
        self.inventory = {k.lower(): v for k, v in (inventory or {}).items()}
        self.clock = clock
        self._lock = threading.RLock()          # observe() holds it and calls add_link(), which takes it again
        self._links: dict[tuple[str, str], list[_Link]] = {}     # parallel links between the same pair are members
        self._adj: dict[str, set[str]] = defaultdict(set)
        self._roles: dict[str, str] = {}
        self._users: dict[str, int] = {}
        self._sites: dict[str, str] = {}
        # per-device state is keyed by the syslog hostname, which anyone who can reach UDP/514 can spoof:
        # capped (least recently written evicted) so a flood of fake hostnames cannot exhaust memory
        _cap = int(os.environ.get("AEGIS_NETOPS_MAX_DEVICES", "20000"))
        # liveness state keeps established devices and churns newcomers (a spoofed-name flood used to evict a
        # real device that had gone silent — the one whose silence is the alert); inventory devices are pinned
        def _inv(d: Any) -> bool:
            return str(d).lower() in self.inventory
        self._iface_link: dict[tuple[str, str], _Link] = BoundedDict(_cap * 8)
        self._incidents: list[_Incident] = []
        self._tele: dict[tuple[str, str], deque] = BoundedDict(_cap * 8)      # (device, iface) -> (ts, counters)
        self._last_seen: dict[str, float] = BoundedDict(_cap, keep_established=True, pinned=_inv)
        self._last_tele: dict[str, float] = BoundedDict(_cap, keep_established=True, pinned=_inv)  # silence: telemetry devices only
        self._last_silence_check = 0.0
        self._unreachable: set[str] = set()
        self._config_hash: dict[str, str] = BoundedDict(_cap)
        self._recent_config: dict[str, dict] = BoundedDict(_cap)               # device -> last change event (for bad-push correlation)
        self._err_open: set[tuple[str, str]] = set()        # bounded by _tele: keys are dropped with it below
        self._cong_open: set[tuple[str, str]] = set()
        self.stats: dict[str, int] = defaultdict(int)

    # ---------------------------------------------------------------- env --
    @classmethod
    def from_env(cls) -> "NetworkAssurance":
        golden: dict[str, str] = {}
        raw = os.environ.get("AEGIS_NET_GOLDEN", "").strip()
        if raw:
            try:
                golden = json.loads(open(raw).read()) if os.path.exists(raw) else json.loads(raw)
            except (OSError, ValueError):
                golden = {}
        inv: dict[str, dict] = {}
        inv_raw = os.environ.get("AEGIS_NET_INVENTORY", "").strip()
        if inv_raw and os.path.exists(inv_raw):
            try:
                rows = json.loads(open(inv_raw).read())
                inv = {str(r.get("device") or r.get("hostname")): r for r in (rows if isinstance(rows, list) else rows.get("devices", []))}
            except (OSError, ValueError):
                inv = {}
        return cls(flap_n=int(_env_f("AEGIS_NET_FLAP_N", 5)), flap_window_s=_env_f("AEGIS_NET_FLAP_WINDOW_S", 300),
                   corr_window_s=_env_f("AEGIS_NET_CORR_WINDOW_S", 900), err_per_min=_env_f("AEGIS_NET_ERR_PER_MIN", 100),
                   util_pct=_env_f("AEGIS_NET_UTIL_PCT", 90), util_samples=int(_env_f("AEGIS_NET_UTIL_SAMPLES", 3)),
                   silent_s=_env_f("AEGIS_NET_SILENT_S", 180), bad_push_s=_env_f("AEGIS_NET_BAD_PUSH_S", 600),
                   golden=golden, golden_first_seen=os.environ.get("AEGIS_NET_GOLDEN_FIRST_SEEN", "").lower() in ("1", "true", "yes"),
                   inventory=inv)

    # ----------------------------------------------------------- topology --
    def _role(self, device: str, hint: str | None = None) -> str:
        r = self._roles.get(device)
        if r and r != "unknown":
            return r
        inv = self.inventory.get(device.lower(), {})
        r = role_of(device, hint or inv.get("role"))
        self._roles[device] = r
        return r

    def add_link(self, a: str, a_if: str | None, b: str, b_if: str | None) -> None:
        with self._lock:
            key = (a, b) if a <= b else (b, a)
            members = self._links.setdefault(key, [])
            link = None
            for m in members:                                   # the same physical link seen from either end
                m_a_if, m_b_if = (m.a_if, m.b_if) if a == m.a else (m.b_if, m.a_if)
                if (a_if is None or m_a_if is None or m_a_if == a_if) and (b_if is None or m_b_if is None or m_b_if == b_if):
                    link = m
                    if a == m.a:
                        m.a_if, m.b_if = m.a_if or a_if, m.b_if or b_if
                    else:
                        m.a_if, m.b_if = m.a_if or b_if, m.b_if or a_if
                    break
            if link is None:
                link = _Link(a, a_if, b, b_if)
                members.append(link)
                self._adj[a].add(b)
                self._adj[b].add(a)
                # LLDP arriving after the first syslog (cold start mid-outage): inherit what the pseudo-link saw
                for dev, ifc in ((a, a_if), (b, b_if)):
                    prev = self._iface_link.get((dev, ifc)) if ifc else None
                    if prev is not None and prev.b.endswith(":peer"):
                        link.state, link.down_since = prev.state, prev.down_since
                        link.transitions.extend(prev.transitions)
            if a_if:
                self._iface_link[(a, a_if)] = link
            if b_if:
                self._iface_link[(b, b_if)] = link

    def _pair_up(self, d: str, n: str, without_link: "_Link | None") -> bool:
        """Two neighbours are connected while ANY member link between them is up (LACP members, dual uplinks)."""
        return any(m.state == "up" and m is not without_link for m in self._links.get((d, n) if d <= n else (n, d), ()))

    def _cores(self) -> set[str]:
        return {d for d in self._adj if self._role(d) == "core"} or {max(self._adj, key=lambda d: len(self._adj[d]))} if self._adj else set()

    def _reachable(self, *, without_link: _Link | None = None, without_device: str | None = None) -> set[str]:
        """Devices with a path to some core over links that are up, optionally with one link or one
        device removed. Reachability, not shortest path: a dual-homed switch that loses one uplink
        still reaches the core over the other, and must not be reported as stranded."""
        cores = self._cores() - ({without_device} if without_device else set())
        seen = set(cores)
        frontier = list(cores)
        while frontier:
            nxt: list[str] = []
            for d in frontier:
                for n in self._adj[d]:
                    if n in seen or n == without_device:
                        continue
                    if not self._pair_up(d, n, without_link):
                        continue
                    seen.add(n)
                    if self._role(n) in _TRANSIT_ROLES:
                        nxt.append(n)           # leaves (access, WAN edge) are reached, never transited:
                                                # a dual-homed access switch is not a backup path between distributions
            frontier = nxt
        return seen

    def _downstream_of_link(self, link: _Link) -> set[str]:
        """Devices that lose their LAST path to a core when this link goes (computed with the link up).
        Empty when a redundant path carries them — that is impact contained, not a quiet failure."""
        before = self._reachable()
        after = self._reachable(without_link=link)
        return (before - after) - {link.a, link.b} if {link.a, link.b} & before else set()

    def _downstream_of_device(self, device: str) -> set[str]:
        before = self._reachable()
        after = self._reachable(without_device=device)
        return (before - after) - {device}

    def _redundant(self, link: _Link) -> bool:
        """Does the far side of this link still reach a core without it?"""
        after = self._reachable(without_link=link)
        return link.a in after and link.b in after

    def _users_behind(self, devices: set[str]) -> int:
        return sum(self._users.get(d, self.inventory.get(d.lower(), {}).get("users", 0) or 0) for d in devices)

    # ------------------------------------------------------------- observe --
    def observe(self, ev: dict) -> list[dict]:
        kind = ev.get("kind")
        now = float(self.clock())
        try:
            ts = float(ev.get("ts") or now)
        except (TypeError, ValueError):
            ts = now
        if ts != ts or ts in (float("inf"), float("-inf")) or ts > now + 30 * 86400 or ts < now - 365 * 86400:
            ts = now                                            # one exporter's absurd clock must not move the estate's "now"
        device = str(ev.get("device") or "unknown")
        out: list[dict] = []
        with self._lock:
            self.stats["events"] += 1
            if device != "unknown" and kind in ("syslog", "trap", "telemetry", "flow", "config"):
                self._last_seen[device] = max(ts, self._last_seen.get(device, 0.0))
                if kind == "telemetry":
                    self._last_tele[device] = max(ts, self._last_tele.get(device, 0.0))
                if device in self._unreachable:
                    self._unreachable.discard(device)
            if kind == "topology":
                self._topology(ev)
            elif kind in ("syslog", "trap"):
                out += self._syslog(ev, ts, device)
            elif kind == "telemetry":
                out += self._telemetry(ev, ts, device)
            elif kind == "config":
                out += self._config(ev, ts, device)
            if ts - self._last_silence_check >= 5.0 or kind == "telemetry":
                self._last_silence_check = ts
                out += self._silence_check(ts)
            self._prune_incidents(ts)
        return out

    def _prune_incidents(self, now: float) -> None:
        if len(self._incidents) > 2000:
            keep = [i for i in self._incidents if i.closed is None and i.fault == "link_down"
                    or now - (i.closed if i.closed is not None else i.opened) <= self.corr_window_s * 2]
            self._incidents = keep[-2000:]

    def _topology(self, ev: dict) -> None:
        a, b = str(ev["device"]), str(ev["neighbor"])
        if ev.get("role"):
            self._roles[a] = role_of(a, ev["role"])
        if ev.get("neighbor_role"):
            self._roles[b] = role_of(b, ev["neighbor_role"])
        if ev.get("site"):
            self._sites[a] = str(ev["site"])
        if ev.get("users") is not None:
            try:
                self._users[a] = int(ev["users"])
            except (TypeError, ValueError):
                pass
        self.add_link(a, ev.get("iface"), b, ev.get("neighbor_iface"))

    # ------------------------------------------------------------- syslog --
    def _syslog(self, ev: dict, ts: float, device: str) -> list[dict]:
        mn, state, iface = str(ev.get("mnemonic") or ""), ev.get("state"), ev.get("iface")
        if mn in _CONFIG_MNEMONICS:
            rc = self._recent_config.get(device)
            if rc is None or ts - float(rc.get("ts") or 0) > self.bad_push_s:
                rc = {"ts": ts, "change_ticket": None, "user": None, "source_ip": None, "msg": ev.get("msg")}   # a stale ticket does not cover a new push
                self._recent_config[device] = rc
            rc["ts"] = ts
            um = _CONFIG_BY_RX.search(str(ev.get("msg") or ""))
            if um:
                rc["user"] = rc.get("user") or um.group("user")
                rc["source_ip"] = rc.get("source_ip") or um.group("ip")
            return []
        if mn in _DOWN_MNEMONICS or (mn.startswith("LINK-") or mn.startswith("LINEPROTO-") or mn.startswith("ETHPORT-")):
            return self._link_event(ts, device, iface, state, ev)
        if mn in _ADJ_MNEMONICS:
            return self._adjacency(ts, device, iface, state, ev)
        if mn in _RESTART_MNEMONICS or mn.split("-")[0] in ("SYS", "PLATFORM", "ENVM") and _sev(ev.get("severity")) <= 2:
            if self._covered(device, ts):
                return []
            return [self._alert("hardware_fault" if mn.startswith(("PLATFORM", "ENVM")) else "device_restart", device, iface, ts,
                                severity="high", root_cause=f"{mn}: {ev.get('msg', '')[:120]}", downstream=set(), ev=ev)]
        return []

    def _link_event(self, ts: float, device: str, iface: str | None, state: str | None, ev: dict) -> list[dict]:
        if not iface or state not in ("up", "down") or device == "unknown":
            return []                   # a line with no hostname cannot be a per-device fault (IOS without `logging origin-id`)
        link = self._iface_link.get((device, iface))
        key = (device, iface)
        known = link is not None and link.b in self._adj and link.a in self._adj
        # downstream is "who loses their path to the core if THIS link goes" — computed while the link
        # still counts as up; once it is marked down those devices have no path at all
        downstream = self._downstream_of_link(link) if (known and state == "down") else set()
        if link is not None:
            _note_transition(link, ts, state)
            prev = link.state
            link.state = state
            if state == "down":
                link.down_since = link.down_since or ts
            else:
                link.down_since = None
                ends, ifaces = {link.a, link.b}, {link.a_if, link.b_if, iface}
                for inc in self._incidents:          # the link is back (reported by EITHER end): close its incident
                    if inc.fault == "link_down" and inc.closed is None and inc.device in ends and inc.iface in ifaces:
                        inc.closed = ts
        else:   # an interface the topology does not know (an edge/access port): track flaps only
            link = self._iface_link.setdefault(key, _Link(device, iface, f"{device}:{iface}:peer", None))
            _note_transition(link, ts, state)
            link.state = state
        # flap: N transitions inside the window
        recent = [t for t, _ in link.transitions if t >= ts - self.flap_window_s]
        if len(recent) >= self.flap_n and ts >= link.flap_open_until:
            link.flap_open_until = ts + self.flap_window_s
            self.stats["flaps"] += 1
            peer_ = (link.b if device == link.a else link.a) if known else None
            return [self._alert("link_flap", device, iface, ts, severity="high",
                                root_cause=f"{len(recent)} up/down transitions on {iface} in {int(self.flap_window_s)} s",
                                downstream=downstream, ev=ev, extra={"transitions": len(recent), "peer": peer_})]
        if state != "down":
            return []
        if not known:
            return []       # an edge / access port the topology does not know: users unplug things all day — flaps only
        # the far end reporting a link that is already down is the same fault seen twice, not a second one
        if prev == "down":
            for inc in reversed(self._incidents):
                if inc.fault == "link_down" and inc.closed is None and {inc.device} <= {link.a, link.b} and inc.device != device:
                    inc.suppressed += 1
                    self.stats["suppressed"] += 1
                    return []
        # down: root cause or symptom? (a second uplink going on a device already in an incident widens it)
        if self._covered(device, ts, downstream):
            return []
        peer = (link.b if device == link.a else link.a) if known else None
        redundant = not downstream and self._redundant(link)
        last_path = downstream and any(i.fault == "link_down" and i.device == device and i.closed is None for i in self._incidents)
        inc = _Incident("link_down", device, iface, ts, downstream)
        self._incidents.append(inc)
        self.stats["link_down"] += 1
        bad_push = self._bad_push_for(device, ts)
        if bad_push is not None:
            return [self._alert("bad_config_push", device, iface, ts, severity="critical", root_cause=bad_push, downstream=downstream,
                                ev=ev, incident=inc, extra={"peer": peer, **self._push_extra(device)})]
        return [self._alert("link_down", device, iface, ts, severity="critical" if downstream else "high" if not redundant else "medium",
                            root_cause=f"{iface} on {device} is down" + (f" (link to {peer})" if peer else "")
                                       + (" — a redundant path is carrying the traffic" if redundant else "")
                                       + (" — the LAST path: the redundant uplink was already down" if last_path else ""),
                            downstream=downstream, ev=ev, incident=inc, extra={"peer": peer, "redundant": redundant, "last_path": bool(last_path)})]

    def _adjacency(self, ts: float, device: str, iface: str | None, state: str | None, ev: dict) -> list[dict]:
        if state != "down":
            return []
        if self._covered(device, ts):
            return []
        peer = ev.get("peer")
        bad_push = self._bad_push_for(device, ts)
        inc = _Incident("adjacency_loss", device, iface, ts, set())
        self._incidents.append(inc)
        self.stats["adjacency_loss"] += 1
        if bad_push is not None:
            return [self._alert("bad_config_push", device, iface, ts, severity="critical", root_cause=bad_push, downstream=set(), ev=ev,
                                incident=inc, extra={"peer": peer, "protocol": str(ev.get("facility") or ""), **self._push_extra(device)})]
        return [self._alert("adjacency_loss", device, iface, ts, severity="high",
                            root_cause=f"{ev.get('facility', 'routing')} adjacency with {peer or 'neighbour'} lost on {device}",
                            downstream=set(), ev=ev, incident=inc, extra={"peer": peer, "protocol": str(ev.get("facility") or "")})]

    def _bad_push_for(self, device: str, ts: float) -> str | None:
        rc = self._recent_config.get(device)
        if not rc or ts - float(rc.get("ts") or 0) > self.bad_push_s:
            return None
        if rc.get("change_ticket"):
            return None                                   # a ticketed change that broke something is still drift, not a bad push
        who = f" by {rc['user']}" if rc.get("user") else ""
        return f"configuration changed on {device}{who} {max(0, int(ts - rc['ts']))} s earlier with no change ticket, then the device lost connectivity"

    def _push_extra(self, device: str) -> dict:
        """Who pushed, from where, when — what the response needs to revoke the right sessions."""
        rc = self._recent_config.get(device) or {}
        return {"user": rc.get("user"), "source_ip": rc.get("source_ip"), "changed_at": rc.get("ts"), "change_ticket": None}

    # ---------------------------------------------------------- telemetry --
    def _telemetry(self, ev: dict, ts: float, device: str) -> list[dict]:
        iface = str(ev.get("iface") or "")
        c = dict(ev.get("counters") or {})
        if not iface or not c:
            return []
        key = (device, iface)
        hist = self._tele.get(key)
        if hist is None:
            if len(self._tele) >= self._tele.maxlen:                # keep the open-state sets in step with _tele
                oldest = next(iter(self._tele))
                self._err_open.discard(oldest); self._cong_open.discard(oldest)
            hist = self._tele[key] = deque(maxlen=8)
        else:
            self._tele.move_to_end(key)
        out: list[dict] = []
        if hist:
            pts, pc = hist[-1]
            dt = max(1.0, ts - pts)
            # error rate per minute over the delta
            err = sum(max(0.0, c.get(k, 0.0) - pc.get(k, 0.0)) for k in ("in_errors", "crc") if k in c and k in pc)
            err_pm = err / dt * 60.0
            if err_pm >= self.err_per_min and len(hist) >= 2:
                if key not in self._err_open and not self._covered(device, ts):
                    self._err_open.add(key)
                    self.stats["interface_errors"] += 1
                    out.append(self._alert("interface_errors", device, iface, ts, severity="medium",
                                           root_cause=f"{err_pm:,.0f} input/CRC errors per minute on {iface}", downstream=set(), ev=ev,
                                           extra={"errors_per_min": round(err_pm, 1)}))
            elif err_pm < self.err_per_min / 4:
                self._err_open.discard(key)
        hist.append((ts, c))
        # utilisation: explicit pct, or derived from octet deltas against speed
        util = c.get("util_pct")
        if util is None and len(hist) >= 2 and c.get("speed_bps"):
            pts, pc = hist[-2]
            dt = max(1.0, ts - pts)
            octets = max(0.0, c.get("in_octets", 0.0) - pc.get("in_octets", 0.0)) + max(0.0, c.get("out_octets", 0.0) - pc.get("out_octets", 0.0))
            util = octets * 8.0 / dt / c["speed_bps"] * 100.0
        if util is not None:
            hist[-1] = (ts, {**c, "_util": util})
            recent = [h[1].get("_util") for h in list(hist)[-self.util_samples:]]
            if len(recent) >= self.util_samples and all(u is not None and u >= self.util_pct for u in recent):
                if key not in self._cong_open:
                    self._cong_open.add(key)
                    self.stats["congestion"] += 1
                    disc = c.get("out_discards")
                    out.append(self._alert("congestion", device, iface, ts, severity="medium",
                                           root_cause=f"{iface} at {min(100.0, max(recent)):.0f}% for {self.util_samples} samples"
                                                      + (f", {disc:,.0f} output discards" if disc else ""),
                                           downstream=set(), ev=ev, extra={"util_pct": round(max(recent), 1)}))
            elif recent and recent[-1] is not None and recent[-1] < self.util_pct * 0.8:
                self._cong_open.discard(key)
        return out

    # ------------------------------------------------------------- config --
    def _config(self, ev: dict, ts: float, device: str) -> list[dict]:
        h = ev.get("config_hash")
        ticket = ev.get("change_ticket")
        self._recent_config[device] = {"ts": ts, "change_ticket": ticket, "user": ev.get("user"), "source_ip": ev.get("source_ip"), "msg": ev.get("msg")}
        if not h:
            return []
        prev = self._config_hash.get(device)
        self._config_hash[device] = str(h)
        golden = self.golden.get(device)
        if golden is None and self.golden_first_seen and prev is None:
            self.golden[device] = str(h)
            return []
        baseline = golden if golden is not None else prev
        if baseline is None or str(h) == str(baseline):
            return []
        self.stats["config_drift"] += 1
        return [self._alert("config_drift", device, None, ts, severity="medium" if ticket else "high",
                            root_cause=(f"running config on {device} differs from the golden" if golden is not None
                                        else f"running config on {device} changed") + (f" (ticket {ticket})" if ticket else " with no change ticket"),
                            downstream=set(), ev=ev, extra={"golden_hash": str(baseline)[:16], "config_hash": str(h)[:16],
                                                            "change_ticket": ticket, "user": ev.get("user"), "source_ip": ev.get("source_ip")})]

    # ------------------------------------------------------------ silence --
    def _silence_check(self, now: float) -> list[dict]:
        out: list[dict] = []
        # only devices that stream telemetry can be "silent"; a syslog-only switch is quiet for days when healthy
        for device, tele_seen in list(self._last_tele.items()):
            seen = max(tele_seen, self._last_seen.get(device, 0.0))      # any sign of life counts once we expect telemetry
            if device in self._unreachable or now - seen < self.silent_s or device not in self._adj:
                continue
            if self._covered(device, now):
                self._unreachable.add(device)
                continue
            self._unreachable.add(device)
            downstream = self._downstream_of_device(device)
            inc = _Incident("device_unreachable", device, None, now, downstream)
            self._incidents.append(inc)
            self.stats["device_unreachable"] += 1
            out.append(self._alert("device_unreachable", device, None, now, severity="critical" if downstream else "high",
                                   root_cause=f"{device} has sent nothing for {int(now - seen)} s", downstream=downstream,
                                   extra={"silent_s": int(now - seen)}, incident=inc))
        return out

    # --------------------------------------------------------- correlate --
    def _covered(self, device: str, ts: float, downstream: set[str] | None = None) -> bool:
        """Is this device inside an open incident's blast radius? Then its alarm is a symptom — unless it
        strands devices that incident did not (the LAST redundant path going): that is a new, wider fault."""
        for inc in reversed(self._incidents):
            if inc.covers(device, ts, self.corr_window_s):
                if downstream and not downstream <= inc.downstream:
                    return False
                inc.suppressed += 1
                if len(inc.symptoms) < 8:
                    inc.symptoms.append(device)
                self.stats["suppressed"] += 1
                return True
        return False

    # ---------------------------------------------------------- checkpoint --
    STATE_VERSION = 1

    def snapshot(self) -> dict:
        """Everything a restart must not forget: links and their state, open and recent incidents, who was last
        seen when, learned roles/users/sites, recent config pushes. Counters and telemetry history are not
        needed — a minute of fresh samples rebuilds them."""
        with self._lock:
            now = float(self.clock())
            links = []
            for (a, b), members in self._links.items():
                for m in members:
                    links.append({"a": m.a, "a_if": m.a_if, "b": m.b, "b_if": m.b_if, "state": m.state, "down_since": m.down_since,
                                  "transitions": [list(x) for x in list(m.transitions)[-16:]], "flap_open_until": m.flap_open_until})
            pseudo = [{"a": l.a, "a_if": l.a_if, "b": l.b, "state": l.state, "down_since": l.down_since, "transitions": [list(x) for x in list(l.transitions)[-16:]]}
                      for (dev, ifc), l in self._iface_link.items() if l.b.endswith(":peer")]
            incidents = [{"fault": i.fault, "device": i.device, "iface": i.iface, "opened": i.opened, "downstream": sorted(i.downstream),
                          "suppressed": i.suppressed, "symptoms": list(i.symptoms), "alert_id": i.alert_id, "closed": i.closed}
                         for i in self._incidents if i.closed is None or now - i.closed <= self.corr_window_s * 2]
            return {"version": self.STATE_VERSION, "saved_at": now, "links": links, "pseudo_links": pseudo, "incidents": incidents,
                    "roles": dict(self._roles), "users": dict(self._users), "sites": dict(self._sites), "last_seen": dict(self._last_seen),
                    "last_tele": dict(self._last_tele), "unreachable": sorted(self._unreachable), "recent_config": self._recent_config,
                    "config_hash": dict(self._config_hash), "stats": dict(self.stats)}

    def restore(self, snap: dict) -> int:
        """Load a snapshot taken by the previous process. Returns the number of open incidents carried over.
        A snapshot from another version, or a corrupt one, is ignored (the detector then relearns)."""
        if not isinstance(snap, dict) or snap.get("version") != self.STATE_VERSION:
            return 0
        with self._lock:
            self._roles.update({str(k): str(v) for k, v in (snap.get("roles") or {}).items()})
            self._users.update({str(k): int(v) for k, v in (snap.get("users") or {}).items()})
            self._sites.update({str(k): str(v) for k, v in (snap.get("sites") or {}).items()})
            for l in snap.get("links") or []:
                self.add_link(str(l["a"]), l.get("a_if"), str(l["b"]), l.get("b_if"))
                link = self._iface_link.get((str(l["a"]), l.get("a_if"))) or self._iface_link.get((str(l["b"]), l.get("b_if")))
                if link is None:
                    continue
                link.state = str(l.get("state") or "up"); link.down_since = l.get("down_since"); link.flap_open_until = float(l.get("flap_open_until") or 0)
                link.transitions.clear(); link.transitions.extend((float(a), str(b)) for a, b in l.get("transitions") or [])
            for l in snap.get("pseudo_links") or []:
                pl = _Link(str(l["a"]), l.get("a_if"), str(l["b"]), None, state=str(l.get("state") or "up"), down_since=l.get("down_since"))
                pl.transitions.extend((float(a), str(b)) for a, b in l.get("transitions") or [])
                self._iface_link[(pl.a, pl.a_if)] = pl
            n = 0
            for i in snap.get("incidents") or []:
                inc = _Incident(str(i["fault"]), str(i["device"]), i.get("iface"), float(i["opened"]), set(i.get("downstream") or []),
                                int(i.get("suppressed") or 0), list(i.get("symptoms") or []), str(i.get("alert_id") or ""), i.get("closed"))
                self._incidents.append(inc)
                n += inc.closed is None
            self._last_seen.update({str(k): float(v) for k, v in (snap.get("last_seen") or {}).items()})
            self._last_tele.update({str(k): float(v) for k, v in (snap.get("last_tele") or {}).items()})
            self._unreachable.update(str(x) for x in snap.get("unreachable") or [])
            self._recent_config.update(snap.get("recent_config") or {})
            self._config_hash.update({str(k): str(v) for k, v in (snap.get("config_hash") or {}).items()})
            for k, v in (snap.get("stats") or {}).items():
                self.stats[str(k)] += int(v)
            return int(n)

    def checkpoint(self, path: "str | os.PathLike[str]") -> None:
        """Write the snapshot atomically (tmp + rename) so a crash mid-write leaves the previous checkpoint intact."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(self.snapshot(), separators=(",", ":")))
        os.replace(tmp, p)

    def restore_from(self, path: "str | os.PathLike[str]") -> int:
        p = Path(path)
        try:
            return self.restore(json.loads(p.read_text()))
        except (OSError, ValueError):
            return 0

    def incident_for(self, alert_id: str) -> dict | None:
        with self._lock:
            return self._incident_for(alert_id)

    def _incident_for(self, alert_id: str) -> dict | None:
        for inc in self._incidents:
            if inc.alert_id == alert_id:
                return {"suppressed": inc.suppressed, "symptoms": list(inc.symptoms), "downstream": sorted(inc.downstream)}
        return None

    def incidents(self) -> list[dict]:
        """Open and past incidents with the symptoms folded into each — what the console shows as one row."""
        with self._lock:
            return [{"alert_id": i.alert_id, "fault": i.fault, "device": i.device, "iface": i.iface, "opened": i.opened,
                     "downstream": sorted(i.downstream), "suppressed": i.suppressed, "symptoms": list(i.symptoms)}
                    for i in self._incidents]

    def _alert(self, fault: str, device: str, iface: str | None, ts: float, *, severity: str, root_cause: str,
               downstream: set[str], ev: dict | None = None, incident: _Incident | None = None, extra: dict | None = None) -> dict:
        digest = hashlib.sha1(f"{fault}|{device}|{iface}|{ts:.3f}|{root_cause}".encode()).hexdigest()[:10]
        aid = f"net-{fault}-{digest}"
        if incident is not None:
            incident.alert_id = aid
        users = self._users_behind(downstream | {device}) if downstream else self._users.get(device, 0)
        return {
            "id": aid, "source": "Network Assurance", "alert_type": "network_fault", "severity": severity,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)), "device": device, "iface": iface,
            "site": self._sites.get(device), "role": self._role(device),
            "netops": {"fault": fault, "device": device, "iface": iface, "role": self._role(device), "root_cause": root_cause,
                       "downstream": sorted(downstream)[:64], "downstream_count": len(downstream),
                       "users_affected": users, "suppressed": incident.suppressed if incident else 0,
                       "symptoms": list(incident.symptoms) if incident else [], "mnemonic": (ev or {}).get("mnemonic"),
                       "msg": (ev or {}).get("msg"), **(extra or {})},
            "note": f"{fault.replace('_', ' ')}: {root_cause}",
        }


__all__ = ["NetworkAssurance", "role_of"]


def _sev(v: object) -> int:
    """Syslog severity; 0 (emergency) is the most severe, not "missing" (round 7 D-7 — ``0 or 5`` was 5)."""
    if v is None or v == "":
        return 5
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 5
