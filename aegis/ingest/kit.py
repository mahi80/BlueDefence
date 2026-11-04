"""Declarative connectors: a pull connector is a YAML spec plus a recorded sample, not new code.

A spec (``aegis/ingest/connectors/<name>.yaml``) says how to authenticate, what to request, where the records are
in the response, how to page, what the watermark is, and how each record becomes an AEGIS alert — either a field
map onto the alert shape the specialists read, or ``format: ocsf`` (the record IS an OCSF event, see ``ocsf.py``).
One generic consumer runs them all, with the same dedupe / watermark / poison handling as every other source.

    AEGIS_SOURCES=kit:okta,kit:sentinelone            # in the service, like any other source
    python -m aegis.ingest.kit list                    # the catalogue, with each spec's verification level
    python -m aegis.ingest.kit test okta               # replay the recorded sample through the mapping (no network)
    python -m aegis.ingest.kit pull okta --limit 5     # one live pull (needs the spec's env vars)

Safety, enforced here rather than trusted to each spec:

* **read-only** — a spec must declare ``read_only: true``; only GET, and POST to search endpoints the spec names,
  are allowed (no PUT / PATCH / DELETE). Pulling alerts must never change the vendor.
* **secrets from the environment only** — ``{env:NAME}`` placeholders; a literal credential in a spec is refused.
* **https only** (http only to loopback), bounded pages / records / response size, timeouts, no redirects followed
  to another host.
* **verification is stated, not implied** — each spec carries ``verified: recorded-sample | live-tenant`` and the
  date; ``list`` prints it, so the catalogue never claims more than was tested.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .base import AlertCheckpoint, BaseConsumer, normalize_severity, severity_to_score

logger = logging.getLogger("aegis.ingest.kit")

SPEC_DIR = Path(__file__).with_name("connectors")
MAX_PAGES = 50
MAX_RECORDS = 10_000
MAX_BODY = 32 * 1024 * 1024
#: transport(method, url, body_bytes|None, headers) -> (status, response headers (lower-cased), text)
Transport = Callable[[str, str, bytes | None, dict], tuple[int, dict, str]]


class SpecError(ValueError):
    pass


# ------------------------------------------------------------------------------------------------- the spec --

def load_spec(name_or_path: str | Path) -> dict:
    import yaml
    p = Path(name_or_path)
    if not p.suffix:
        p = SPEC_DIR / f"{name_or_path}.yaml"
    if not p.exists():
        raise SpecError(f"no connector spec {p}")
    spec = yaml.safe_load(p.read_text(encoding="utf-8"))
    validate_spec(spec, where=str(p))
    spec["_path"] = str(p)
    return spec


_SECRETISH = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|apikey|authorization|credential)")
# a credential written into a URL / query string: ...?api_key=abc, token=abc (not {env:...})
_SECRET_IN_TEXT = re.compile(r"(?i)(?:token|secret|password|api[_-]?key|apikey|sig|signature)=(?!\{env:)[^&\s{]+")


def validate_spec(spec: Any, *, where: str = "spec") -> None:
    if not isinstance(spec, dict):
        raise SpecError(f"{where}: not a mapping")
    for k in ("name", "title", "read_only", "request", "verified"):
        if k not in spec:
            raise SpecError(f"{where}: missing {k!r}")
    if spec["read_only"] is not True:
        raise SpecError(f"{where}: pull connectors must declare read_only: true")
    req = spec["request"]
    method = str(req.get("method", "GET")).upper()
    if method not in ("GET", "POST"):
        raise SpecError(f"{where}: method {method} is not allowed (read-only connectors use GET / POST search)")
    if method == "POST" and not req.get("search_endpoint"):
        raise SpecError(f"{where}: a POST must be marked search_endpoint: true (a read-only query API)")
    if spec.get("format", "map") not in ("map", "ocsf"):
        raise SpecError(f"{where}: format must be map or ocsf")
    if spec.get("format", "map") == "map" and not isinstance(spec.get("map"), dict):
        raise SpecError(f"{where}: format map needs a map: section")
    # a credential written into the spec instead of {env:…}
    def walk(o: Any, path: str) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, f"{path}.{k}")
                if _SECRETISH.search(str(k)) and isinstance(v, str) and v and "{env:" not in v:
                    raise SpecError(f"{where}: {path}.{k} looks like a literal credential — use {{env:NAME}}")
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{path}[{i}]")
        elif isinstance(o, str) and _SECRET_IN_TEXT.search(o):
            raise SpecError(f"{where}: {path} carries a literal credential in a URL / query — use {{env:NAME}}")
    # every part of the spec that reaches the wire or the context, not only auth + headers (round 6 I-10)
    walk(spec.get("auth") or {}, "auth")
    walk(req, "request")
    walk(spec.get("config") or {}, "config")
    # every credential-carrying auth field must come from the environment, whatever it is called
    for k, v in (spec.get("auth") or {}).items():
        if k not in ("type", "name", "token_url", "scope", "audience", "resource") and isinstance(v, str) \
                and "{env:" not in v:
            raise SpecError(f"{where}: auth.{k} must come from the environment ({{env:NAME}}), not the spec")


def catalogue() -> list[dict]:
    out = []
    for p in sorted(SPEC_DIR.glob("*.yaml")):
        try:
            s = load_spec(p)
            out.append({"name": s["name"], "title": s["title"], "category": s.get("category", ""),
                        "format": s.get("format", "map"), "verified": s["verified"], "docs": s.get("docs", "")})
        except SpecError as e:
            out.append({"name": p.stem, "error": str(e)})
    return out


# ----------------------------------------------------------------------------------------------- templating --

_TOKEN = re.compile(r"\{(env:[A-Z0-9_]+|[a-z_]+)\}")


def render(value: Any, ctx: dict, env: dict) -> Any:
    """``{env:NAME}`` from the environment, ``{name}`` from ``ctx`` (watermark, cursor, config …), recursively."""
    if isinstance(value, dict):
        return {k: render(v, ctx, env) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx, env) for v in value]
    if not isinstance(value, str):
        return value
    whole = _TOKEN.fullmatch(value)
    if whole and not whole.group(1).startswith("env:") and whole.group(1) in ctx:
        return ctx[whole.group(1)]                          # "{page_size}" alone keeps its type (an int in a JSON body)

    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key.startswith("env:"):
            name = key[4:]
            if name not in env or not str(env[name]).strip():
                raise SpecError(f"environment variable {name} is not set")
            return str(env[name])
        if key not in ctx:
            raise SpecError(f"unknown placeholder {{{key}}}")
        return str(ctx[key])
    return _TOKEN.sub(sub, value)


# --------------------------------------------------------------------------------------------------- paths --

_PART = re.compile(r"\[(\d+)\]|\[([^=\]]+)=([^\]]*)\]|([^.\[\]]+)")


def _parts(path: str) -> list[tuple]:
    out: list[tuple] = []
    for m in _PART.finditer(path):
        idx, fk, fv, name = m.groups()
        out.append(("i", int(idx)) if idx is not None else ("f", fk, fv) if fk is not None else ("k", name))
    return out


def _walk(cur: Any, parts: list[tuple]) -> Any:
    if not parts:
        return cur
    kind = parts[0][0]
    if kind == "k":
        if not isinstance(cur, dict):
            return None
        # longest literal key first: Elastic / ECS documents often hold flattened keys ("kibana.alert.rule.name")
        j = 0
        while j < len(parts) and parts[j][0] == "k":
            j += 1
        for end in range(j, 0, -1):
            key = ".".join(p[1] for p in parts[:end])
            if key in cur:
                v = _walk(cur[key], parts[end:])
                if v is not None:
                    return v
        return None
    if kind == "i":
        return _walk(cur[parts[0][1]], parts[1:]) if isinstance(cur, list) and parts[0][1] < len(cur) else None
    if not isinstance(cur, list):
        return None
    for x in cur:
        if isinstance(x, dict) and str(x.get(parts[0][1])) == parts[0][2]:
            return _walk(x, parts[1:])
    return None


def get_path(obj: Any, path: str) -> Any:
    """``a.b[0].c``, ``evidence[@odata.type=#microsoft.graph.security.ipEvidence].ipAddress`` (first match),
    flattened dotted keys (``kibana.alert.rule.name`` as one key), and ``x|y`` alternatives (first non-empty).
    ``$`` is the record itself."""
    for alt in str(path).split("|"):
        alt = alt.strip()
        if alt == "$":
            return obj
        v = _walk(obj, _parts(alt))
        if v not in (None, "", [], {}):
            return v
    return None


# ---------------------------------------------------------------------------------------------- transport --

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:          # a 3xx is an error, never a silent hop
        return None


def urllib_transport(timeout: float = 30.0) -> Transport:
    opener = urllib.request.build_opener(_NoRedirect)

    def t(method: str, url: str, body: bytes | None, headers: dict) -> tuple[int, dict, str]:
        _check_url(url)
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with opener.open(req, timeout=timeout) as r:
                data = r.read(MAX_BODY + 1)
                return r.status, {k.lower(): v for k, v in r.headers.items()}, data[:MAX_BODY].decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read(65536).decode("utf-8", "replace")
    return t


def _check_url(url: str) -> None:
    u = urllib.parse.urlsplit(url)
    if u.scheme == "https":
        return
    if u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost", "::1"):
        return
    raise SpecError(f"refusing {u.scheme}:// to {u.hostname}: connectors use https")


# ------------------------------------------------------------------------------------------------ the pull --

def _fmt_time(t: datetime, how: str) -> Any:
    if how == "epoch_ms":
        return int(t.timestamp() * 1000)
    if how == "epoch":
        return int(t.timestamp())
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_time(v: Any) -> datetime | None:
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, UTC)
    if isinstance(v, str) and v.strip():
        try:
            d = datetime.fromisoformat(v.strip())
            return d if d.tzinfo else d.replace(tzinfo=UTC)
        except ValueError:
            return None
    return None


FUTURE_SKEW_S = 300.0


def _origin(url: str) -> tuple[str, str, int | None]:
    u = urllib.parse.urlsplit(url)
    try:
        port = u.port or (443 if u.scheme == "https" else 80 if u.scheme == "http" else None)
    except ValueError:
        port = -1
    return u.scheme.lower(), (u.hostname or "").lower(), port


class KitConsumer(BaseConsumer):
    """Runs one declarative spec as a source.

    The watermark is committed once per completed pass, from the records the pass read (not per alert): a pass cut
    short by an error re-reads from the old watermark (round 6 I-5). A pass that hits its cap — a page with no
    paging, ``max_pages`` or ``MAX_RECORDS`` — leaves a resume point at its newest record, and the next pass starts
    there instead of re-reading the overlap: with more records in the overlap window than one pass returns, every
    pass used to re-read the same duplicates and the feed went blind (I-1). Timestamps beyond now + 5 min never
    move the watermark (I-6)."""

    advance_per_alert = False

    def __init__(self, spec: dict | str, *, checkpoint: AlertCheckpoint | None = None,
                 transport: Transport | None = None, env: dict | None = None, clock: Callable[[], float] = time.time):
        super().__init__(checkpoint)
        self.spec = load_spec(spec) if isinstance(spec, str) else spec
        validate_spec(self.spec, where=self.spec.get("name", "spec"))
        self.name = f"kit-{self.spec['name']}"
        self._t = transport or urllib_transport(float(self.spec.get("timeout_s", 30)))
        self._env = os.environ if env is None else env
        self._clock = clock
        self._token: tuple[str, float] | None = None
        self._future_warned = False

    # -- auth
    def _auth_headers(self) -> dict:
        a = self.spec.get("auth") or {}
        kind = a.get("type", "none")
        if kind == "none":
            return {}
        if kind == "header":
            return {str(a["name"]): render(a["value"], {}, self._env)}
        if kind == "basic":
            raw = f"{render(a['username'], {}, self._env)}:{render(a['password'], {}, self._env)}".encode()
            return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
        if kind == "oauth2_client_credentials":
            if self._token is None or self._token[1] <= self._clock() + 60:
                form = {"grant_type": "client_credentials", "client_id": render(a["client_id"], {}, self._env),
                        "client_secret": render(a["client_secret"], {}, self._env)}
                for k in ("scope", "audience", "resource"):
                    if a.get(k):
                        form[k] = render(a[k], {}, self._env)
                url = render(a["token_url"], {}, self._env)
                st, _h, text = self._t("POST", url, urllib.parse.urlencode(form).encode(),
                                       {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
                if st != 200:
                    raise SpecError(f"{self.spec['name']}: token endpoint answered HTTP {st}")
                tok = json.loads(text)
                self._token = (str(tok["access_token"]), self._clock() + float(tok.get("expires_in", 3600)))
            return {"Authorization": f"Bearer {self._token[0]}"}
        raise SpecError(f"unknown auth type {kind!r}")

    # -- fetch
    def _context(self) -> dict:
        wm_cfg = self.spec.get("watermark") or {}
        how = wm_cfg.get("format", "iso")
        wm = _parse_time(self.checkpoint.watermark(self.name)) if self.checkpoint is not None else None
        now = datetime.fromtimestamp(self._clock(), UTC)
        if wm is not None and wm > now + timedelta(seconds=FUTURE_SKEW_S):
            wm = now                                     # a watermark persisted before the cap existed
        overlap = float(wm_cfg.get("overlap_s", 300))
        resume = self.checkpoint.aux(f"{self.name}:resume") if self.checkpoint is not None else None
        rt = _parse_time(resume.get("ts")) if isinstance(resume, dict) else None
        if rt is not None:
            # the last pass was capped: carry on from its newest record (1 ms before it, so ties are re-read and
            # deduped; strictly at it once a pass made no progress, so a cap's worth of same-millisecond records
            # can never pin the feed)
            start = rt if resume.get("strict") else rt - timedelta(milliseconds=1)
        else:
            start = (wm - timedelta(seconds=overlap)) if wm else \
                now - timedelta(seconds=float(wm_cfg.get("initial_lookback_s", 3600)))
        ctx = {"watermark": _fmt_time(start, how), "now": _fmt_time(datetime.fromtimestamp(self._clock(), UTC), how),
               "page_size": int(self.spec.get("page_size", 200))}
        for k, v in (self.spec.get("config") or {}).items():
            ctx[k] = render(v, {}, self._env)
        return ctx

    def _record_time(self, r: Any) -> datetime | None:
        if not isinstance(r, dict):
            return None
        path = (self.spec.get("watermark") or {}).get("field") or (
            "time" if self.spec.get("format") == "ocsf" else (self.spec.get("map") or {}).get("timestamp"))
        t = _parse_time(get_path(r, path)) if path else None
        if t is None:
            return None
        if t > datetime.fromtimestamp(self._clock(), UTC) + timedelta(seconds=FUTURE_SKEW_S):
            if not self._future_warned:
                self._future_warned = True
                logger.warning("[ingest:%s] record stamped %s is in the future; it does not move the watermark",
                               self.name, t.isoformat())
            return None
        return t

    def fetch(self, **kw: Any) -> Iterator[Any]:
        newest: list[datetime] = []
        capped = [False]
        for r in self._fetch_pages(capped):
            t = self._record_time(r)
            if t is not None and (not newest or t > newest[0]):
                newest[:] = [t]
            yield r
        # the whole pass was read and handled (a generator resumes only after the caller took the last record)
        if self.checkpoint is None or not newest:
            return
        key = f"{self.name}:resume"
        if capped[0]:
            prev = self.checkpoint.aux(key)
            prev_t = _parse_time(prev.get("ts")) if isinstance(prev, dict) else None
            strict = prev_t is not None and newest[0] <= prev_t
            logger.warning("[ingest:%s] pass hit its cap — resuming from %s next cycle%s", self.name,
                           newest[0].isoformat(), " (strictly after: the last pass made no progress)" if strict else "")
            self.checkpoint.set_aux(key, {"ts": newest[0].isoformat(), "strict": strict})
        else:
            self.checkpoint.set_aux(key, None)
        self.checkpoint.advance(self.name, newest[0].isoformat())

    def _fetch_pages(self, capped: list[bool]) -> Iterator[Any]:
        req = self.spec["request"]
        paging = self.spec.get("paging") or {"type": "none"}
        ctx = self._context()
        url = render(req["url"], ctx, self._env)
        params = render(req.get("params") or {}, ctx, self._env)
        body_t = req.get("body")
        n = 0
        cursor: Any = None
        offset = 0
        max_pages = int(self.spec.get("max_pages", MAX_PAGES))
        for _page in range(max_pages):
            pctx = {**ctx, "cursor": cursor if cursor is not None else "", "offset": offset}
            q = dict(params)
            if paging.get("type") in ("cursor", "offset") and _page > 0:
                q[paging["param"]] = cursor if paging["type"] == "cursor" else offset
            full = url if not q else url + ("&" if "?" in url else "?") + urllib.parse.urlencode(q, doseq=True)
            headers = {"Accept": "application/json", **render(req.get("headers") or {}, pctx, self._env),
                       **self._auth_headers()}
            if paging.get("type") == "range":
                headers["Range"] = f"items={offset}-{offset + int(ctx['page_size']) - 1}"
            body = None
            if body_t is not None:
                body = json.dumps(render(body_t, pctx, self._env)).encode()
                headers["Content-Type"] = "application/json"
            st, rh, text = self._t(str(req.get("method", "GET")).upper(), full, body, headers)
            if st == 429 or st >= 500:
                raise RuntimeError(f"{self.spec['name']}: HTTP {st} — retried next cycle")
            if st not in (200, 206):
                raise RuntimeError(f"{self.spec['name']}: HTTP {st}: {text[:200]}")
            data = json.loads(text) if text.strip() else []
            records = get_path(data, self.spec.get("records", "$")) if self.spec.get("records", "$") != "$" else data
            if isinstance(records, dict):
                records = [records]
            records = records if isinstance(records, list) else []
            for r in records:
                yield r
                n += 1
                if n >= MAX_RECORDS:
                    capped[0] = True
                    return
            kind = paging.get("type", "none")
            if _page == max_pages - 1 and records:
                capped[0] = True                          # a next page may exist that this pass will not read
            if kind == "link_header":
                m = re.search(r'<([^>]+)>;\s*rel="next"', rh.get("link", ""))
                if not m or not records:
                    return
                url, params = m.group(1), {}
                if _origin(url) != _origin(full):
                    return                     # never follow a next link to another host, port or scheme (I-11)
            elif kind == "next_url":
                nxt = get_path(data, paging["path"])
                if not nxt or not records:
                    return
                if _origin(str(nxt)) != _origin(full):
                    return
                url, params = str(nxt), {}
            elif kind == "cursor":
                cursor = get_path(data, paging["path"])
                if not cursor or not records:
                    return
            elif kind in ("offset", "range"):
                if len(records) < int(ctx["page_size"]):
                    return
                offset += len(records)
            else:
                if len(records) >= int(ctx["page_size"]):
                    capped[0] = True                      # no paging and a full page: there may be more
                return

    # -- map
    def normalize(self, record: Any) -> dict | None:
        if not isinstance(record, dict):
            return None
        if self.spec.get("format") == "ocsf":
            from .ocsf import to_alert
            a = to_alert(record, source_hint=self.spec["title"])
            if a is not None:
                a["connector"] = self.spec["name"]
                try:
                    from aegis.detect.sigma import enrich
                    enrich(a, record)              # Sigma rules (AEGIS_SIGMA_RULES; off when unset)
                except Exception as e:  # noqa: BLE001 — a detector failure never drops the alert
                    logger.warning("[kit] sigma enrichment failed: %s", str(e)[:160])
            return a
        m = self.spec["map"]
        alert: dict[str, Any] = dict(self.spec.get("constants") or {})
        for field, path in m.items():
            if field == "severity":
                continue
            v = get_path(record, path)
            if v is not None:
                alert[field] = v if isinstance(v, (str, int, float, bool, list)) else json.dumps(v, default=str)[:2000]
        if "id" not in alert:
            return None
        alert["id"] = f"{self.spec['name']}:{str(alert['id'])[:160]}"
        sev_raw = get_path(record, m["severity"]) if "severity" in m else None
        table = {str(k).lower(): v for k, v in (self.spec.get("severity_map") or {}).items()}
        sev = table.get(str(sev_raw).lower(), sev_raw) if sev_raw is not None else alert.get("severity")
        alert["severity"] = normalize_severity(sev) if sev is not None else "medium"
        alert.setdefault("anomaly_score", severity_to_score(alert["severity"]))
        ts = _parse_time(alert.get("timestamp"))
        if ts is not None:
            alert["timestamp"] = ts.isoformat()
        alert.setdefault("source", self.spec["title"])
        alert["connector"] = self.spec["name"]
        raw = json.dumps(record, default=str)
        alert["raw"] = record if len(raw) <= 16_000 else {"truncated": True, "head": raw[:16_000]}
        return alert


def consumer_for(name: str, *, checkpoint: AlertCheckpoint | None = None, **kw: Any) -> KitConsumer:
    return KitConsumer(load_spec(name), checkpoint=checkpoint, **kw)


# ---------------------------------------------------------------------------------------------------- tests --

def sample_transport(spec: dict) -> Transport:
    """Replays ``<name>.sample.json`` (``{"token": {...}?, "pages": [{"status", "headers", "body"}, …]}``)."""
    p = Path(spec["_path"]).with_suffix(".sample.json")
    sample = json.loads(p.read_text(encoding="utf-8"))
    pages = list(sample["pages"])
    calls: list[tuple[str, str]] = []

    def t(method: str, url: str, body: bytes | None, headers: dict) -> tuple[int, dict, str]:
        calls.append((method, url))
        if "token" in sample and body and b"grant_type=client_credentials" in body:
            return 200, {}, json.dumps(sample["token"])
        if not pages:
            return 200, {}, "[]"
        pg = pages.pop(0)
        return int(pg.get("status", 200)), {k.lower(): v for k, v in (pg.get("headers") or {}).items()}, json.dumps(pg["body"])
    t.calls = calls  # type: ignore[attr-defined]
    return t


def replay(name: str) -> list[dict]:
    spec = load_spec(name)
    sample = json.loads(Path(spec["_path"]).with_suffix(".sample.json").read_text(encoding="utf-8"))
    env = {k: (sample.get("base_url", "https://vendor.example") if k.endswith("_URL") else "x")
           for k in re.findall(r"\{env:([A-Z0-9_]+)\}", Path(spec["_path"]).read_text(encoding="utf-8"))}
    c = KitConsumer(spec, transport=sample_transport(spec), env=env)
    return list(c.iter_alerts())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Declarative pull connectors.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    t = sub.add_parser("test"); t.add_argument("name")
    p = sub.add_parser("pull"); p.add_argument("name"); p.add_argument("--limit", type=int, default=5)
    a = ap.parse_args(argv)
    if a.cmd == "list":
        for c in catalogue():
            print(f"  {c['name']:<18} {c.get('category', ''):<10} {c.get('format', ''):<5} "
                  f"{c.get('verified', c.get('error', ''))}  {c.get('title', '')}")
        return 0
    if a.cmd == "test":
        alerts = replay(a.name)
        for al in alerts[:5]:
            print(json.dumps({k: v for k, v in al.items() if k not in ("raw", "ocsf")}, default=str)[:400])
        print(f"  {len(alerts)} alert(s) from the recorded sample")
        return 0 if alerts else 1
    c = consumer_for(a.name)
    for i, al in enumerate(c.iter_alerts()):
        print(json.dumps({k: v for k, v in al.items() if k not in ("raw", "ocsf")}, default=str)[:400])
        if i + 1 >= a.limit:
            break
    return 0


__all__ = ["KitConsumer", "SpecError", "catalogue", "consumer_for", "get_path", "load_spec", "replay", "validate_spec"]

if __name__ == "__main__":
    sys.exit(main())
