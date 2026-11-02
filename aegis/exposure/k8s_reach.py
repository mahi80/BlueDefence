"""Kubernetes reachability for the exposure engine: which workloads the internet can reach, and how.

One asset per workload (Deployment / StatefulSet / DaemonSet, plus bare Pods and ReplicaSets with no
owner). Internet paths:

* a ``LoadBalancer`` Service selecting the workload, unless annotated as an internal load balancer
  (AWS / Azure / GCP annotations recognised) → the Service's target port;
* an ``Ingress`` routing to such a Service, unless internal (``alb.ingress.kubernetes.io/scheme:
  internal``, an internal ingress class) → the target port behind it; a WAF annotation on the Ingress
  (AWS WAFv2 ACL, ModSecurity, App Gateway WAF policy) counts as a WAF in front;
* a ``NodePort`` Service only when the nodes are known to be public (``public_nodes=True``).

Lateral traffic: in a namespace with no NetworkPolicy every pod in the cluster can reach the workload.
A namespace that has any NetworkPolicy is treated as restricting lateral traffic — policy rules are
not evaluated yet, so this errs towards *isolated* for those namespaces; the README says so.

Container images are part of each asset's identity, so Trivy image findings land on the workloads
running that image.
"""

from __future__ import annotations

from ..agents.orchestrator.walkers.graph import SENSITIVITY
from .engine import Asset
from .loaders import _image_keys

WORKLOADS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod"}
INTERNAL_LB_ANNOTATIONS = {
    "service.beta.kubernetes.io/aws-load-balancer-internal": {"true", "0.0.0.0/0"},
    "service.beta.kubernetes.io/aws-load-balancer-scheme": {"internal"},
    "service.beta.kubernetes.io/azure-load-balancer-internal": {"true"},
    "networking.gke.io/load-balancer-type": {"internal"},
    "cloud.google.com/load-balancer-type": {"internal"},
}
INGRESS_WAF_ANNOTATIONS = ("alb.ingress.kubernetes.io/wafv2-acl-arn", "alb.ingress.kubernetes.io/waf-acl-id",
                           "nginx.ingress.kubernetes.io/enable-modsecurity", "appgw.ingress.kubernetes.io/waf-policy-for-path")


def _meta(o: dict) -> dict:
    return o.get("metadata") or {}


def _internal_service(svc: dict) -> bool:
    ann = {k.lower(): str(v).lower() for k, v in (_meta(svc).get("annotations") or {}).items()}
    return any(ann.get(k) in vals for k, vals in INTERNAL_LB_ANNOTATIONS.items())


def _internal_ingress(ing: dict) -> bool:
    ann = {k.lower(): str(v).lower() for k, v in (_meta(ing).get("annotations") or {}).items()}
    cls = str((ing.get("spec") or {}).get("ingressClassName") or ann.get("kubernetes.io/ingress.class", "")).lower()
    return ann.get("alb.ingress.kubernetes.io/scheme") == "internal" or "internal" in cls or "private" in cls


def _waf_ingress(ing: dict) -> bool:
    ann = {k.lower(): str(v).lower() for k, v in (_meta(ing).get("annotations") or {}).items()}
    return any(ann.get(k) not in (None, "", "false") for k in INGRESS_WAF_ANNOTATIONS)


def _template(o: dict) -> tuple[dict, dict]:
    """(pod labels, pod spec) for a workload or bare pod."""
    if o.get("kind") == "Pod":
        return _meta(o).get("labels") or {}, o.get("spec") or {}
    t = (o.get("spec") or {}).get("template") or {}
    return _meta(t).get("labels") or {}, t.get("spec") or {}


def _target_port(sp: dict, pod_spec: dict) -> int | None:
    tp = sp.get("targetPort", sp.get("port"))
    if isinstance(tp, int) or (isinstance(tp, str) and tp.isdigit()):
        return int(tp)
    for c in pod_spec.get("containers") or []:
        for cp in c.get("ports") or []:
            if cp.get("name") == tp:
                return int(cp.get("containerPort"))
    return None


def assets_from_k8s(export: dict | list, *, cluster: str = "k8s", public_nodes: bool = False) -> list[Asset]:
    items = export.get("items", []) if isinstance(export, dict) else list(export)
    items = [o for o in items if isinstance(o, dict) and o.get("kind") != "Secret"]
    zone = f"k8s:{cluster}"
    policed = {_meta(o).get("namespace") for o in items if o.get("kind") == "NetworkPolicy"}
    services = [o for o in items if o.get("kind") == "Service"]
    ingresses = [o for o in items if o.get("kind") == "Ingress"]

    out: list[Asset] = []
    for o in items:
        if o.get("kind") not in WORKLOADS or _meta(o).get("ownerReferences"):
            continue
        m = _meta(o)
        ns, name = m.get("namespace", "default"), m.get("name", "?")
        labels, pod = _template(o)
        ref = f"{o['kind']}/{ns}/{name}"
        images = [c.get("image", "") for c in (pod.get("containers") or []) + (pod.get("initContainers") or []) if c.get("image")]
        role = (m.get("labels") or {}).get("aegis.io/role") or (m.get("annotations") or {}).get("aegis.io/role") or "server"
        a = Asset(id=ref, name=ref, keys={ref, f"{ns}/{name}", name, *(k for img in images for k in _image_keys(img))},
                  zone=zone, role=role if role in SENSITIVITY else "server", public=False,
                  lateral=[] if ns in policed else [(0, 65535, frozenset({"*"}))], source="k8s")

        def expose(port: int | None, via: str, *, waf: bool = False, fronts: tuple[str, ...] = (), a: Asset = a) -> None:
            if port is None:
                return
            a.fronted_by |= {f for f in fronts if f and f != "*"}
            r = (port, port)
            if r not in a.internet_ports:
                a.internet_ports.append(r)
            a.internet_via.setdefault(r, via)
            a.public = True
            a.waf = a.waf or waf

        selected: dict[str, dict] = {}
        for svc in services:
            sm, spec = _meta(svc), svc.get("spec") or {}
            sel = spec.get("selector") or {}
            if sm.get("namespace", "default") != ns or not sel or any(labels.get(k) != v for k, v in sel.items()):
                continue
            selected[sm.get("name", "?")] = svc
            stype = spec.get("type", "ClusterIP")
            for sp in spec.get("ports") or []:
                tp = _target_port(sp, pod)
                if stype == "LoadBalancer" and not _internal_service(svc):
                    expose(tp, f"Service {ns}/{sm.get('name')} (LoadBalancer :{sp.get('port')} → {tp})")
                elif stype == "NodePort" and public_nodes:
                    expose(tp, f"Service {ns}/{sm.get('name')} (NodePort {sp.get('nodePort', '?')} on public nodes → {tp})")
        for ing in ingresses:
            im, spec = _meta(ing), ing.get("spec") or {}
            if im.get("namespace", "default") != ns or _internal_ingress(ing):
                continue
            backends = []
            if spec.get("defaultBackend"):
                backends.append(("*", spec["defaultBackend"]))
            for rule in spec.get("rules") or []:
                for path in ((rule.get("http") or {}).get("paths") or []):
                    backends.append((rule.get("host") or "*", path.get("backend") or {}))
            for host, be in backends:
                bs = be.get("service") or {}
                svc = selected.get(bs.get("name"))
                if svc is None:
                    continue
                want = bs.get("port") or {}
                num, pname = want.get("number"), want.get("name")
                for sp in (svc.get("spec") or {}).get("ports") or []:
                    if (num is not None and num != sp.get("port")) or (pname is not None and pname != sp.get("name")):
                        continue
                    expose(_target_port(sp, pod), f"Ingress {ns}/{im.get('name')} ({host}) → Service {bs.get('name')}",
                           waf=_waf_ingress(ing), fronts=(host,))
        out.append(a)
    return out
