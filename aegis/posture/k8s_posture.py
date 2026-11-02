"""Kubernetes posture — workloads, RBAC and network isolation as they stand in the cluster.

The runtime ``k8s_audit_check`` sees the ``kubectl exec`` or the privileged pod being *created*.
This sees the privileged DaemonSet that has been running for a year, the CI service account bound to
cluster-admin, and the namespace with no NetworkPolicy at all.

Input: one ``kubectl get ... -A -o json`` List (see ``EXPORT_KINDS``), exported by the bank, or
collected by AEGIS with the same read-only ``kubectl get`` when ``AEGIS_POSTURE_LIVE=1``.
**Secrets are never part of the export.** If Secret objects are present anyway they are ignored and
the report says so.

Checks follow CIS Kubernetes Benchmark section 5 and the Pod Security Standards (baseline /
restricted). ``kube-system`` is skipped for workload checks by default (CNI and kube-proxy are
privileged by design); ``include_system=True`` scans it too.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from .base import PostureFinding, sort_findings

CIS = "CIS Kubernetes v1.9"
PSS = "Pod Security Standards"

EXPORT_KINDS = ("namespaces", "pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs",
                "serviceaccounts", "roles", "clusterroles", "rolebindings", "clusterrolebindings", "networkpolicies")
EXPORT_COMMAND = "kubectl get " + ",".join(EXPORT_KINDS) + " -A -o json"

SYSTEM_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})
WORKLOAD_KINDS = {"Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"}
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_RAW", "BPF", "PERFMON"}
CRITICAL_HOST_PATHS = ("/", "/etc", "/root", "/var/run/docker.sock", "/run/containerd/containerd.sock",
                       "/var/run/crio/crio.sock", "/var/lib/kubelet", "/proc", "/sys")
SECRET_ENV = re.compile(r"(pass(word)?|secret|token|api[_-]?key|private[_-]?key|credential)", re.IGNORECASE)
ANONYMOUS = {("Group", "system:unauthenticated"), ("Group", "system:authenticated"), ("User", "system:anonymous")}


def _f(**kw: Any) -> PostureFinding:
    kw.setdefault("confidence", 0.95)
    kw.setdefault("category", "misconfig")
    return PostureFinding(scanner="k8s_posture", **kw)


def _ref(o: dict) -> str:
    m = o.get("metadata", {})
    ns = m.get("namespace")
    return f"{o.get('kind')}/{ns + '/' if ns else ''}{m.get('name', '?')}"


def _pod_spec(o: dict) -> dict | None:
    k, spec = o.get("kind"), o.get("spec") or {}
    if k == "Pod":
        return spec
    if k == "CronJob":
        return ((((spec.get("jobTemplate") or {}).get("spec") or {}).get("template")) or {}).get("spec")
    if k in WORKLOAD_KINDS:
        return (spec.get("template") or {}).get("spec")
    return None


def _containers(ps: dict) -> Iterable[dict]:
    for key in ("initContainers", "containers", "ephemeralContainers"):
        yield from ps.get(key) or []


# ---- workloads ------------------------------------------------------------------------------------

def _workload(o: dict, ps: dict, admin_sas: set[tuple[str, str]]) -> list[PostureFinding]:
    out: list[PostureFinding] = []
    ref, ns = _ref(o), o.get("metadata", {}).get("namespace", "default")
    psc = ps.get("securityContext") or {}

    def add(fid: str, sev: str, ev: str, fix: str, control: str | None = None, conf: float = 0.95) -> None:
        out.append(_f(id=fid, severity=sev, resource=ref, affected_component=ref, evidence=ev,
                      recommended_remediation=fix, control=control, confidence=conf))

    host = [n for n in ("hostNetwork", "hostPID", "hostIPC") if ps.get(n)]
    if host:
        add("K8S-HOST-NAMESPACE", "high", f"pod shares the node's {', '.join(host)}",
            "Remove hostNetwork/hostPID/hostIPC; use a Service or a node agent with a narrow scope", f"{CIS} 5.2.2-5.2.4")

    for v in ps.get("volumes") or []:
        hp = (v.get("hostPath") or {}).get("path")
        if hp is None:
            continue
        crit = hp.rstrip("/") in {p.rstrip("/") for p in CRITICAL_HOST_PATHS} or hp == "/"
        add("K8S-HOSTPATH-SENSITIVE" if crit else "K8S-HOSTPATH", "critical" if crit else "high",
            f"hostPath volume mounts the node's {hp}" + (" — container breakout / node takeover" if crit else ""),
            "Replace hostPath with a PersistentVolume, ConfigMap or projected volume", f"{PSS} baseline")

    sa = ps.get("serviceAccountName") or ps.get("serviceAccount") or "default"
    automount = ps.get("automountServiceAccountToken")
    if (ns, sa) in admin_sas and automount is not False:
        add("K8S-WORKLOAD-CLUSTER-ADMIN-SA", "critical",
            f"runs as service account {ns}/{sa}, which is bound to cluster-admin, and mounts its token",
            "Give the workload a dedicated least-privilege service account; never mount a cluster-admin token into a pod",
            f"{CIS} 5.1.1")
    elif sa == "default" and automount is not False and ns not in SYSTEM_NAMESPACES:
        add("K8S-DEFAULT-SA-TOKEN", "low", "uses the namespace's default service account with its token auto-mounted",
            "Create a dedicated service account, or set automountServiceAccountToken: false", f"{CIS} 5.1.5-5.1.6")

    for c in _containers(ps):
        name = c.get("name", "?")
        sc = c.get("securityContext") or {}
        where = f"container '{name}'"

        if sc.get("privileged"):
            add("K8S-PRIVILEGED", "critical", f"{where} runs privileged: full access to the node",
                "Drop privileged; grant only the specific capability the workload needs", f"{CIS} 5.2.1 / {PSS} baseline")

        caps = {str(x).upper() for x in ((sc.get("capabilities") or {}).get("add") or [])}
        if bad := caps & DANGEROUS_CAPS:
            add("K8S-DANGEROUS-CAPABILITY", "high", f"{where} adds capabilities {', '.join(sorted(bad))}",
                "Remove added capabilities; drop ALL and add back only what is proven necessary", f"{CIS} 5.2.8-5.2.9")

        if sc.get("allowPrivilegeEscalation", True) is not False and not sc.get("privileged"):
            add("K8S-PRIV-ESCALATION-ALLOWED", "medium", f"{where} does not set allowPrivilegeEscalation: false",
                "Set allowPrivilegeEscalation: false", f"{CIS} 5.2.6 / {PSS} restricted")

        uid = sc.get("runAsUser", psc.get("runAsUser"))
        non_root = sc.get("runAsNonRoot", psc.get("runAsNonRoot"))
        if uid == 0:
            add("K8S-RUNS-AS-ROOT", "high", f"{where} explicitly runs as UID 0",
                "Run as a non-root UID and set runAsNonRoot: true", f"{CIS} 5.2.7 / {PSS} restricted")
        elif non_root is not True and uid is None:
            add("K8S-ROOT-NOT-PREVENTED", "medium", f"{where} may run as root (no runAsNonRoot / runAsUser)",
                "Set runAsNonRoot: true and a non-zero runAsUser", f"{CIS} 5.2.7 / {PSS} restricted", conf=0.8)

        if not sc.get("readOnlyRootFilesystem"):
            add("K8S-WRITABLE-ROOTFS", "low", f"{where} has a writable root filesystem",
                "Set readOnlyRootFilesystem: true; mount an emptyDir for scratch paths")

        if any(p.get("hostPort") for p in c.get("ports") or []):
            add("K8S-HOST-PORT", "medium", f"{where} binds a hostPort on the node",
                "Expose through a Service instead of hostPort", f"{PSS} baseline")

        limits = (c.get("resources") or {}).get("limits") or {}
        if "memory" not in limits or "cpu" not in limits:
            add("K8S-NO-LIMITS", "low", f"{where} has no CPU/memory limit: one compromised pod can starve the node",
                "Set resources.limits (and a namespace LimitRange)")

        image = c.get("image", "")
        tagless = "@" not in image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest"))
        if tagless:
            add("K8S-IMAGE-LATEST", "low", f"{where} uses an unpinned image '{image}'",
                "Pin images by digest (or at least an immutable version tag)")

        leaked = [e.get("name") for e in c.get("env") or [] if "value" in e and e.get("value") and SECRET_ENV.search(e.get("name", ""))]
        if leaked:
            add("K8S-SECRET-IN-ENV", "high", f"{where} has plaintext secret-like env vars in the manifest: {', '.join(leaked)}",
                "Move the values to a Secret (or an external secret store) and reference them with valueFrom",
                f"{CIS} 5.4.1", conf=0.75)
    return out


# ---- RBAC -----------------------------------------------------------------------------------------

def _rules_risk(rules: list[dict]) -> list[tuple[str, str, str]]:
    """(id, severity, evidence) for the risky permissions in a role's rules."""
    hits = []
    for r in rules or []:
        verbs = {str(v).lower() for v in r.get("verbs") or []}
        res = {str(x).lower() for x in r.get("resources") or []}
        if "*" in verbs and "*" in res:
            hits.append(("K8S-RBAC-WILDCARD", "high", "grants every verb on every resource ('*' / '*')"))
            continue
        if verbs & {"escalate", "bind", "impersonate"}:
            hits.append(("K8S-RBAC-ESCALATE", "high", f"grants {', '.join(sorted(verbs & {'escalate', 'bind', 'impersonate'}))}"))
        if ("secrets" in res or "*" in res) and verbs & {"get", "list", "watch", "*"}:
            hits.append(("K8S-RBAC-READ-SECRETS", "medium", "can read Secrets"))
        if ("pods/exec" in res or "*" in res) and verbs & {"create", "*"}:
            hits.append(("K8S-RBAC-POD-EXEC", "medium", "can exec into pods"))
    return hits


def _rbac(items: list[dict]) -> tuple[list[PostureFinding], set[tuple[str, str]]]:
    out: list[PostureFinding] = []
    roles = {("ClusterRole", None, o["metadata"]["name"]): o for o in items if o.get("kind") == "ClusterRole"}
    roles.update({("Role", o["metadata"].get("namespace"), o["metadata"]["name"]): o for o in items if o.get("kind") == "Role"})
    admin_sas: set[tuple[str, str]] = set()
    seen_roles: set[tuple] = set()

    for b in (o for o in items if o.get("kind") in ("RoleBinding", "ClusterRoleBinding")):
        bref = _ref(b)
        bns = b.get("metadata", {}).get("namespace")
        rr = b.get("roleRef") or {}
        rk = rr.get("kind")
        role_key = ("ClusterRole", None, rr.get("name")) if rk == "ClusterRole" else ("Role", bns, rr.get("name"))
        subjects = b.get("subjects") or []
        is_admin = rk == "ClusterRole" and rr.get("name") == "cluster-admin"
        system_binding = b.get("metadata", {}).get("name", "").startswith("system:")

        for s in subjects:
            sk, sn = s.get("kind"), s.get("name", "")
            if (sk, sn) in ANONYMOUS and not system_binding:
                out.append(_f(id="K8S-RBAC-ANONYMOUS", severity="critical", resource=bref, affected_component=bref,
                              control=f"{CIS} 5.1.1", evidence=f"{rr.get('name')} is granted to {sk} {sn} (everyone / anonymous)",
                              recommended_remediation="Remove the binding; grant roles to named users, groups or service accounts"))
            if is_admin and sk == "ServiceAccount":
                admin_sas.add((s.get("namespace") or bns or "default", sn))

        if is_admin and not system_binding:
            who = ", ".join(f"{s.get('kind')} {s.get('namespace') + '/' if s.get('namespace') else ''}{s.get('name')}"
                            for s in subjects if (s.get("kind"), s.get("name")) != ("Group", "system:masters"))
            if who:
                out.append(_f(id="K8S-RBAC-CLUSTER-ADMIN", severity="high", resource=bref, affected_component=bref,
                              control=f"{CIS} 5.1.1", evidence=f"cluster-admin bound to {who}",
                              recommended_remediation="Replace cluster-admin with a scoped ClusterRole; keep cluster-admin for break-glass only"))

        role = roles.get(role_key)
        name = rr.get("name", "")
        if role is None or role_key in seen_roles or name.startswith("system:") or name in ("cluster-admin", "admin", "edit", "view"):
            continue
        seen_roles.add(role_key)
        rref = _ref(role)
        for fid, sev, ev in _rules_risk(role.get("rules")):
            out.append(_f(id=fid, severity=sev, resource=rref, affected_component=rref, confidence=0.9,
                          control={"K8S-RBAC-WILDCARD": f"{CIS} 5.1.3", "K8S-RBAC-ESCALATE": f"{CIS} 5.1.8",
                                   "K8S-RBAC-READ-SECRETS": f"{CIS} 5.1.2"}.get(fid),
                          evidence=f"{ev} (bound via {bref})",
                          recommended_remediation="Narrow the rule to the verbs and resources the subject actually uses"))
    return out, admin_sas


# ---- scan -----------------------------------------------------------------------------------------

def scan(export: dict | list, *, include_system: bool = False) -> list[PostureFinding]:
    items = export.get("items", []) if isinstance(export, dict) else list(export)
    items = [o for o in items if isinstance(o, dict) and o.get("kind") != "Secret"]
    out, admin_sas = _rbac(items)

    for o in items:
        if o.get("kind") not in WORKLOAD_KINDS:
            continue
        m = o.get("metadata", {})
        if m.get("ownerReferences"):
            continue  # judged once, at its controller (Deployment → ReplicaSet → Pod)
        if m.get("namespace") in SYSTEM_NAMESPACES and not include_system:
            continue
        if (ps := _pod_spec(o)) is not None:
            out.extend(_workload(o, ps, admin_sas))

    # Network isolation and namespace hygiene.
    namespaces = {o["metadata"]["name"]: o for o in items if o.get("kind") == "Namespace"}
    with_policy = {o["metadata"].get("namespace") for o in items if o.get("kind") == "NetworkPolicy"}
    workloads_in = defaultdict(int)
    for o in items:
        if o.get("kind") in WORKLOAD_KINDS and not o.get("metadata", {}).get("ownerReferences"):
            workloads_in[o.get("metadata", {}).get("namespace", "default")] += 1
    for ns, n in sorted(workloads_in.items()):
        if ns in SYSTEM_NAMESPACES and not include_system:
            continue
        if ns not in with_policy:
            out.append(_f(id="K8S-NO-NETWORKPOLICY", severity="medium", resource=f"Namespace/{ns}", affected_component=f"Namespace/{ns}",
                          control=f"{CIS} 5.3.2", evidence=f"{n} workload(s) and no NetworkPolicy: any pod can reach any pod",
                          recommended_remediation="Add a default-deny ingress/egress NetworkPolicy, then allow the flows the app needs"))
        if ns == "default":
            out.append(_f(id="K8S-DEFAULT-NAMESPACE-USED", severity="low", resource="Namespace/default", affected_component="Namespace/default",
                          control=f"{CIS} 5.7.4", evidence=f"{n} workload(s) run in the default namespace",
                          recommended_remediation="Move workloads into dedicated namespaces with their own RBAC and policies"))
    for name, nso in sorted(namespaces.items()):
        if name in SYSTEM_NAMESPACES or not workloads_in.get(name):
            continue
        labels = nso.get("metadata", {}).get("labels") or {}
        if labels.get("pod-security.kubernetes.io/enforce") not in ("baseline", "restricted"):
            out.append(_f(id="K8S-NO-POD-SECURITY-ADMISSION", severity="low", resource=f"Namespace/{name}", affected_component=f"Namespace/{name}",
                          control=f"{PSS}", evidence="namespace does not enforce a Pod Security Admission level",
                          recommended_remediation="Label the namespace pod-security.kubernetes.io/enforce=baseline (restricted where possible)"))
    return sort_findings(out)


def notes(export: dict | list, *, include_system: bool = False) -> list[str]:
    items = export.get("items", []) if isinstance(export, dict) else list(export)
    kinds = {o.get("kind") for o in items if isinstance(o, dict)}
    n: list[str] = []
    if "Secret" in kinds:
        n.append("Secret objects were present in the export and were ignored; export without secrets (see EXPORT_COMMAND)")
    missing = [k for k, plural in (("Namespace", "namespaces"), ("ClusterRoleBinding", "clusterrolebindings"),
                                   ("NetworkPolicy", "networkpolicies")) if k not in kinds]
    if missing:
        n.append(f"no {', '.join(missing)} objects in the export; if they were not exported, those checks are incomplete")
    if not include_system:
        n.append("kube-system / kube-public / kube-node-lease workloads skipped (use --include-system to scan them)")
    return n
