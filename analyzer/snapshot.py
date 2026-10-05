"""
snapshot.py  --  Stage 1: load a cluster's access-control configuration.

A *snapshot* is the set of JSON files produced by `kubectl get ... -o json`
(see scripts/collect_k3s.sh). `Cluster.from_raw` normalises those raw
Kubernetes objects into a small, uniform model that the rest of the tool uses.
The synthetic-cluster generator emits the *same raw format*, so real and
synthetic clusters go through exactly the same code path.
"""
import json
from pathlib import Path

TARGET = "TARGET::cluster-admin"          # virtual node: cluster-admin-equivalent privilege
PSA_LABEL = "pod-security.kubernetes.io/enforce"
RAW_KINDS = ["serviceaccounts", "roles", "clusterroles", "rolebindings",
             "clusterrolebindings", "pods", "namespaces"]


# ---- stable node-id helpers -------------------------------------------------
def sa_id(ns, name):   return f"serviceaccount::{ns}::{name}"
def pod_id(ns, name):  return f"pod::{ns}::{name}"
def user_id(name):     return f"user::{name}"
def group_id(name):    return f"group::{name}"
def role_id(kind, ns, name):
    return f"clusterrole::{name}" if kind == "ClusterRole" else f"role::{ns}::{name}"


def load_snapshot(directory):
    """Read <directory>/<kind>.json for every kind; missing files become []."""
    directory = Path(directory)
    raw = {}
    for kind in RAW_KINDS:
        f = directory / f"{kind}.json"
        raw[kind] = json.loads(f.read_text(encoding="utf-8")).get("items", []) if f.exists() else []
    return raw


class Cluster:
    """Normalised view of a cluster's access-control configuration."""

    def __init__(self):
        self.service_accounts = {}   # id -> {ns, name, automount}
        self.roles = {}              # id -> {kind, ns, name, rules}
        self.bindings = []           # {id, kind, ns, role, subjects:[{kind,id,ns,name}]}
        self.pods = {}               # id -> {ns, name, sa, automount, escape}
        self.namespaces = {}         # ns -> pod-security enforce level
        self.users, self.groups = set(), set()

    @classmethod
    def from_raw(cls, raw):
        c = cls()
        # namespaces: the pod-security level decides whether privileged pods are admitted
        for it in raw.get("namespaces", []):
            labels = it["metadata"].get("labels", {}) or {}
            c.namespaces[it["metadata"]["name"]] = labels.get(PSA_LABEL, "privileged")

        for it in raw.get("serviceaccounts", []):
            m = it["metadata"]
            c.service_accounts[sa_id(m["namespace"], m["name"])] = dict(
                ns=m["namespace"], name=m["name"],
                automount=it.get("automountServiceAccountToken", True))

        for it in raw.get("roles", []) + raw.get("clusterroles", []):
            m = it["metadata"]
            kind = "Role" if "namespace" in m else "ClusterRole"
            c.roles[role_id(kind, m.get("namespace"), m["name"])] = dict(
                kind=kind, ns=m.get("namespace"), name=m["name"], rules=it.get("rules") or [])

        for kind, items in (("RoleBinding", raw.get("rolebindings", [])),
                            ("ClusterRoleBinding", raw.get("clusterrolebindings", []))):
            for it in items:
                m = it["metadata"]
                ns = m.get("namespace") if kind == "RoleBinding" else None
                ref = it["roleRef"]
                b = dict(id=(f"rolebinding::{ns}::{m['name']}" if ns else f"clusterrolebinding::{m['name']}"),
                         kind=kind, ns=ns, name=m["name"],
                         role=role_id(ref["kind"], ns, ref["name"]), subjects=[])
                for s in it.get("subjects") or []:
                    if s["kind"] == "ServiceAccount":
                        sns = s.get("namespace") or ns or "default"
                        sid = sa_id(sns, s["name"])
                        c.service_accounts.setdefault(sid, dict(ns=sns, name=s["name"], automount=True))
                        b["subjects"].append(dict(kind="ServiceAccount", id=sid, ns=sns, name=s["name"]))
                    elif s["kind"] == "User":
                        c.users.add(s["name"])
                        b["subjects"].append(dict(kind="User", id=user_id(s["name"]), name=s["name"]))
                    else:
                        c.groups.add(s["name"])
                        b["subjects"].append(dict(kind="Group", id=group_id(s["name"]), name=s["name"]))
                c.bindings.append(b)
                c.roles.setdefault(b["role"], dict(kind=ref["kind"], ns=ns, name=ref["name"], rules=[]))

        for it in raw.get("pods", []):
            m, spec = it["metadata"], it.get("spec", {})
            ns, sa = m["namespace"], spec.get("serviceAccountName", "default")
            sid = sa_id(ns, sa)
            c.service_accounts.setdefault(sid, dict(ns=ns, name=sa, automount=True))
            conts = (spec.get("containers") or []) + (spec.get("initContainers") or [])
            reasons = []
            if any((x.get("securityContext") or {}).get("privileged") for x in conts):
                reasons.append("privileged container")
            if spec.get("hostPID"):
                reasons.append("hostPID")
            if any("hostPath" in v for v in spec.get("volumes") or []):
                reasons.append("hostPath volume")
            auto = spec.get("automountServiceAccountToken")
            if auto is None:
                auto = c.service_accounts[sid].get("automount", True)
            c.pods[pod_id(ns, m["name"])] = dict(ns=ns, name=m["name"], sa=sid,
                                                 automount=bool(auto), escape=reasons)

        for sa in c.service_accounts.values():
            c.namespaces.setdefault(sa["ns"], "privileged")
        for p in c.pods.values():
            c.namespaces.setdefault(p["ns"], "privileged")
        return c

    @classmethod
    def from_dir(cls, directory):
        return cls.from_raw(load_snapshot(directory))

    def sas_in(self, ns):
        """ServiceAccount ids in a namespace (index built lazily, then reused)."""
        if getattr(self, "_by_ns", None) is None:
            self._by_ns = {}
            for i, s in self.service_accounts.items():
                self._by_ns.setdefault(s["ns"], []).append(i)
        return self._by_ns.get(ns, [])
