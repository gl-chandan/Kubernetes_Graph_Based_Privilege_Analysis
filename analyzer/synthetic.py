
import random

from .snapshot import PSA_LABEL, sa_id

HOP_KINDS = ["READ_SECRET", "CREATE_WORKLOAD", "TOKEN_REQUEST", "POD_EXEC", "NS_BIND"]
TERMINAL_KINDS = ["HOLDS_ADMIN", "BIND_CLUSTER_ROLE", "ESCALATE_ROLE", "IMPERSONATE"]
RBAC = "rbac.authorization.k8s.io"

HOP_RULES = {
    "READ_SECRET":     [dict(apiGroups=[""], resources=["secrets"], verbs=["get", "list"])],
    "CREATE_WORKLOAD": [dict(apiGroups=[""], resources=["pods"], verbs=["create"])],
    "TOKEN_REQUEST":   [dict(apiGroups=[""], resources=["serviceaccounts/token"], verbs=["create"])],
    "POD_EXEC":        [dict(apiGroups=[""], resources=["pods/exec"], verbs=["create"])],
    "NS_BIND":         [dict(apiGroups=[RBAC], resources=["rolebindings"], verbs=["create"]),
                        dict(apiGroups=[RBAC], resources=["clusterroles"], verbs=["bind"])],
}
TERMINAL_RULES = {
    "BIND_CLUSTER_ROLE": [dict(apiGroups=[RBAC], resources=["clusterrolebindings"], verbs=["create"]),
                          dict(apiGroups=[RBAC], resources=["clusterroles"], verbs=["bind"])],
    "ESCALATE_ROLE":     [dict(apiGroups=[RBAC], resources=["clusterroles"], verbs=["escalate", "update"])],
    "IMPERSONATE":       [dict(apiGroups=[""], resources=["groups"], verbs=["impersonate"])],
}


# ------------------------------------------------------------ raw-object helpers
def _meta(name, ns=None, labels=None):
    m = {"name": name}
    if ns:
        m["namespace"] = ns
    if labels:
        m["labels"] = labels
    return m


def _binding(kind, name, ns, subject_ns, subject, role_kind, role):
    meta = _meta(name, ns if kind == "RoleBinding" else None)
    return {"metadata": meta,
            "subjects": [dict(kind="ServiceAccount", name=subject, namespace=subject_ns)],
            "roleRef": dict(kind=role_kind, name=role, apiGroup=RBAC)}


class _Builder:
    def __init__(self):
        self.raw = {k: [] for k in ["serviceaccounts", "roles", "clusterroles", "rolebindings",
                                    "clusterrolebindings", "pods", "namespaces"]}

    def ns(self, name, psa="restricted"):
        self.raw["namespaces"].append({"metadata": _meta(name, labels={PSA_LABEL: psa})})
        self.raw["serviceaccounts"].append({"metadata": _meta("default", name)})

    def sa(self, ns, name, with_pod=True):
        self.raw["serviceaccounts"].append({"metadata": _meta(name, ns)})
        if with_pod:
            self.raw["pods"].append({"metadata": _meta(f"pod-{name}", ns),
                                     "spec": {"serviceAccountName": name, "containers": [{"name": "c"}]}})

    def role(self, ns, name, rules):
        self.raw["roles"].append({"metadata": _meta(name, ns), "rules": rules})

    def clusterrole(self, name, rules):
        self.raw["clusterroles"].append({"metadata": _meta(name), "rules": rules})


def make_cluster(chain_lengths=(1, 2, 3, 4, 5), chains_per_length=2, n_noise_ns=10,
                 sas_per_noise_ns=4, seed=0, n_decoys=True):
    """Return (raw_objects, truth). truth = {'chains': [...], 'decoys': [...]}."""
    rnd = random.Random(seed)
    b = _Builder()
    b.clusterrole("cluster-admin", [dict(apiGroups=["*"], resources=["*"], verbs=["*"])])
    b.clusterrole("viewer", [dict(apiGroups=[""], resources=["pods", "configmaps", "services"],
                                  verbs=["get", "list"])])
    # every ServiceAccount may read pods/configmaps/services (exercises group expansion)
    b.raw["clusterrolebindings"].append({
        "metadata": _meta("viewer-all-sa"),
        "subjects": [dict(kind="Group", name="system:serviceaccounts", apiGroup=RBAC)],
        "roleRef": dict(kind="ClusterRole", name="viewer", apiGroup=RBAC)})
    for t, rules in TERMINAL_RULES.items():
        b.clusterrole(f"terminal-{t.lower()}", rules)

    chains, cid = [], 0
    for n in chain_lengths:
        for _ in range(chains_per_length):
            ns_of = [f"chain{cid}-s{i}" for i in range(n)]
            sas = [f"app-{i}" for i in range(n)]
            for ns, sa in zip(ns_of, sas):
                b.ns(ns)
                b.sa(ns, sa)
            hops = []
            for i in range(n - 1):                      # sa_i --hop--> sa_{i+1}
                kind = HOP_KINDS[(cid + i) % len(HOP_KINDS)]
                hops.append(kind)
                b.role(ns_of[i + 1], f"hop{i}", HOP_RULES[kind])
                b.raw["rolebindings"].append(_binding("RoleBinding", f"hop{i}", ns_of[i + 1],
                                                      ns_of[i], sas[i], "Role", f"hop{i}"))
            term = TERMINAL_KINDS[cid % len(TERMINAL_KINDS)]
            last_ns, last_sa = ns_of[-1], sas[-1]
            role = "cluster-admin" if term == "HOLDS_ADMIN" else f"terminal-{term.lower()}"
            b.raw["clusterrolebindings"].append(_binding("ClusterRoleBinding", f"terminal-{cid}",
                                                         None, last_ns, last_sa, "ClusterRole", role))
            chains.append(dict(id=cid, length=n, hops=hops, terminal=term,
                               subjects=[sa_id(ns, sa) for ns, sa in zip(ns_of, sas)]))
            cid += 1

    # --- noise: ordinary namespaces, nothing leads to admin --------------------------
    for j in range(n_noise_ns):
        ns = f"noise{j}"
        b.ns(ns, psa=rnd.choice(["restricted", "baseline"]))
        for m in range(sas_per_noise_ns):
            b.sa(ns, f"svc-{m}")
        b.role(ns, "reader", [dict(apiGroups=[""], resources=["configmaps", "services"], verbs=["get", "list"])])
        b.role(ns, "own-secrets", HOP_RULES["READ_SECRET"])
        b.raw["rolebindings"].append(_binding("RoleBinding", "r", ns, ns, "svc-1", "Role", "reader"))
        b.raw["rolebindings"].append(_binding("RoleBinding", "s", ns, ns, "svc-0", "Role", "own-secrets"))

    # --- decoys: look risky, are not --------------------------------------------------
    decoys = []
    if n_decoys:
        ns = "decoy"
        b.ns(ns)
        specs = {
            "bind-only":        ("clusterrole", [dict(apiGroups=[RBAC], resources=["clusterroles"], verbs=["bind"])]),
            "escalate-only":    ("clusterrole", [dict(apiGroups=[RBAC], resources=["clusterroles"], verbs=["escalate"])]),
            "pods-restricted":  ("role", HOP_RULES["CREATE_WORKLOAD"]),
            "impersonate-ghost": ("clusterrole", [dict(apiGroups=[""], resources=["users"], verbs=["impersonate"],
                                                       resourceNames=["nobody"])]),
        }
        for name, (scope, rules) in specs.items():
            b.sa(ns, name)
            if scope == "clusterrole":
                b.clusterrole(f"decoy-{name}", rules)
                b.raw["clusterrolebindings"].append(_binding("ClusterRoleBinding", f"decoy-{name}", None,
                                                             ns, name, "ClusterRole", f"decoy-{name}"))
            else:
                b.role(ns, name, rules)
                b.raw["rolebindings"].append(_binding("RoleBinding", name, ns, ns, name, "Role", name))
            decoys.append(sa_id(ns, name))
    return b.raw, dict(chains=chains, decoys=decoys)


def expected_flagged(truth):
    """Entries that SHOULD be flagged: every chain SA and its pod."""
    out = set()
    for c in truth["chains"]:
        for s in c["subjects"]:
            out.add(s)
            out.add(s.replace("serviceaccount::", "pod::").rsplit("::", 1)[0] + "::pod-" + s.rsplit("::", 1)[1])
    return out


def cluster_size_variant(n_sas_target, seed=0):
    """Grow a cluster to roughly n_sas_target ServiceAccounts by adding noise namespaces."""
    base = sum(range(1, 6)) * 2           # chain SAs in the default config (30)
    n_noise = max(0, (n_sas_target - base - 4) // 4)
    return make_cluster(n_noise_ns=n_noise, seed=seed)
