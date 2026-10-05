
from .rbac import ALL, allowed_scopes, expand, intersect, is_admin
from .snapshot import TARGET

COST = {
    "HOLDS_ADMIN": 0,
    "BIND_CLUSTER_ROLE": 1,
    "ESCALATE_ROLE": 1,
    "IMPERSONATE": 1,
    "READ_SECRET": 1,
    "TOKEN_REQUEST": 1,
    "POD_EXEC": 1,
    "TOKEN_MOUNT": 1,
    "CREATE_WORKLOAD": 2,
    "NS_BIND": 2,
    "CREATE_PRIVILEGED_POD": 3,
    "POD_ESCAPE": 3,
}
ALL_PRIMITIVES = frozenset(COST)

RBAC = "rbac.authorization.k8s.io"
WORKLOADS = [("pods", "", ["create"]),
             ("deployments", "apps", ["create", "update", "patch"]),
             ("daemonsets", "apps", ["create", "update", "patch"]),
             ("statefulsets", "apps", ["create", "update", "patch"]),
             ("replicasets", "apps", ["create", "update", "patch"]),
             ("jobs", "batch", ["create", "update", "patch"]),
             ("cronjobs", "batch", ["create", "update", "patch"])]


def derive_edges(cluster, grants_by_subject, enabled=ALL_PRIMITIVES):
    """Yield one edge dict per (subject, primitive, destination)."""
    edges = []

    def add(src, dst, prim, perm, grant=None, scope=None):
        if prim in enabled and src != dst:
            edges.append(dict(src=src, dst=dst, primitive=prim, cost=COST[prim], permission=perm,
                              via_binding=grant.binding if grant else None,
                              via_role=grant.role if grant else None, scope=scope))

    pods_in = {}
    for pid, p in cluster.pods.items():
        pods_in.setdefault(p["ns"], []).append(pid)

    for sid, grants in grants_by_subject.items():
        # --- cluster-level primitives -> TARGET --------------------------------
        g = is_admin(grants)
        if g:
            add(sid, TARGET, "HOLDS_ADMIN", "* on *", g, ALL)

        crb = allowed_scopes(grants, ["create"], "clusterrolebindings", RBAC).get(ALL)
        bind = allowed_scopes(grants, ["bind"], "clusterroles", RBAC).get(ALL)
        if crb and bind:
            add(sid, TARGET, "BIND_CLUSTER_ROLE", "create clusterrolebindings + bind clusterroles", crb, ALL)

        esc = allowed_scopes(grants, ["escalate"], "clusterroles", RBAC).get(ALL)
        upd = allowed_scopes(grants, ["update", "patch"], "clusterroles", RBAC).get(ALL)
        if esc and upd:
            add(sid, TARGET, "ESCALATE_ROLE", "escalate + update clusterroles", esc, ALL)

        # --- impersonation -------------------------------------------------------
        for res in ("groups", "users", "serviceaccounts"):
            for scope, gr in allowed_scopes(grants, ["impersonate"], res, "", honour_names=True).items():
                if res == "groups":
                    add(sid, TARGET, "IMPERSONATE", "impersonate group system:masters", gr, scope)
                elif res == "users":
                    for u in cluster.users:
                        add(sid, f"user::{u}", "IMPERSONATE", "impersonate users", gr, scope)
                else:
                    for ns, g2 in expand({scope: gr}, cluster).items():
                        for t in cluster.sas_in(ns):
                            add(sid, t, "IMPERSONATE", f"impersonate serviceaccounts @{ns}", g2, ns)

        # --- namespaced primitives -> SAs / pods in that namespace ------------------
        def to_sas(scopes, prim, perm):
            for ns, gr in expand(scopes, cluster).items():
                for t in cluster.sas_in(ns):
                    add(sid, t, prim, f"{perm} @{ns}", gr, ns)

        to_sas(allowed_scopes(grants, ["get", "list"], "secrets"), "READ_SECRET", "get secrets")
        to_sas(allowed_scopes(grants, ["create"], "serviceaccounts/token"), "TOKEN_REQUEST",
               "create serviceaccounts/token")

        for ns, gr in expand(allowed_scopes(grants, ["create"], "pods/exec"), cluster).items():
            for pid in pods_in.get(ns, []):
                add(sid, pid, "POD_EXEC", f"create pods/exec @{ns}", gr, ns)

        wl = {}
        for res, grp, verbs in WORKLOADS:
            for k, v in allowed_scopes(grants, verbs, res, grp).items():
                wl.setdefault(k, v)
        to_sas(wl, "CREATE_WORKLOAD", "create pods")
        for ns, gr in expand(wl, cluster).items():
            if cluster.namespaces.get(ns, "privileged") == "privileged":
                add(sid, TARGET, "CREATE_PRIVILEGED_POD", f"create privileged pod @{ns} (no PSA)", gr, ns)

        rb = allowed_scopes(grants, ["create"], "rolebindings", RBAC)
        bnd = allowed_scopes(grants, ["bind"], "roles", RBAC)
        for k, v in allowed_scopes(grants, ["bind"], "clusterroles", RBAC).items():
            bnd.setdefault(k, v)
        to_sas(intersect(rb, bnd), "NS_BIND", "create rolebindings + bind")

    # --- pod-spec edges (no RBAC needed: facts about running workloads) ------------
    for pid, p in cluster.pods.items():
        if p["automount"]:
            add(pid, p["sa"], "TOKEN_MOUNT", "token auto-mounted in pod")
        if p["escape"]:
            add(pid, TARGET, "POD_ESCAPE", "pod spec: " + ", ".join(p["escape"]))
    return edges
