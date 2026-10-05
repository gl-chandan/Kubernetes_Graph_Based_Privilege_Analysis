"""
rbac.py  --  Stage 2: effective permissions.

Resolves  subject -> binding -> role -> rules  into a list of `Grant`s per
subject, and answers "may this subject do VERB on RESOURCE, and where?".
This is the same question `kubectl auth can-i` answers, but computed offline
for every subject at once from the snapshot.

Scope model: a grant's scope is a namespace (RoleBinding) or "*" (ClusterRoleBinding).
"""
from collections import defaultdict
from typing import NamedTuple

from .snapshot import sa_id

ALL = "*"


class Grant(NamedTuple):
    binding: str      # binding node id that confers it
    role: str         # role node id it came from
    scope: str        # namespace name, or "*" for cluster-wide
    rules: list


def covered_subject_ids(cluster, subj):
    """Which subject nodes does a binding subject entry apply to?
    Expands the implicit groups every ServiceAccount belongs to."""
    if subj["kind"] == "Group":
        g = subj["name"]
        if g == "system:serviceaccounts":
            return list(cluster.service_accounts)
        if g.startswith("system:serviceaccounts:"):
            return cluster.sas_in(g.split(":", 2)[2])
        if g == "system:authenticated":
            return list(cluster.service_accounts) + [f"user::{u}" for u in cluster.users]
    return [subj["id"]]


def effective_grants(cluster):
    """Return {subject_id: [Grant, ...]} for every subject with at least one binding."""
    grants = defaultdict(list)
    for b in cluster.bindings:
        rules = cluster.roles[b["role"]]["rules"]
        if not rules:
            continue
        scope = b["ns"] if b["kind"] == "RoleBinding" else ALL
        g = Grant(b["id"], b["role"], scope, rules)
        for subj in b["subjects"]:
            for sid in covered_subject_ids(cluster, subj):
                grants[sid].append(g)
    return grants


# ---------------------------------------------------------------- rule matching
def _res_match(rule_resources, resource):
    base = resource.split("/")[0]
    return (ALL in rule_resources or resource in rule_resources
            or (f"{base}/*" in rule_resources))


def rule_allows(rule, verb, resource, group=""):
    return ((verb in rule.get("verbs", []) or ALL in rule.get("verbs", []))
            and _res_match(rule.get("resources", []), resource)
            and (group in rule.get("apiGroups", []) or ALL in rule.get("apiGroups", [])))


def allowed_scopes(grants, verbs, resource, group="", honour_names=True):
    """{scope: Grant} where any of `verbs` is allowed on `resource`.
    Rules restricted by resourceNames are skipped (conservative: they cannot be
    assumed to cover an attacker-chosen object) unless honour_names=False."""
    out = {}
    for g in grants:
        for rule in g.rules:
            if honour_names and rule.get("resourceNames"):
                continue
            if any(rule_allows(rule, v, resource, group) for v in verbs):
                out.setdefault(g.scope, g)
    return out


def intersect(a, b):
    """Scopes present in both a and b (cluster-wide '*' covers every namespace)."""
    if ALL in a and ALL in b:
        return {ALL: a[ALL]}
    if ALL in a:
        return dict(b)
    if ALL in b:
        return dict(a)
    return {k: a[k] for k in a if k in b}


def expand(scopes, cluster):
    """Turn a scope dict into {namespace: Grant} over the cluster's real namespaces."""
    out = {}
    if ALL in scopes:
        out = {ns: scopes[ALL] for ns in cluster.namespaces}
    for k, g in scopes.items():
        if k != ALL:
            out[k] = g
    return out


def is_admin(grants):
    """Cluster-admin-equivalent: '*' verbs on '*' resources in '*' groups, cluster-wide."""
    for g in grants:
        if g.scope != ALL:
            continue
        for r in g.rules:
            if ALL in r.get("verbs", []) and ALL in r.get("resources", []) and ALL in r.get("apiGroups", []):
                return g
    return None


def can_i(cluster, grants_by_subject, subject_id, verb, resource, group="", ns=None):
    """Offline equivalent of `kubectl auth can-i VERB RESOURCE [-n NS] --as SUBJECT`."""
    sc = allowed_scopes(grants_by_subject.get(subject_id, []), [verb], resource, group, honour_names=False)
    return ALL in sc or (ns is not None and ns in sc) or (ns is None and bool(sc))
