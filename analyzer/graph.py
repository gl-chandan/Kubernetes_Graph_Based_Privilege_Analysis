
import networkx as nx

from .primitives import ALL_PRIMITIVES, derive_edges
from .rbac import effective_grants
from .snapshot import TARGET, Cluster


def build_graph(cluster: Cluster, enabled=ALL_PRIMITIVES):
    G = nx.DiGraph()
    G.add_node(TARGET, type="target", label="CLUSTER-ADMIN", builtin=False)

    role_names_of = {}                                # subject -> role names (to flag built-ins)
    for b in cluster.bindings:
        for s in b["subjects"]:
            role_names_of.setdefault(s["id"], []).append(cluster.roles[b["role"]]["name"])

    def add_subject(sid, kind, ns, name):
        roles = role_names_of.get(sid, [])
        builtin = name.startswith("system:") if kind != "ServiceAccount" else \
            bool(roles) and all(r.startswith("system:") for r in roles)
        G.add_node(sid, type="subject", kind=kind, ns=ns, name=name, builtin=builtin,
                   label=f"{kind}\n{ns + '/' if ns else ''}{name}")

    for sid, sa in cluster.service_accounts.items():
        add_subject(sid, "ServiceAccount", sa["ns"], sa["name"])
    for u in cluster.users:
        add_subject(f"user::{u}", "User", None, u)
    for g in cluster.groups:
        add_subject(f"group::{g}", "Group", None, g)

    for rid, r in cluster.roles.items():
        G.add_node(rid, type="role", name=r["name"], ns=r["ns"], builtin=False,
                   label=f"{r['kind']}\n{r['name']}")
    for b in cluster.bindings:
        G.add_node(b["id"], type="binding", name=b["name"], ns=b["ns"], builtin=False,
                   label=f"{b['kind']}\n{b['name']}")
        G.add_edge(b["id"], b["role"], layer="structure", relation="roleRef")
        for s in b["subjects"]:
            G.add_edge(s["id"], b["id"], layer="structure", relation="subject")
    for pid, p in cluster.pods.items():
        G.add_node(pid, type="pod", name=p["name"], ns=p["ns"], builtin=False,
                   label=f"Pod\n{p['ns']}/{p['name']}")

    grants = effective_grants(cluster)
    for e in derive_edges(cluster, grants, enabled):
        src, dst = e["src"], e["dst"]
        if src not in G or dst not in G:
            continue
        attrs = dict(layer="escalation", primitive=e["primitive"], cost=e["cost"],
                     permission=e["permission"], via_binding=e["via_binding"],
                     via_role=e["via_role"], alternatives=[])
        if G.has_edge(src, dst) and G[src][dst].get("layer") == "escalation":
            old = G[src][dst]
            if e["cost"] < old["cost"]:
                attrs["alternatives"] = old["alternatives"] + [old["primitive"]]
                G[src][dst].update(attrs)
            else:
                old["alternatives"].append(e["primitive"])
        else:
            G.add_edge(src, dst, **attrs)
    return G, grants


def escalation_view(G):
    """Subgraph containing only escalation edges.
    A node that already HOLDS_ADMIN keeps just that edge: nothing it does afterwards
    is an escalation, and keeping its other edges would only inflate the path count."""
    admins = {u for u, v, d in G.edges(data=True) if d.get("primitive") == "HOLDS_ADMIN"}
    edges = [(u, v) for u, v, d in G.edges(data=True)
             if d["layer"] == "escalation" and (u not in admins or d["primitive"] == "HOLDS_ADMIN")]
    return G.edge_subgraph(edges)


def entry_points(G, include_builtin=False):
    """Where an attacker may start: every pod, and every non-built-in subject.
    (Built-in system:* identities are held by control-plane components, not by
    applications, so they are excluded by default.)"""
    return [n for n, d in G.nodes(data=True)
            if d["type"] == "pod" or (d["type"] == "subject" and (include_builtin or not d["builtin"]))]
