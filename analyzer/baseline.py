
from .snapshot import TARGET


def _direct(G, node, only_admin):
    d = G.get_edge_data(node, TARGET)
    return bool(d) and d["layer"] == "escalation" and (not only_admin or d["primitive"] == "HOLDS_ADMIN")


def _identity(G, node):
    """Subject whose permissions this entry point carries (pod -> its SA)."""
    if G.nodes[node]["type"] == "pod":
        for _, v, d in G.out_edges(node, data=True):
            if d.get("primitive") == "TOKEN_MOUNT":
                return v
        return None
    return node


def flat_review(G, entries):
    out = set()
    for e in entries:
        ident = _identity(G, e)
        if ident is not None and _direct(G, ident, only_admin=True):
            out.add(e)
    return out


def single_step_lint(G, entries):
    out = set()
    for e in entries:
        ident = _identity(G, e)
        if _direct(G, e, False) or (ident is not None and _direct(G, ident, False)):
            out.add(e)
    return out
