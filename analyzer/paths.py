
from dataclasses import dataclass

import networkx as nx

from .graph import entry_points, escalation_view
from .snapshot import TARGET


@dataclass
class EscalationPath:
    nodes: list
    steps: list          # edge-attribute dicts, one per hop
    cost: int
    score: float

    @property
    def hops(self):
        return len(self.steps)

    @property
    def entry(self):
        return self.nodes[0]

    def subjects(self, G):
        """The path with pods removed (used to compare against planted chains)."""
        return [n for n in self.nodes if G.nodes[n]["type"] == "subject"]

    def describe(self, G):
        label = lambda n: G.nodes[n]["label"].replace("\n", " ")
        s = label(self.nodes[0])
        for n, st in zip(self.nodes[1:], self.steps):
            s += f"  --[{st['primitive']}]-->  {label(n)}"
        return s


def enumerate_paths(G, entries=None, max_hops=6, max_paths_per_entry=10_000):
    EV = escalation_view(G)
    if TARGET not in EV:
        return []
    useful = nx.ancestors(EV, TARGET) | {TARGET}          # prune dead ends
    H = EV.subgraph(useful)
    entries = entry_points(G) if entries is None else entries
    out = []
    for e in entries:
        if e not in H:
            continue
        for k, nodes in enumerate(nx.all_simple_paths(H, e, TARGET, cutoff=max_hops)):
            if k >= max_paths_per_entry:
                break
            steps = [H[u][v] for u, v in zip(nodes, nodes[1:])]
            cost = sum(s["cost"] for s in steps)
            out.append(EscalationPath(nodes, steps, cost, round(10 / (1 + cost), 2)))
    out.sort(key=lambda p: (p.cost, p.hops, p.nodes))
    return out


def flagged_entries(paths):
    return {p.entry for p in paths}
