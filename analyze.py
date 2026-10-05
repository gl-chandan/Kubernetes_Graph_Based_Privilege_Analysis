#!/usr/bin/env python3
"""
analyze.py  --  run the analyser on ONE cluster snapshot (e.g. a k3s dump or an installed Helm chart).

    python analyze.py data/k3s_snapshot --max-hops 4 --out results/k3s

Writes <out>_paths.csv (ranked), <out>_attack_graph.png and prints a summary.
"""
import argparse
import csv
from collections import Counter
from pathlib import Path

from analyzer.baseline import flat_review, single_step_lint
from analyzer.graph import build_graph, entry_points
from analyzer.paths import enumerate_paths, flagged_entries
from analyzer.plots import plot_attack_graph
from analyzer.snapshot import Cluster


def pick_showcase(paths, k=10):
    """One representative path per flagged entry (cheapest multi-hop if it exists)."""
    best = {}
    for p in paths:                                   # paths are already sorted by cost
        cur = best.get(p.entry)
        if cur is None or (cur.hops < 2 <= p.hops):
            best[p.entry] = p
    return sorted(best.values(), key=lambda p: (p.cost, p.hops))[:k]


def analyze(snapshot_dir, max_hops=4, out="results/k3s", verbose=True):
    cluster = Cluster.from_dir(snapshot_dir)
    G, _ = build_graph(cluster)
    entries = entry_points(G)
    paths = enumerate_paths(G, entries, max_hops=max_hops)
    flagged, flat, lint = flagged_entries(paths), flat_review(G, entries), single_step_lint(G, entries)

    Path(out).parent.mkdir(parents=True, exist_ok=True)
    with open(f"{out}_paths.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rank", "entry", "hops", "total_cost", "exploitability", "path"])
        for i, p in enumerate(paths[:500], 1):
            w.writerow([i, p.entry, p.hops, p.cost, p.score, p.describe(G)])
    plot_attack_graph(G, pick_showcase(paths), f"{out}_attack_graph.png",
                      f"Escalation paths to cluster-admin ({Path(snapshot_dir).name}, one path per entry point)")

    if verbose:
        types = Counter(d["type"] for _, d in G.nodes(data=True))
        prims = Counter(d["primitive"] for _, _, d in G.edges(data=True) if d["layer"] == "escalation")
        print(f"Graph: {G.number_of_nodes()} nodes {dict(types)}, {G.number_of_edges()} edges")
        print(f"Escalation edges by primitive: {dict(prims)}")
        print(f"Entry points: {len(entries)}   paths (<= {max_hops} hops): {len(paths)}")
        print(f"Entry points flagged  flat={len(flat)}  single-step={len(lint)}  graph={len(flagged)}")
        print("Top 10 paths:")
        for p in paths[:10]:
            print(f"  cost={p.cost} hops={p.hops}  {p.describe(G)}")
    return G, paths, entries


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("snapshot", help="directory with serviceaccounts.json, roles.json, ...")
    ap.add_argument("--max-hops", type=int, default=4)
    ap.add_argument("--out", default="results/analysis")
    a = ap.parse_args()
    analyze(a.snapshot, a.max_hops, a.out)
