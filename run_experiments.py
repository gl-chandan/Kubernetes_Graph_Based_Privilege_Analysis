#!/usr/bin/env python3
"""
run_experiments.py  --  reproduces every number and figure for Review 2.   python run_experiments.py

  Exp 1  Real k3s snapshot          -> results/k3s_*            (O1, O2 on a real cluster)
  Exp 2  Planted-chain validation   -> results/validation*.csv  (recall, false positives)
  Exp 3  Baseline vs graph          -> results/baseline_comparison.{csv,png}
  Exp 4  Ablation + max_hops sweep  -> results/ablation.*, hop_sweep.*
  Exp 5  Runtime vs cluster size    -> results/scale.*
"""
import json
import statistics
import time
from pathlib import Path

import pandas as pd

from analyze import analyze
from analyzer import plots
from analyzer.baseline import flat_review, single_step_lint
from analyzer.graph import build_graph, entry_points
from analyzer.paths import enumerate_paths, flagged_entries
from analyzer.primitives import ALL_PRIMITIVES
from analyzer.snapshot import Cluster
from analyzer.synthetic import cluster_size_variant, expected_flagged, make_cluster

OUT = Path("results")
OUT.mkdir(exist_ok=True)
K3S_DIR = "data/k3s_snapshot"
K3S_HOPS, SYN_HOPS = 4, 8            # chain of 5 hops (+1 per POD_EXEC, which goes via a pod node) needs 8
METHODS = ["Flat review (can-i)", "Single-step lint", "Graph (this work)"]


def prepare(raw=None, enabled=ALL_PRIMITIVES):
    cluster = Cluster.from_raw(raw) if raw is not None else Cluster.from_dir(K3S_DIR)
    G, _ = build_graph(cluster, enabled)
    return G, entry_points(G)


def chain_found(G, paths, chain):
    return any(p.subjects(G) == chain["subjects"] for p in paths if p.entry == chain["subjects"][0])


def planted_clusters():
    return {
        "planted-S": make_cluster((1, 2, 3), 1, n_noise_ns=3, seed=1),
        "planted-M": make_cluster((1, 2, 3, 4, 5), 2, n_noise_ns=10, seed=2),
        "planted-L": make_cluster((1, 2, 3, 4, 5), 4, n_noise_ns=40, seed=3),
    }


# --------------------------------------------------------------------------- Exp 1
def exp1_k3s():
    print("\n=== Exp 1: real k3s snapshot ===")
    G, paths, entries = analyze(K3S_DIR, max_hops=K3S_HOPS, out=str(OUT / "k3s"))
    plots.plot_full_graph(G, OUT / "k3s_full_graph.png", "k3s default install: full access-control graph")
    # small planted cluster drawn in full for the O1 figure
    raw, truth = make_cluster((3,), 1, n_noise_ns=1, seed=0, n_decoys=True)
    G2, E2 = prepare(raw)
    plots.plot_full_graph(G2, OUT / "graph_structure_demo.png", "Synthetic cluster with one planted 3-hop chain + decoys")
    P2 = enumerate_paths(G2, E2, SYN_HOPS)
    chain = truth["chains"][0]
    shown = [p for p in P2 if p.entry == chain["subjects"][0]][:1]
    plots.plot_attack_graph(G2, shown, OUT / "planted_chain_path.png",
                            f"Planted chain recovered: {' → '.join(chain['hops'] + [chain['terminal']])}")
    return G, paths, entries


# --------------------------------------------------------------------------- Exp 2
def exp2_validation():
    print("\n=== Exp 2: validation on planted chains ===")
    rows, fp_rows = [], []
    for L in (1, 2, 3, 4, 5):
        raw, truth = make_cluster((L,), 8, n_noise_ns=10, seed=10 + L)
        G, entries = prepare(raw)
        paths = enumerate_paths(G, entries, SYN_HOPS)
        found = {"Flat review (can-i)": flat_review(G, entries),
                 "Single-step lint": single_step_lint(G, entries),
                 "Graph (this work)": flagged_entries(paths)}
        exp = expected_flagged(truth)
        for m in METHODS:
            hit = sum(c["subjects"][0] in found[m] for c in truth["chains"])
            if m == "Graph (this work)":                     # graph must also recover the exact chain
                hit = sum(chain_found(G, paths, c) for c in truth["chains"])
            rows.append(dict(method=m, chain_length=L, planted=len(truth["chains"]), found=hit,
                             recall=hit / len(truth["chains"])))
            fp = found[m] - exp
            fp_rows.append(dict(method=m, chain_length=L, flagged=len(found[m]), false_positives=len(fp),
                                decoys_flagged=len(found[m] & set(truth["decoys"]))))
    rec, fp = pd.DataFrame(rows), pd.DataFrame(fp_rows)
    rec.to_csv(OUT / "validation_recall.csv", index=False)
    fp.to_csv(OUT / "validation_false_positives.csv", index=False)
    plots.plot_recall_by_length(rec, OUT / "validation_recall.png")
    g = rec[rec.method == "Graph (this work)"]
    gfp = fp[fp.method == "Graph (this work)"]
    print(rec.pivot(index="chain_length", columns="method", values="recall").round(2))
    print(f"graph: found {g.found.sum()}/{g.planted.sum()} planted chains; "
          f"false positives {gfp.false_positives.sum()} / flagged {gfp.flagged.sum()}; "
          f"decoys flagged {gfp.decoys_flagged.sum()}")
    return rec, fp


# --------------------------------------------------------------------------- Exp 3
def exp3_baseline():
    print("\n=== Exp 3: baseline vs graph (same clusters) ===")
    rows = []
    clusters = {"k3s (real)": (None, K3S_HOPS)}
    clusters.update({k: (v[0], SYN_HOPS) for k, v in planted_clusters().items()})
    for name, (raw, hops) in clusters.items():
        G, entries = prepare(raw)
        paths = enumerate_paths(G, entries, hops)
        res = {"Flat review (can-i)": flat_review(G, entries), "Single-step lint": single_step_lint(G, entries),
               "Graph (this work)": flagged_entries(paths)}
        for m in METHODS:
            rows.append(dict(cluster=name, method=m, flagged=len(res[m]), entries=len(entries)))
        print(f"{name:12s} entries={len(entries):3d}  " + "  ".join(f"{m.split()[0]}={len(res[m])}" for m in METHODS))
    df = pd.DataFrame(rows)
    df.to_csv(OUT / "baseline_comparison.csv", index=False)
    plots.plot_baseline_comparison(df, OUT / "baseline_comparison.png")
    return df


# --------------------------------------------------------------------------- Exp 4
def exp4_ablation_sweep():
    print("\n=== Exp 4a: max_hops sweep ===")
    rows = []
    raw_m, truth_m = planted_clusters()["planted-M"]
    for name, raw in (("k3s (real)", None), ("planted-M", raw_m)):
        G, entries = prepare(raw)
        for h in range(1, 8):
            paths = enumerate_paths(G, entries, h, max_paths_per_entry=2000)
            rows.append(dict(cluster=name, max_hops=h, flagged=len(flagged_entries(paths)), paths=len(paths)))
    sweep = pd.DataFrame(rows)
    sweep.to_csv(OUT / "hop_sweep.csv", index=False)
    plots.plot_hop_sweep(sweep, OUT / "hop_sweep.png")
    print(sweep.pivot(index="max_hops", columns="cluster", values="flagged"))

    print("\n=== Exp 4b: leave-one-primitive-out ablation ===")
    rows = []
    for removed in ["(none - full model)"] + sorted(ALL_PRIMITIVES):
        enabled = ALL_PRIMITIVES if removed.startswith("(") else ALL_PRIMITIVES - {removed}
        G, entries = prepare(raw_m, enabled)
        P = enumerate_paths(G, entries, SYN_HOPS)
        rec = sum(chain_found(G, P, c) for c in truth_m["chains"]) / len(truth_m["chains"])
        Gk, Ek = prepare(None, enabled)
        Pk = enumerate_paths(Gk, Ek, K3S_HOPS)
        rows.append(dict(removed=removed, recall_planted=rec, k3s_flagged=len(flagged_entries(Pk)),
                         k3s_paths=len(Pk)))
    abl = pd.DataFrame(rows)
    abl.to_csv(OUT / "ablation.csv", index=False)
    plots.plot_ablation(abl, OUT / "ablation.png")
    print(abl.to_string(index=False))
    return sweep, abl


# --------------------------------------------------------------------------- Exp 5
def timed(fn):
    t = time.perf_counter()
    r = fn()
    return r, time.perf_counter() - t


def exp5_scale():
    print("\n=== Exp 5: runtime vs cluster size ===")
    rows = []
    for n in (50, 100, 200, 400, 800, 1600, 3200):
        raw, _ = cluster_size_variant(n, seed=5)
        tb, te, tbase = [], [], []
        for _ in range(3):
            (G, ent), t1 = timed(lambda: prepare(raw))
            P, t2 = timed(lambda: enumerate_paths(G, ent, SYN_HOPS))
            _, t3 = timed(lambda: (flat_review(G, ent), single_step_lint(G, ent)))
            tb.append(t1); te.append(t2); tbase.append(t3)
        rows.append(dict(subjects=sum(1 for _, d in G.nodes(data=True) if d["type"] == "subject"),
                         graph_nodes=G.number_of_nodes(), graph_edges=G.number_of_edges(),
                         build_s=statistics.median(tb), enumerate_s=statistics.median(te),
                         graph_total_s=statistics.median(tb) + statistics.median(te),
                         baseline_s=statistics.median(tbase), paths=len(P)))
    df = pd.DataFrame(rows)
    df.to_csv(OUT / "scale.csv", index=False)
    plots.plot_scale(df, OUT / "scale.png")
    print(df.round(4).to_string(index=False))
    return df


if __name__ == "__main__":
    exp1_k3s()
    exp2_validation()
    exp3_baseline()
    exp4_ablation_sweep()
    exp5_scale()
    print("\nDone. Figures and CSVs are in results/")
