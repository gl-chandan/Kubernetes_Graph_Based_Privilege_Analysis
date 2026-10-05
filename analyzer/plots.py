
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

TYPE_COLOR = {"subject": "#8ecae6", "pod": "#cdb4db", "target": "#e63946",
              "role": "#b7e4c7", "binding": "#ffd166"}
METHOD_COLOR = {"Flat review (can-i)": "#adb5bd", "Single-step lint": "#f4a261", "Graph (this work)": "#2a9d8f"}


def _wrap(label, width=19):
    """Wrap node labels so they fit inside their box."""
    import textwrap
    out = []
    for line in label.replace("serviceaccount::", "").split("\n"):
        out += textwrap.wrap(line.replace("/", "/ "), width, break_long_words=True) or [""]
    return "\n".join(l.replace("/ ", "/") for l in out)


def _save(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=200, bbox_inches="tight")
    plt.close(fig)


def plot_attack_graph(G, paths, path_out, title, max_paths=10):
    """Layered drawing: entry points on the left, CLUSTER-ADMIN on the right,
    each edge labelled with the escalation primitive used."""
    paths = paths[:max_paths]
    if not paths:
        return
    depth = {}
    for p in paths:                              # column = distance from the end of the path
        for i, n in enumerate(p.nodes):
            depth[n] = min(depth.get(n, 99), len(p.nodes) - 1 - i)
    D = nx.DiGraph()
    for p in paths:
        for u, v, st in zip(p.nodes, p.nodes[1:], p.steps):
            D.add_edge(u, v, label=st["primitive"])
    cols = {}
    for n, d in depth.items():
        cols.setdefault(d, []).append(n)
    pos = {}
    for d, nodes in cols.items():
        for k, n in enumerate(sorted(nodes)):
            pos[n] = (-d * 3.2, (len(nodes) - 1) / 2 * 1.6 - k * 1.6)
    fig, ax = plt.subplots(figsize=(3.4 * (max(depth.values()) + 1) + 3, 1.5 * max(len(v) for v in cols.values()) + 2))
    nx.draw_networkx_nodes(D, pos, ax=ax, node_size=6200, node_shape="s",
                           node_color=[TYPE_COLOR[G.nodes[n]["type"]] for n in D], edgecolors="#333")
    nx.draw_networkx_labels(D, pos, ax=ax, font_size=7,
                            labels={n: _wrap(G.nodes[n]["label"]) for n in D})
    nx.draw_networkx_edges(D, pos, ax=ax, arrows=True, arrowsize=14, edge_color="#555",
                           node_size=6200, node_shape="s", connectionstyle="arc3,rad=0.08")
    nx.draw_networkx_edge_labels(D, pos, ax=ax, edge_labels=nx.get_edge_attributes(D, "label"),
                                 font_size=6.5, font_color="#9d0208", rotate=False,
                                 bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none", alpha=0.85))
    ax.set_title(title, fontsize=11)
    ax.axis("off")
    _save(fig, path_out)


def plot_baseline_comparison(df, path_out):
    """Grouped bars: entry points flagged by each method, per cluster (same axes)."""
    clusters = list(df["cluster"].unique())
    fig, ax = plt.subplots(figsize=(8, 4.5))
    w = 0.26
    for i, m in enumerate(METHOD_COLOR):
        sub = df[df["method"] == m].set_index("cluster").loc[clusters]
        xs = [k + (i - 1) * w for k in range(len(clusters))]
        bars = ax.bar(xs, sub["flagged"], w, label=m, color=METHOD_COLOR[m])
        ax.bar_label(bars, fontsize=8)
    ax.set_xticks(range(len(clusters)))
    ax.set_xticklabels(clusters, fontsize=9)
    ax.set_ylabel("Entry points with a route to cluster-admin")
    ax.set_title("Baseline vs. graph analysis (same clusters, same axes)")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    _save(fig, path_out)


def plot_recall_by_length(df, path_out):
    """Recall of planted chains vs. chain length for each method."""
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    for m, c in METHOD_COLOR.items():
        sub = df[df["method"] == m]
        ax.plot(sub["chain_length"], sub["recall"], marker="o", label=m, color=c, lw=2)
    ax.set_xlabel("Planted chain length (number of escalation hops)")
    ax.set_ylabel("Recall on planted chains")
    ax.set_ylim(-0.05, 1.08)
    ax.set_xticks(sorted(df["chain_length"].unique()))
    ax.set_title("Flat/single-step review degrade as chains get longer")
    ax.legend(loc="center right")
    ax.grid(alpha=0.3)
    _save(fig, path_out)


def plot_hop_sweep(df, path_out):
    """Parameter sweep: flagged entries and enumerated paths vs. max_hops."""
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for cl, sub in df.groupby("cluster"):
        axes[0].plot(sub["max_hops"], sub["flagged"], marker="o", label=cl, lw=2)
        axes[1].plot(sub["max_hops"], sub["paths"], marker="o", label=cl, lw=2)
    axes[0].set_ylabel("Entry points flagged")
    axes[1].set_ylabel("Paths enumerated (log scale)")
    axes[1].set_yscale("log")
    for a in axes:
        a.set_xlabel("Path-length bound (max_hops)")
        a.grid(alpha=0.3)
        a.legend()
    axes[0].set_title("Coverage saturates")
    axes[1].set_title("Path count keeps growing")
    _save(fig, path_out)


def plot_ablation(df, path_out):
    """Leave-one-primitive-out: loss in flagged entry points and in planted-chain recall."""
    d = df.sort_values("recall_planted")
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.6), sharey=True)
    axes[0].barh(d["removed"], d["recall_planted"], color="#2a9d8f")
    axes[0].set_xlabel("Planted-chain recall")
    axes[0].set_title("Planted clusters")
    axes[1].barh(d["removed"], d["k3s_flagged"], color="#e76f51")
    axes[1].set_xlabel("Entry points flagged")
    axes[1].set_title("Real k3s snapshot")
    for a in axes:
        a.grid(axis="x", alpha=0.3)
    fig.suptitle("Ablation: remove one escalation primitive at a time", fontsize=11)
    _save(fig, path_out)


def plot_scale(df, path_out):
    fig, ax = plt.subplots(figsize=(6.5, 4.2))
    ax.plot(df["graph_nodes"], df["graph_total_s"], marker="o", lw=2, label="Graph analysis (build + enumerate)",
            color=METHOD_COLOR["Graph (this work)"])
    ax.plot(df["graph_nodes"], df["baseline_s"], marker="s", lw=2, label="Baselines (flat + lint)",
            color=METHOD_COLOR["Single-step lint"])
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("Graph size (nodes)")
    ax.set_ylabel("Runtime (seconds, median of 3)")
    ax.set_title("Analysis runtime as cluster size grows")
    ax.legend(); ax.grid(alpha=0.3, which="both")
    _save(fig, path_out)


def plot_full_graph(G, path_out, title):
    """Whole (small) graph: all node types, structure edges grey, escalation edges red + labelled."""
    nodes = [n for n, d in G.nodes(data=True)
             if not (d["type"] == "subject" and d["name"] == "default")]       # hide idle default SAs
    H = G.subgraph(nodes)
    pos = nx.spring_layout(H, seed=7, k=1.1, iterations=200)
    fig, ax = plt.subplots(figsize=(13, 9))
    for t, c in TYPE_COLOR.items():
        ns = [n for n in H if H.nodes[n]["type"] == t]
        nx.draw_networkx_nodes(H, pos, nodelist=ns, node_color=c, node_size=700 if t != "target" else 1800,
                               ax=ax, edgecolors="#333", label=t)
    struct = [(u, v) for u, v, d in H.edges(data=True) if d["layer"] == "structure"]
    esc = [(u, v) for u, v, d in H.edges(data=True) if d["layer"] == "escalation"]
    nx.draw_networkx_edges(H, pos, edgelist=struct, edge_color="#aaa", arrows=True, arrowsize=8, ax=ax, node_size=700)
    nx.draw_networkx_edges(H, pos, edgelist=esc, edge_color="#d00000", arrows=True, arrowsize=12,
                           width=1.4, ax=ax, node_size=700, connectionstyle="arc3,rad=0.1")
    nx.draw_networkx_edge_labels(H, pos, ax=ax, font_size=5.5, font_color="#9d0208", rotate=False,
                                 edge_labels={(u, v): H[u][v]["primitive"] for u, v in esc})
    nx.draw_networkx_labels(H, pos, ax=ax, font_size=5,
                            labels={n: H.nodes[n]["label"].replace("serviceaccount::", "") for n in H})
    ax.legend(scatterpoints=1, fontsize=8, loc="lower left")
    ax.set_title(title + "\n(grey = structure: subject→binding→role;  red = escalation edge derived from a permission / pod spec)",
                 fontsize=10)
    ax.axis("off")
    _save(fig, path_out)
