"""pytest -q   --  unit tests for rule matching, primitives, and planted-chain recovery."""
from analyzer.baseline import flat_review, single_step_lint
from analyzer.graph import build_graph, entry_points
from analyzer.paths import enumerate_paths, flagged_entries
from analyzer.primitives import ALL_PRIMITIVES
from analyzer.rbac import rule_allows
from analyzer.snapshot import TARGET, Cluster, sa_id
from analyzer.synthetic import expected_flagged, make_cluster


def _graph(raw, enabled=ALL_PRIMITIVES):
    G, _ = build_graph(Cluster.from_raw(raw), enabled)
    return G, entry_points(G)


def test_rule_matching_wildcards_and_subresources():
    assert rule_allows({"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}, "create", "pods/exec")
    assert rule_allows({"verbs": ["create"], "resources": ["pods/*"], "apiGroups": [""]}, "create", "pods/exec")
    assert not rule_allows({"verbs": ["get"], "resources": ["pods"], "apiGroups": [""]}, "create", "pods")
    assert not rule_allows({"verbs": ["create"], "resources": ["pods"], "apiGroups": ["apps"]}, "create", "pods")


def test_all_planted_chains_recovered_exactly():
    raw, truth = make_cluster(seed=1)
    G, entries = _graph(raw)
    paths = enumerate_paths(G, entries, max_hops=8)
    for c in truth["chains"]:
        assert any(p.subjects(G) == c["subjects"] for p in paths if p.entry == c["subjects"][0]), c


def test_no_false_positives_and_decoys_not_flagged():
    raw, truth = make_cluster(seed=2)
    G, entries = _graph(raw)
    flagged = flagged_entries(enumerate_paths(G, entries, max_hops=8))
    assert flagged == expected_flagged(truth)
    assert not (flagged & set(truth["decoys"]))


def test_baselines_miss_multi_hop_chains():
    raw, truth = make_cluster((2, 3, 4), 2, seed=3)
    G, entries = _graph(raw)
    entry_sas = {c["subjects"][0] for c in truth["chains"]}
    assert not (flat_review(G, entries) & entry_sas)          # nothing is directly admin at the entry
    assert not (single_step_lint(G, entries) & entry_sas)     # nothing is one step from admin either
    assert entry_sas <= flagged_entries(enumerate_paths(G, entries, 8))


def test_hop_bound_limits_search():
    raw, truth = make_cluster((4,), 1, n_noise_ns=0, n_decoys=False, seed=4)
    G, entries = _graph(raw)
    entry = truth["chains"][0]["subjects"][0]
    assert entry not in flagged_entries(enumerate_paths(G, entries, max_hops=2))
    assert entry in flagged_entries(enumerate_paths(G, entries, max_hops=8))


def test_ranking_prefers_cheap_short_paths():
    raw, _ = make_cluster(seed=5)
    G, entries = _graph(raw)
    paths = enumerate_paths(G, entries, 8)
    assert [p.cost for p in paths] == sorted(p.cost for p in paths)
    assert paths[0].cost == 0 and paths[0].nodes[-1] == TARGET


def test_psa_restricted_blocks_direct_pod_escape():
    raw, _ = make_cluster((1,), 1, n_noise_ns=0, n_decoys=False, seed=6)
    pods_sa = sa_id("chain0-s0", "app-0")
    raw["roles"].append({"metadata": {"name": "mk", "namespace": "chain0-s0"},
                         "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["create"]}]})
    raw["rolebindings"].append({"metadata": {"name": "mk", "namespace": "chain0-s0"},
                                "subjects": [{"kind": "ServiceAccount", "name": "app-0", "namespace": "chain0-s0"}],
                                "roleRef": {"kind": "Role", "name": "mk"}})
    G, _ = _graph(raw)
    assert not G.has_edge("serviceaccount::chain0-s0::default", TARGET)
    # restricted namespace -> no CREATE_PRIVILEGED_POD edge from app-0 via that role
    d = G.get_edge_data(pods_sa, TARGET)
    assert d is None or d["primitive"] != "CREATE_PRIVILEGED_POD"
    # relax the namespace -> the edge appears
    for ns in raw["namespaces"]:
        ns["metadata"]["labels"] = {}
    G, _ = _graph(raw)
    assert G.has_edge(pods_sa, TARGET)
