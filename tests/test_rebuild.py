"""End-to-end tests for POST /plan/rebuild."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _plan(**payload):
    response = client.post("/plan/rebuild", json=payload)
    return response.status_code, response.json()


def _edge(source, source_version, target, target_version):
    return {
        "source": source,
        "source_version": source_version,
        "target": target,
        "target_version": target_version,
    }


DIAMOND_RESOLVED = {
    "app": "1.0",
    "left": "1.0",
    "right": "1.0",
    "shared": "1.5",
}
DIAMOND_GRAPH = [
    _edge("<root>", "", "app", "1.0"),
    _edge("app", "1.0", "left", "1.0"),
    _edge("app", "1.0", "right", "1.0"),
    _edge("left", "1.0", "shared", "1.5"),
    _edge("right", "1.0", "shared", "1.5"),
]


def _groups_by_id(body):
    return {group["id"]: group for group in body["groups"]}


def _names(path):
    return [node["name"] for node in path]


# ---------------------------------------------------------------------------
# Core planning
# ---------------------------------------------------------------------------


def test_diamond_plan_stages_and_paths():
    status, body = _plan(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH,
        changed=["shared"],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["summary"] == {
        "changed": 1,
        "uninstalled": 0,
        "affected": 4,
        "groups": 4,
        "stages": 3,
    }
    assert body["changed"] == ["shared"]
    assert body["uninstalled"] == []
    assert body["affected"] == ["app", "left", "right", "shared"]

    groups = _groups_by_id(body)
    # The changed package is its own (leaf) group and is flagged as changed.
    assert body["stages"][0] == [body["groups"][0]["id"]]
    assert groups[body["stages"][0][0]]["packages"] == ["shared"]
    assert groups[body["stages"][0][0]]["changed"] == ["shared"]

    # left/right share a stage (parallel); app comes after both.
    assert body["stages"] == [
        [body["groups"][0]["id"]],
        [body["groups"][1]["id"], body["groups"][2]["id"]],
        [body["groups"][3]["id"]],
    ]
    middle = {
        name
        for gid in body["stages"][1]
        for name in groups[gid]["packages"]
    }
    assert middle == {"left", "right"}
    top = groups[body["stages"][2][0]]["packages"]
    assert top == ["app"]

    # Every affected package appears in exactly one group/stage.
    staged = {
        name
        for stage in body["stages"]
        for gid in stage
        for name in groups[gid]["packages"]
    }
    assert staged == set(body["affected"])

    paths = {entry["package"]: entry for entry in body["rebuild_paths"]}
    assert paths["shared"]["distance"] == 0
    assert _names(paths["shared"]["path"]) == ["shared"]
    assert paths["left"]["distance"] == 1
    assert _names(paths["left"]["path"]) == ["left", "shared"]
    assert paths["right"]["distance"] == 1
    assert _names(paths["right"]["path"]) == ["right", "shared"]
    # Tied shortest paths from app resolve lexicographically (left < right).
    assert paths["app"]["distance"] == 2
    assert _names(paths["app"]["path"]) == ["app", "left", "shared"]

    # Path nodes carry resolved versions.
    assert paths["app"]["path"][-1] == {"name": "shared", "version": "1.5"}

    # rebuild_paths are ordered by (distance, package name).
    ordered = [(e["distance"], e["package"]) for e in body["rebuild_paths"]]
    assert ordered == sorted(ordered)


def test_unaffected_packages_are_excluded():
    # util is resolved but nothing relevant connects it to the change.
    resolved = dict(DIAMOND_RESOLVED, util="0.9")
    graph = DIAMOND_GRAPH + [_edge("<root>", "", "util", "0.9")]
    status, body = _plan(
        resolved=resolved, dependency_graph=graph, changed=["shared"]
    )
    assert status == 200
    assert "util" not in body["affected"]
    assert all(entry["package"] != "util" for entry in body["rebuild_paths"])


def test_uninstalled_changed_packages_listed_separately():
    status, body = _plan(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH,
        changed=["numpy", "shared"],
    )
    assert status == 200
    assert body["changed"] == ["shared"]
    assert body["uninstalled"] == ["numpy"]
    assert body["summary"]["uninstalled"] == 1
    # Uninstalled seeds do not seed propagation.
    assert "numpy" not in body["affected"]


def test_no_changes_means_empty_plan():
    status, body = _plan(
        resolved=DIAMOND_RESOLVED, dependency_graph=DIAMOND_GRAPH, changed=[]
    )
    assert status == 200
    assert body["summary"] == {
        "changed": 0,
        "uninstalled": 0,
        "affected": 0,
        "groups": 0,
        "stages": 0,
    }
    assert body["affected"] == []
    assert body["groups"] == []
    assert body["stages"] == []
    assert body["rebuild_paths"] == []


def test_all_changed_packages_are_rebuild_leaves():
    # Changing leaf and mid packages: every changed seed has distance 0.
    status, body = _plan(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH,
        changed=["shared", "left"],
    )
    assert status == 200
    assert body["changed"] == ["left", "shared"]
    paths = {entry["package"]: entry for entry in body["rebuild_paths"]}
    assert paths["shared"]["distance"] == 0
    assert paths["left"]["distance"] == 0
    # app's nearest changed package is left (distance 1), not shared (2).
    assert paths["app"]["distance"] == 1
    assert _names(paths["app"]["path"]) == ["app", "left"]
    assert paths["right"]["distance"] == 1
    assert _names(paths["right"]["path"]) == ["right", "shared"]


# ---------------------------------------------------------------------------
# Cycles
# ---------------------------------------------------------------------------


def test_cycle_is_compressed_into_one_group():
    resolved = {"a": "1.0", "b": "1.0", "c": "1.0"}
    graph = [
        _edge("<root>", "", "c", "1.0"),
        _edge("a", "1.0", "b", "1.0"),
        _edge("b", "1.0", "a", "1.0"),
        _edge("c", "1.0", "a", "1.0"),
    ]
    status, body = _plan(resolved=resolved, dependency_graph=graph, changed=["a"])
    assert status == 200
    assert body["summary"]["groups"] == 2
    groups = _groups_by_id(body)
    assert groups[body["stages"][0][0]]["packages"] == ["a", "b"]
    assert groups[body["stages"][0][0]]["changed"] == ["a"]
    assert groups[body["stages"][1][0]]["packages"] == ["c"]
    assert body["stages"] == [
        [body["groups"][0]["id"]],
        [body["groups"][1]["id"]],
    ]
    paths = {entry["package"]: entry for entry in body["rebuild_paths"]}
    assert _names(paths["a"]["path"]) == ["a"]
    assert _names(paths["b"]["path"]) == ["b", "a"]
    assert _names(paths["c"]["path"]) == ["c", "a"]


def test_changed_package_depending_on_changed_package_rebuilds_later():
    # a -> b -> c, with both a and c changed.  "Dependencies before
    # dependents" still applies: c (leaf) is stage 0, b stage 1, a stage 2.
    resolved = {"a": "1.0", "b": "1.0", "c": "1.0"}
    graph = [
        _edge("<root>", "", "a", "1.0"),
        _edge("a", "1.0", "b", "1.0"),
        _edge("b", "1.0", "c", "1.0"),
    ]
    status, body = _plan(
        resolved=resolved, dependency_graph=graph, changed=["a", "c"]
    )
    assert status == 200
    groups = _groups_by_id(body)
    assert [len(stage) for stage in body["stages"]] == [1, 1, 1]
    assert groups[body["stages"][0][0]]["packages"] == ["c"]
    assert groups[body["stages"][1][0]]["packages"] == ["b"]
    assert groups[body["stages"][2][0]]["packages"] == ["a"]
    paths = {entry["package"]: entry for entry in body["rebuild_paths"]}
    assert paths["a"]["distance"] == 0  # a is itself changed
    assert paths["b"]["distance"] == 1
    assert _names(paths["b"]["path"]) == ["b", "c"]


def test_self_loop_does_not_inflate_stages():
    resolved = {"a": "1.0", "b": "1.0"}
    graph = [
        _edge("<root>", "", "b", "1.0"),
        _edge("b", "1.0", "a", "1.0"),
        _edge("a", "1.0", "a", "1.0"),
    ]
    status, body = _plan(resolved=resolved, dependency_graph=graph, changed=["a"])
    assert status == 200
    assert body["summary"]["groups"] == 2
    assert body["stages"] == [
        [body["groups"][0]["id"]],
        [body["groups"][1]["id"]],
    ]


def test_scc_to_scc_dependencies_order_stages():
    # X={x1,x2} -> Y={y1,y2} -> z(changed): three sequential stages.
    resolved = {"x1": "1", "x2": "1", "y1": "1", "y2": "1", "z": "1"}
    graph = [
        _edge("x1", "1", "x2", "1"),
        _edge("x2", "1", "x1", "1"),
        _edge("y1", "1", "y2", "1"),
        _edge("y2", "1", "y1", "1"),
        _edge("x1", "1", "y1", "1"),
        _edge("y1", "1", "z", "1"),
    ]
    status, body = _plan(resolved=resolved, dependency_graph=graph, changed=["z"])
    assert status == 200
    assert body["summary"]["groups"] == 3
    assert [len(stage) for stage in body["stages"]] == [1, 1, 1]
    groups = _groups_by_id(body)
    assert groups[body["stages"][0][0]]["packages"] == ["z"]
    assert groups[body["stages"][1][0]]["packages"] == ["y1", "y2"]
    assert groups[body["stages"][2][0]]["packages"] == ["x1", "x2"]


# ---------------------------------------------------------------------------
# Normalization, roundtrip, determinism
# ---------------------------------------------------------------------------


def test_changed_names_are_canonicalized_and_deduped():
    status, body = _plan(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH,
        changed=["Shared", "SHARED", "Ghost_Pkg"],
    )
    assert status == 200
    assert body["changed"] == ["shared"]
    assert body["uninstalled"] == ["ghost-pkg"]


def test_roundtrip_from_resolve_response():
    resolve_body = client.post(
        "/resolve",
        json={
            "packages": {
                "app": {"1.0": {"dependencies": {"web": ">=2.0", "db": ""}}},
                "web": {
                    "2.0": {"dependencies": {"common": "<2.0"}},
                    "3.0": {"dependencies": {"common": ">=2.0"}},
                },
                "db": {"1.0": {"dependencies": {"common": "==1.5"}}},
                "common": {"1.5": {}, "2.0": {}},
            },
            "root": {"app": ""},
        },
    ).json()
    assert resolve_body["status"] == "ok"

    status, body = _plan(
        resolved=resolve_body["resolved"],
        dependency_graph=resolve_body["dependency_graph"],
        changed=["common"],
    )
    assert status == 200
    assert body["affected"] == ["app", "common", "db", "web"]
    # common first; db/web parallel; app last.
    assert [len(stage) for stage in body["stages"]] == [1, 2, 1]
    groups = _groups_by_id(body)
    assert groups[body["stages"][0][0]]["packages"] == ["common"]
    assert {
        name
        for gid in body["stages"][1]
        for name in groups[gid]["packages"]
    } == {"db", "web"}
    assert groups[body["stages"][2][0]]["packages"] == ["app"]


def test_deterministic_results_regardless_of_edge_order():
    payload = {
        "resolved": DIAMOND_RESOLVED,
        "dependency_graph": DIAMOND_GRAPH,
        "changed": ["shared"],
    }
    first = client.post("/plan/rebuild", json=payload).json()
    # Edge input permutation must not change the plan.
    shuffled = dict(payload, dependency_graph=list(reversed(DIAMOND_GRAPH)))
    second = client.post("/plan/rebuild", json=shuffled).json()
    assert second == first
    results = [
        client.post("/plan/rebuild", json=payload).json() for _ in range(5)
    ]
    assert all(r == first for r in results)


# ---------------------------------------------------------------------------
# 400s / 422s (audit conventions reused)
# ---------------------------------------------------------------------------


def test_invalid_resolved_version_returns_400():
    status, body = _plan(
        resolved={"x": "not-a-version"}, dependency_graph=[], changed=[]
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "PEP 440" in body["error"]["message"]


def test_dangling_edge_returns_400():
    status, body = _plan(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "ghost", "1.0")],
        changed=["app"],
    )
    assert status == 400
    assert "dangling" in body["error"]["message"]


def test_edge_version_inconsistent_with_resolved_returns_400():
    status, body = _plan(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "app", "2.0")],
        changed=["app"],
    )
    assert status == 400
    assert "inconsistent" in body["error"]["message"]


def test_root_edge_with_source_version_returns_400():
    status, body = _plan(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "1.0", "app", "1.0")],
        changed=["app"],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_changed_root_name_returns_400():
    status, body = _plan(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH,
        changed=["<root>"],
    )
    assert status == 400
    assert "reserved" in body["error"]["message"]


def test_changed_empty_name_returns_400():
    status, body = _plan(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH,
        changed=["app", "   "],
    )
    assert status == 400
    assert "must not be empty" in body["error"]["message"]


def test_extra_fields_rejected():
    response = client.post(
        "/plan/rebuild",
        json={
            "resolved": {},
            "dependency_graph": [],
            "changed": [],
            "nope": 1,
        },
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Differential testing against an independent brute-force oracle
# ---------------------------------------------------------------------------


def _oracle_plan(nodes, edges, seeds):
    """Reference plan via Floyd-Warshall reachability + naive SCCs/BFS."""
    n = len(nodes)
    idx = {name: i for i, name in enumerate(nodes)}
    reach = [[i == j for j in range(n)] for i in range(n)]
    adj = {name: set() for name in nodes}
    for s, t in edges:
        reach[idx[s]][idx[t]] = True
        adj[s].add(t)

    for k in range(n):
        for i in range(n):
            if reach[i][k]:
                for j in range(n):
                    if reach[k][j]:
                        reach[i][j] = True

    # Naive SCC: mutually reachable nodes, canonically keyed by min member.
    scc_of = {}
    for a in nodes:
        for b in nodes:
            if reach[idx[a]][idx[b]] and reach[idx[b]][idx[a]]:
                scc_of[(a, b)] = True
    components = []
    seen = set()
    for a in nodes:
        if a in seen:
            continue
        members = [b for b in nodes if scc_of.get((a, b))]
        seen.update(members)
        components.append(sorted(members))

    # Affected: seeds + anyone that can reach a seed via >=1 hop path.
    seed_set = set(seeds)
    affected = set(seeds)
    for a in nodes:
        if any(a != s and reach[idx[a]][idx[s]] for s in seeds):
            affected.add(a)
    return components, adj, affected, seed_set


def test_random_graphs_match_oracle():
    import random

    rng = random.Random(20260918)
    for trial in range(500):
        count = rng.randint(1, 7)
        names = [f"p{i}" for i in range(count)]
        edges = set()
        for s in names:
            for t in names:
                if rng.random() < 0.28:
                    edges.add((s, t))

        resolved = {name: "1.0" for name in names}
        graph = [_edge("<root>", "", names[0], "1.0")]
        graph += [
            _edge(s, "1.0", t, "1.0") for s, t in sorted(edges)
        ]
        seeds = sorted(rng.sample(names, rng.randint(0, count)))
        uninstalled_names = ["ghost"] if rng.random() < 0.3 else []

        components, adj, affected, seed_set = _oracle_plan(names, edges, seeds)

        status, body = _plan(
            resolved=resolved,
            dependency_graph=graph,
            changed=seeds + uninstalled_names,
        )
        assert status == 200, trial
        assert set(body["affected"]) == affected
        assert set(body["changed"]) == seed_set
        assert body["uninstalled"] == uninstalled_names

        # Groups restricted to affected nodes partition the affected set.
        groups = _groups_by_id(body)
        planned = {
            pkg
            for group in body["groups"]
            for pkg in group["packages"]
        }
        assert planned == affected
        # Every reported group really is one SCC of the induced subgraph: all
        # members are mutually reachable within the affected closure.
        induced_edges = {
            (s, t) for s, t in edges if s in affected and t in affected
        }
        oracle_components, _adj, _a, _s = _oracle_plan(
            sorted(affected), induced_edges, seeds
        )
        reported = {frozenset(g["packages"]) for g in body["groups"]}
        # Oracle runs on the whole graph; SCCs intersecting the affected set
        # are fully inside it by definition (affected is reverse-closed).
        oracle_sccs = {
            frozenset(c)
            for c in oracle_components
            if set(c) <= affected
        }
        assert oracle_sccs == reported
        # Stages: dependencies strictly before dependents across groups.
        cid_of = {
            pkg: group["id"]
            for group in body["groups"]
            for pkg in group["packages"]
        }
        stage_of = {
            gid: level
            for level, stage in enumerate(body["stages"])
            for gid in stage
        }
        induced_adj_sets = {name: set() for name in affected}
        for s, t in induced_edges:
            induced_adj_sets[s].add(t)
        for s, t in induced_edges:
            if cid_of[s] != cid_of[t]:
                assert stage_of[cid_of[s]] > stage_of[cid_of[t]]
        # Oracle for the stage number: longest forward path (in condensation
        # hops) from each component down to a component with no further
        # dependencies.  Seed components that sit above other seed
        # components therefore rebuild later: "dependencies before
        # dependents" is the only ordering rule.
        def oracle_stage(cid, seen=None):
            if seen is None:
                seen = frozenset()
            if cid in seen:
                return 0
            seen = seen | {cid}
            dep_components = {
                cid_of[t]
                for pkg in groups[cid]["packages"]
                for t in induced_adj_sets[pkg]
                if cid_of[t] != cid
            }
            if not dep_components:
                return 0
            return 1 + max(oracle_stage(d, seen) for d in dep_components)

        for cid in stage_of:
            assert stage_of[cid] == oracle_stage(cid)

        # Distance/path oracle: reverse multi-source BFS from the seeds,
        # then the lexicographically smallest path that follows the level
        # edges to a seed.  Mirrors the level-DAG approach used by the audit
        # path enumerator.
        rev_adj = {name: set() for name in affected}
        for s, ts in induced_adj_sets.items():
            for t in ts:
                rev_adj[t].add(s)
        distances = {seed: 0 for seed in seed_set}
        queue = list(seed_set)
        while queue:
            cur = queue.pop(0)
            for dependent in sorted(rev_adj.get(cur, ())):
                if dependent not in distances:
                    distances[dependent] = distances[cur] + 1
                    queue.append(dependent)

        def shortest(node):
            path = [node]
            cur = node
            while distances[cur] > 0:
                nxt = min(
                    dep
                    for dep in induced_adj_sets[cur]
                    if distances.get(dep) == distances[cur] - 1
                )
                path.append(nxt)
                cur = nxt
            return path

        paths = {entry["package"]: entry for entry in body["rebuild_paths"]}
        assert set(paths) == affected
        for pkg, entry in paths.items():
            oracle_path = shortest(pkg)
            assert _names(entry["path"]) == oracle_path
            assert entry["distance"] == len(oracle_path) - 1

