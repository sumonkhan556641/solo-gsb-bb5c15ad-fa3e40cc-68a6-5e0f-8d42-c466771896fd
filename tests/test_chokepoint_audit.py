"""End-to-end tests for POST /audit/dependency-chokepoints."""

import random

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _audit(**payload):
    response = client.post("/audit/dependency-chokepoints", json=payload)
    return response.status_code, response.json()


def _edge(source, source_version, target, target_version):
    return {
        "source": source,
        "source_version": source_version,
        "target": target,
        "target_version": target_version,
    }


DIAMOND_RESOLVED = {"app": "1.0", "left": "1.0", "right": "1.0", "shared": "1.5"}
DIAMOND_GRAPH = [
    _edge("<root>", "", "app", "1.0"),
    _edge("app", "1.0", "left", "1.0"),
    _edge("app", "1.0", "right", "1.0"),
    _edge("left", "1.0", "shared", "1.5"),
    _edge("right", "1.0", "shared", "1.5"),
]


def _by_package(entries):
    return {entry["package"]: entry for entry in entries}


# ---------------------------------------------------------------------------
# Core domination logic
# ---------------------------------------------------------------------------


def test_diamond_only_app_is_a_chokepoint():
    status, body = _audit(resolved=DIAMOND_RESOLVED, dependency_graph=DIAMOND_GRAPH)
    assert status == 200
    assert body["status"] == "ok"
    assert body["summary"] == {
        "packages": 4,
        "reachable": 4,
        "unreachable": 0,
        "chokepoints": 1,
    }
    assert body["unreachable"] == []

    packages = _by_package(body["packages"])
    assert set(packages) == {"app", "left", "right", "shared"}
    assert packages["app"]["required_dependencies"] == []
    assert packages["left"]["required_dependencies"] == ["app"]
    assert packages["right"]["required_dependencies"] == ["app"]
    # Neither branch gates shared: it is reachable via left OR right.
    assert packages["shared"]["required_dependencies"] == ["app"]
    # Packages carry their resolved versions.
    assert packages["shared"]["version"] == "1.5"

    (gate,) = body["chokepoints"]
    assert gate == {
        "package": "app",
        "version": "1.0",
        "exclusive_count": 3,
        "exclusive_dominees": ["left", "right", "shared"],
    }


def test_linear_chain_every_upstream_link_is_mandatory():
    resolved = {"a": "1.0", "b": "1.0", "c": "1.0"}
    graph = [
        _edge("<root>", "", "a", "1.0"),
        _edge("a", "1.0", "b", "1.0"),
        _edge("b", "1.0", "c", "1.0"),
    ]
    status, body = _audit(resolved=resolved, dependency_graph=graph)
    assert status == 200
    packages = _by_package(body["packages"])
    assert packages["a"]["required_dependencies"] == []
    assert packages["b"]["required_dependencies"] == ["a"]
    assert packages["c"]["required_dependencies"] == ["a", "b"]
    # Chokepoints sort by exclusive_count desc, then package name.
    assert body["chokepoints"] == [
        {
            "package": "a",
            "version": "1.0",
            "exclusive_count": 2,
            "exclusive_dominees": ["b", "c"],
        },
        {
            "package": "b",
            "version": "1.0",
            "exclusive_count": 1,
            "exclusive_dominees": ["c"],
        },
    ]


def test_cycle_nodes_still_dominated_by_the_package_gating_the_scc():
    # root -> a <-> b (plus a self loop): a gates entry into the {a, b} cycle.
    status, body = _audit(
        resolved={"a": "1.0", "b": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "a", "1.0"),
            _edge("a", "1.0", "b", "1.0"),
            _edge("b", "1.0", "a", "1.0"),
            _edge("a", "1.0", "a", "1.0"),
        ],
    )
    assert status == 200
    packages = _by_package(body["packages"])
    assert packages["a"]["required_dependencies"] == []
    assert packages["b"]["required_dependencies"] == ["a"]
    assert body["chokepoints"] == [
        {
            "package": "a",
            "version": "1.0",
            "exclusive_count": 1,
            "exclusive_dominees": ["b"],
        }
    ]


def test_cycle_with_diamond_entry_into_the_scc():
    # root -> a; a -> b, a -> c; b -> d; c -> d; d -> b.
    # a alone dominates the {b, c, d} cluster; nothing inside it dominates
    # another member (b and c both reach d; d loops back to b).
    resolved = {"a": "1.0", "b": "1.0", "c": "1.0", "d": "1.0"}
    graph = [
        _edge("<root>", "", "a", "1.0"),
        _edge("a", "1.0", "b", "1.0"),
        _edge("a", "1.0", "c", "1.0"),
        _edge("b", "1.0", "d", "1.0"),
        _edge("c", "1.0", "d", "1.0"),
        _edge("d", "1.0", "b", "1.0"),
    ]
    status, body = _audit(resolved=resolved, dependency_graph=graph)
    assert status == 200
    packages = _by_package(body["packages"])
    assert packages["a"]["required_dependencies"] == []
    assert packages["b"]["required_dependencies"] == ["a"]
    assert packages["c"]["required_dependencies"] == ["a"]
    assert packages["d"]["required_dependencies"] == ["a"]
    (gate,) = body["chokepoints"]
    assert gate["package"] == "a"
    assert gate["exclusive_count"] == 3
    assert gate["exclusive_dominees"] == ["b", "c", "d"]


def test_deep_package_behind_a_diamond_has_no_mandatory_dep_but_its_own_leaf_is_gated():
    # Two parallel root requirements both reach c; only c leads to d.
    resolved = {"a": "1.0", "b": "1.0", "c": "1.0", "d": "1.0"}
    graph = [
        _edge("<root>", "", "a", "1.0"),
        _edge("<root>", "", "b", "1.0"),
        _edge("a", "1.0", "c", "1.0"),
        _edge("b", "1.0", "c", "1.0"),
        _edge("c", "1.0", "d", "1.0"),
    ]
    status, body = _audit(resolved=resolved, dependency_graph=graph)
    assert status == 200
    packages = _by_package(body["packages"])
    assert packages["c"]["required_dependencies"] == []
    assert packages["d"]["required_dependencies"] == ["c"]
    (gate,) = body["chokepoints"]
    assert gate == {
        "package": "c",
        "version": "1.0",
        "exclusive_count": 1,
        "exclusive_dominees": ["d"],
    }


def test_chokepoints_sorted_by_count_then_name():
    # a -> a1 -> a2 (a owns two), b -> b1 (b owns one, a1 owns one).
    resolved = {"a": "1.0", "a1": "1.0", "a2": "1.0", "b": "1.0", "b1": "1.0"}
    graph = [
        _edge("<root>", "", "a", "1.0"),
        _edge("<root>", "", "b", "1.0"),
        _edge("a", "1.0", "a1", "1.0"),
        _edge("a1", "1.0", "a2", "1.0"),
        _edge("b", "1.0", "b1", "1.0"),
    ]
    status, body = _audit(resolved=resolved, dependency_graph=graph)
    assert status == 200
    assert [entry["package"] for entry in body["chokepoints"]] == ["a", "a1", "b"]
    assert [entry["exclusive_count"] for entry in body["chokepoints"]] == [2, 1, 1]
    # Packages are sorted by name independently.
    assert [entry["package"] for entry in body["packages"]] == [
        "a",
        "a1",
        "a2",
        "b",
        "b1",
    ]
    packages = _by_package(body["packages"])
    assert packages["a2"]["required_dependencies"] == ["a", "a1"]
    assert packages["b1"]["required_dependencies"] == ["b"]


# ---------------------------------------------------------------------------
# Unreachable packages
# ---------------------------------------------------------------------------


def test_unreachable_packages_are_listed_separately():
    status, body = _audit(
        resolved={"app": "1.0", "ghost": "1.0", "zombie": "2.0"},
        dependency_graph=[_edge("<root>", "", "app", "1.0")],
    )
    assert status == 200
    assert body["summary"] == {
        "packages": 3,
        "reachable": 1,
        "unreachable": 2,
        "chokepoints": 0,
    }
    assert [entry["package"] for entry in body["packages"]] == ["app"]
    assert body["chokepoints"] == []
    assert body["unreachable"] == [
        {"package": "ghost", "version": "1.0"},
        {"package": "zombie", "version": "2.0"},
    ]


def test_edges_between_unreachable_packages_do_not_create_reachability():
    status, body = _audit(
        resolved={"app": "1.0", "u1": "1.0", "u2": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("u1", "1.0", "u2", "1.0"),
        ],
    )
    assert status == 200
    assert body["summary"]["reachable"] == 1
    assert [entry["package"] for entry in body["unreachable"]] == ["u1", "u2"]


def test_empty_graph_audits_everything_as_unreachable():
    status, body = _audit(resolved={"x": "1.0"}, dependency_graph=[])
    assert status == 200
    assert body == {
        "status": "ok",
        "summary": {"packages": 1, "reachable": 0, "unreachable": 1, "chokepoints": 0},
        "packages": [],
        "chokepoints": [],
        "unreachable": [{"package": "x", "version": "1.0"}],
    }


def test_empty_input():
    status, body = _audit(resolved={}, dependency_graph=[])
    assert status == 200
    assert body == {
        "status": "ok",
        "summary": {"packages": 0, "reachable": 0, "unreachable": 0, "chokepoints": 0},
        "packages": [],
        "chokepoints": [],
        "unreachable": [],
    }


# ---------------------------------------------------------------------------
# Roundtrip, determinism, normalization
# ---------------------------------------------------------------------------


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

    status, body = _audit(
        resolved=resolve_body["resolved"],
        dependency_graph=resolve_body["dependency_graph"],
    )
    assert status == 200
    packages = _by_package(body["packages"])
    assert packages["app"]["required_dependencies"] == []
    assert packages["db"]["required_dependencies"] == ["app"]
    assert packages["web"]["required_dependencies"] == ["app"]
    assert packages["common"]["required_dependencies"] == ["app"]
    (gate,) = body["chokepoints"]
    assert gate["package"] == "app"
    assert gate["exclusive_count"] == 3
    assert gate["exclusive_dominees"] == ["common", "db", "web"]


def test_deterministic_and_independent_of_edge_order():
    payload = {"resolved": DIAMOND_RESOLVED, "dependency_graph": DIAMOND_GRAPH}
    baseline = client.post("/audit/dependency-chokepoints", json=payload).json()
    assert all(
        client.post("/audit/dependency-chokepoints", json=payload).json() == baseline
        for _ in range(5)
    )

    shuffled = DIAMOND_GRAPH[:]
    random.Random(7).shuffle(shuffled)
    shuffled_payload = {
        "resolved": DIAMOND_RESOLVED,
        "dependency_graph": shuffled + shuffled[:2],  # duplicates collapse
    }
    assert (
        client.post("/audit/dependency-chokepoints", json=shuffled_payload).json()
        == baseline
    )


def test_package_names_are_canonicalized():
    status, body = _audit(
        resolved={"Foo_Bar": "1.0", "baz-qux": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "foo-bar", "1.0"),
            _edge("foo.bar", "1.0", "Baz.Qux", "1.0"),
        ],
    )
    assert status == 200
    packages = _by_package(body["packages"])
    assert set(packages) == {"foo-bar", "baz-qux"}
    assert packages["baz-qux"]["required_dependencies"] == ["foo-bar"]


# ---------------------------------------------------------------------------
# 400s (shared graph validation)
# ---------------------------------------------------------------------------


def test_dangling_target_returns_400():
    status, body = _audit(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "ghost", "1.0")],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "dangling" in body["error"]["message"]


def test_dangling_source_returns_400():
    status, body = _audit(
        resolved={"app": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("ghost", "1.0", "app", "1.0"),
        ],
    )
    assert status == 400
    assert "dangling" in body["error"]["message"]


def test_edge_version_inconsistent_with_resolved_returns_400():
    status, body = _audit(
        resolved={"app": "1.0", "lib": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("app", "9.9", "lib", "1.0"),
        ],
    )
    assert status == 400
    assert "inconsistent" in body["error"]["message"]


def test_invalid_resolved_version_returns_400():
    status, body = _audit(resolved={"x": "not-a-version"}, dependency_graph=[])
    assert status == 400
    assert "PEP 440" in body["error"]["message"]


def test_root_edge_with_source_version_returns_400():
    status, body = _audit(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "1.0", "app", "1.0")],
    )
    assert status == 400


def test_extra_fields_rejected():
    response = client.post(
        "/audit/dependency-chokepoints",
        json={"resolved": {}, "dependency_graph": [], "nope": 1},
    )
    assert response.status_code == 422
