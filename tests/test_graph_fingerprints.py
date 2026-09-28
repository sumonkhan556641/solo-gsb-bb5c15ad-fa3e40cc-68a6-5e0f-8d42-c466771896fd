"""End-to-end tests for POST /audit/graph-fingerprints."""

import random
import re

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _fingerprints(**payload):
    response = client.post("/audit/graph-fingerprints", json=payload)
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
# Golden values (lock the canonical serialization format)
# ---------------------------------------------------------------------------


def test_single_package_golden_fingerprints():
    status, body = _fingerprints(
        resolved={"a": "1.0"},
        dependency_graph=[_edge("<root>", "", "a", "1.0")],
    )
    assert status == 200
    assert body == {
        "status": "ok",
        "summary": {"packages": 1, "reachable": 1, "unreachable": 0},
        # {"nodes":[["<root>",""],["a","1.0"]],"edges":[["<root>","a"]]}
        "root_fingerprint": "dd21c390888e5cfbcaab35e859844e1f1f0d540e28dd9dc4e75aae526fd4a7fe",
        "packages": [
            {
                "package": "a",
                "version": "1.0",
                # {"nodes":[["a","1.0"]],"edges":[]}
                "fingerprint": "abcde3b2d6b6de5d765c19f9d804404108c6691abe7d0e11ec641af39127bfa0",
            }
        ],
        "unreachable": [],
    }


def test_diamond_golden_fingerprints():
    status, body = _fingerprints(
        resolved=DIAMOND_RESOLVED, dependency_graph=DIAMOND_GRAPH
    )
    assert status == 200
    assert body["root_fingerprint"] == (
        "076fa588d8933035a38342337cec19d2f9a29b25c68006bcd2344978f0184118"
    )
    assert _by_package(body["packages"]) == {
        "app": {
            "package": "app",
            "version": "1.0",
            "fingerprint": "17d739a96fdc2ba04d00ebecb4f0345e6d6fcf5bf01693961c702c788c0c4d76",
        },
        "left": {
            "package": "left",
            "version": "1.0",
            "fingerprint": "78363271440acfe06dca27a9d6f30b95e857be62a9cf6a6ea9700190e126609f",
        },
        "right": {
            "package": "right",
            "version": "1.0",
            "fingerprint": "841d348a4bf7e8b0b5bc14c466c4687e4912875c45d91c999c638c2a87f5a6ff",
        },
        "shared": {
            "package": "shared",
            "version": "1.5",
            "fingerprint": "616cc28664b5f3044aae80ccab83d5fe9d22923d4485fc4a490a12c9c19a2d84",
        },
    }


def test_empty_input():
    status, body = _fingerprints(resolved={}, dependency_graph=[])
    assert status == 200
    assert body == {
        "status": "ok",
        "summary": {"packages": 0, "reachable": 0, "unreachable": 0},
        # {"nodes":[["<root>",""]],"edges":[]}
        "root_fingerprint": "6cfed21a92b24b19879469769b3061739637d690cb6d6189795dc868ff4cf328",
        "packages": [],
        "unreachable": [],
    }


# ---------------------------------------------------------------------------
# Closure semantics
# ---------------------------------------------------------------------------


def test_fingerprints_are_sha256_hex_and_packages_sorted():
    status, body = _fingerprints(
        resolved=DIAMOND_RESOLVED, dependency_graph=DIAMOND_GRAPH
    )
    assert status == 200
    assert HEX64.match(body["root_fingerprint"])
    assert [entry["package"] for entry in body["packages"]] == [
        "app",
        "left",
        "right",
        "shared",
    ]
    for entry in body["packages"]:
        assert HEX64.match(entry["fingerprint"])


def test_diamond_shared_node_counted_once_and_closures_differ():
    _, body = _fingerprints(
        resolved=DIAMOND_RESOLVED, dependency_graph=DIAMOND_GRAPH
    )
    packages = _by_package(body["packages"])
    # left and right have isomorphic closures, but names are part of the
    # hashed content, so their fingerprints differ.
    assert packages["left"]["fingerprint"] != packages["right"]["fingerprint"]
    # Every node in the diamond has a distinct closure.
    fps = {entry["fingerprint"] for entry in body["packages"]}
    assert len(fps) == 4
    assert body["root_fingerprint"] not in fps


def test_cycle_members_share_one_closure_fingerprint():
    # root -> a <-> b (plus a self loop): both cycle members reach exactly
    # the same node/edge set, so their closures — and fingerprints — agree.
    status, body = _fingerprints(
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
    assert packages["a"]["fingerprint"] == packages["b"]["fingerprint"]
    # The root additionally carries the <root> node and its edge.
    assert body["root_fingerprint"] != packages["a"]["fingerprint"]


def test_deep_chain_terminates_and_inner_closure_is_shared():
    # A long chain: every suffix of the chain is one node's closure; the
    # leaf's fingerprint is a building block but each level hashes its own
    # content, so all fingerprints differ.
    depth = 200
    resolved = {f"p{i}": "1.0" for i in range(depth)}
    graph = [_edge("<root>", "", "p0", "1.0")] + [
        _edge(f"p{i}", "1.0", f"p{i+1}", "1.0") for i in range(depth - 1)
    ]
    status, body = _fingerprints(resolved=resolved, dependency_graph=graph)
    assert status == 200
    fps = [entry["fingerprint"] for entry in body["packages"]]
    assert len(set(fps)) == depth


# ---------------------------------------------------------------------------
# Determinism: input mapping and edge order must not matter
# ---------------------------------------------------------------------------


def test_deterministic_and_independent_of_input_order():
    payload = {"resolved": DIAMOND_RESOLVED, "dependency_graph": DIAMOND_GRAPH}
    baseline = client.post("/audit/graph-fingerprints", json=payload).json()
    assert all(
        client.post("/audit/graph-fingerprints", json=payload).json() == baseline
        for _ in range(5)
    )

    rng = random.Random(7)
    shuffled_edges = DIAMOND_GRAPH[:]
    rng.shuffle(shuffled_edges)
    shuffled_resolved = dict(reversed(list(DIAMOND_RESOLVED.items())))
    shuffled_payload = {
        "resolved": shuffled_resolved,
        "dependency_graph": shuffled_edges + shuffled_edges[:2],  # duplicates collapse
    }
    assert (
        client.post("/audit/graph-fingerprints", json=shuffled_payload).json()
        == baseline
    )


def test_name_and_version_normalization_do_not_change_fingerprints():
    status, plain = _fingerprints(
        resolved={"foo-bar": "1.0", "baz-qux": "2.0"},
        dependency_graph=[
            _edge("<root>", "", "foo-bar", "1.0"),
            _edge("foo-bar", "1.0", "baz-qux", "2.0"),
        ],
    )
    assert status == 200
    status, spelled = _fingerprints(
        resolved={"Foo_Bar": "01.0", "Baz.Qux": "2.0"},
        dependency_graph=[
            _edge("<root>", "", "FOO-BAR", "1.0"),
            _edge("foo_bar", "1.0", "baz.qux", "2.0.0"),
        ],
    )
    assert status == 200
    # Names canonicalize and versions normalize to the same PEP 440 forms,
    # so every fingerprint is identical; only the reported version strings
    # are the normalized ones.
    assert spelled == plain
    assert _by_package(spelled["packages"])["foo-bar"]["version"] == "1.0"


# ---------------------------------------------------------------------------
# Sensitivity: version/edge changes inside a closure change its fingerprint
# ---------------------------------------------------------------------------


def test_version_change_propagates_to_every_enclosing_closure():
    _, before = _fingerprints(
        resolved={**DIAMOND_RESOLVED, "solo": "3.0"},
        dependency_graph=DIAMOND_GRAPH + [_edge("<root>", "", "solo", "3.0")],
    )
    bumped = {**DIAMOND_RESOLVED, "shared": "1.6", "solo": "3.0"}
    bumped_graph = [
        _edge("<root>", "", "app", "1.0"),
        _edge("app", "1.0", "left", "1.0"),
        _edge("app", "1.0", "right", "1.0"),
        _edge("left", "1.0", "shared", "1.6"),
        _edge("right", "1.0", "shared", "1.6"),
        _edge("<root>", "", "solo", "3.0"),
    ]
    _, after = _fingerprints(resolved=bumped, dependency_graph=bumped_graph)

    before_packages = _by_package(before["packages"])
    after_packages = _by_package(after["packages"])
    # shared's version sits in the closure of everything except solo.
    for name in ("app", "left", "right", "shared"):
        assert before_packages[name]["fingerprint"] != after_packages[name]["fingerprint"]
    assert before_packages["solo"]["fingerprint"] == after_packages["solo"]["fingerprint"]
    assert before["root_fingerprint"] != after["root_fingerprint"]
    # The reported version string follows the resolved mapping.
    assert after_packages["shared"]["version"] == "1.6"


def test_edge_change_propagates_only_to_enclosing_closures():
    _, before = _fingerprints(
        resolved=DIAMOND_RESOLVED, dependency_graph=DIAMOND_GRAPH
    )
    # Drop right -> shared: right's closure loses the node, app's loses an
    # edge; left and shared keep exactly their old closures.
    trimmed_graph = [edge for edge in DIAMOND_GRAPH if edge["source"] != "right"]
    _, after = _fingerprints(
        resolved=DIAMOND_RESOLVED, dependency_graph=trimmed_graph
    )

    before_packages = _by_package(before["packages"])
    after_packages = _by_package(after["packages"])
    assert before_packages["right"]["fingerprint"] != after_packages["right"]["fingerprint"]
    assert before_packages["app"]["fingerprint"] != after_packages["app"]["fingerprint"]
    assert before_packages["left"]["fingerprint"] == after_packages["left"]["fingerprint"]
    assert before_packages["shared"]["fingerprint"] == after_packages["shared"]["fingerprint"]
    assert before["root_fingerprint"] != after["root_fingerprint"]


# ---------------------------------------------------------------------------
# Unreachable packages
# ---------------------------------------------------------------------------


def test_unreachable_packages_are_fingerprinted_and_listed():
    status, body = _fingerprints(
        resolved={"app": "1.0", "ghost": "1.0", "zombie": "2.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("ghost", "1.0", "zombie", "2.0"),
        ],
    )
    assert status == 200
    assert body["summary"] == {"packages": 3, "reachable": 1, "unreachable": 2}
    # Every package is fingerprinted, reachable or not.
    assert [entry["package"] for entry in body["packages"]] == [
        "app",
        "ghost",
        "zombie",
    ]
    assert body["unreachable"] == [
        {"package": "ghost", "version": "1.0"},
        {"package": "zombie", "version": "2.0"},
    ]

    # ghost's closure is {ghost, zombie}: its fingerprint matches the one
    # computed for the same subgraph in isolation, and unreachable content
    # never leaks into the root fingerprint.
    _, isolated = _fingerprints(
        resolved={"ghost": "1.0", "zombie": "2.0"},
        dependency_graph=[_edge("ghost", "1.0", "zombie", "2.0")],
    )
    isolated_packages = _by_package(isolated["packages"])
    packages = _by_package(body["packages"])
    assert packages["ghost"]["fingerprint"] == isolated_packages["ghost"]["fingerprint"]
    assert packages["zombie"]["fingerprint"] == isolated_packages["zombie"]["fingerprint"]

    _, without_unreachable = _fingerprints(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "app", "1.0")],
    )
    assert body["root_fingerprint"] == without_unreachable["root_fingerprint"]
    assert (
        packages["app"]["fingerprint"]
        == _by_package(without_unreachable["packages"])["app"]["fingerprint"]
    )


def test_empty_graph_marks_everything_unreachable():
    status, body = _fingerprints(resolved={"x": "1.0"}, dependency_graph=[])
    assert status == 200
    assert body["summary"] == {"packages": 1, "reachable": 0, "unreachable": 1}
    assert body["unreachable"] == [{"package": "x", "version": "1.0"}]
    # x is still fingerprinted over its own (singleton) closure.
    assert _by_package(body["packages"])["x"]["fingerprint"]


# ---------------------------------------------------------------------------
# Roundtrip from /resolve
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

    status, body = _fingerprints(
        resolved=resolve_body["resolved"],
        dependency_graph=resolve_body["dependency_graph"],
    )
    assert status == 200
    assert body["summary"] == {"packages": 4, "reachable": 4, "unreachable": 0}
    assert [entry["package"] for entry in body["packages"]] == [
        "app",
        "common",
        "db",
        "web",
    ]
    assert body["unreachable"] == []
    # The resolved graph is a tree here, so every package has its own
    # distinct closure; the root covers all of them.
    fps = {entry["fingerprint"] for entry in body["packages"]}
    assert len(fps) == 4
    assert body["root_fingerprint"] not in fps


# ---------------------------------------------------------------------------
# 400s (shared graph validation)
# ---------------------------------------------------------------------------


def test_dangling_target_returns_400():
    status, body = _fingerprints(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "ghost", "1.0")],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "dangling" in body["error"]["message"]


def test_dangling_source_returns_400():
    status, body = _fingerprints(
        resolved={"app": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("ghost", "1.0", "app", "1.0"),
        ],
    )
    assert status == 400
    assert "dangling" in body["error"]["message"]


def test_edge_version_inconsistent_with_resolved_returns_400():
    status, body = _fingerprints(
        resolved={"app": "1.0", "lib": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("app", "9.9", "lib", "1.0"),
        ],
    )
    assert status == 400
    assert "inconsistent" in body["error"]["message"]


def test_invalid_resolved_version_returns_400():
    status, body = _fingerprints(resolved={"x": "not-a-version"}, dependency_graph=[])
    assert status == 400
    assert "PEP 440" in body["error"]["message"]


def test_root_is_a_reserved_package_name():
    status, body = _fingerprints(resolved={"<root>": "1.0"}, dependency_graph=[])
    assert status == 400
    assert "reserved" in body["error"]["message"]


def test_root_edge_with_source_version_returns_400():
    status, body = _fingerprints(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "1.0", "app", "1.0")],
    )
    assert status == 400


def test_duplicate_normalized_names_return_400():
    status, body = _fingerprints(
        resolved={"Foo_Bar": "1.0", "foo-bar": "1.0"}, dependency_graph=[]
    )
    assert status == 400
    assert "duplicates" in body["error"]["message"]


def test_extra_fields_rejected():
    response = client.post(
        "/audit/graph-fingerprints",
        json={"resolved": {}, "dependency_graph": [], "nope": 1},
    )
    assert response.status_code == 422
