"""End-to-end tests for POST /audit/vulnerabilities."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _audit(**payload):
    response = client.post("/audit/vulnerabilities", json=payload)
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


def _names(path):
    return [node["name"] for node in path]


def test_health_still_ok():
    response = client.get("/health")
    assert response.status_code == 200


def test_diamond_reports_all_shortest_paths_sorted():
    status, body = _audit(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH,
        advisories=[{"id": "ADV-1", "package": "shared", "affected": ">=1.0,<2.0"}],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["summary"] == {"advisories": 1, "matches": 1, "orphaned": 0}
    (match,) = body["matches"]
    assert match["advisory"] == {"id": "ADV-1", "package": "shared", "affected": ">=1.0,<2.0"}
    assert match["package"] == "shared"
    assert match["version"] == "1.5"
    paths = [_names(p) for p in match["paths"]]
    assert paths == [
        ["<root>", "app", "left", "shared"],
        ["<root>", "app", "right", "shared"],
    ]
    # Paths carry the resolved versions; the root node has an empty version.
    first = match["paths"][0]
    assert first[0] == {"name": "<root>", "version": ""}
    assert first[-1] == {"name": "shared", "version": "1.5"}


def test_duplicate_edges_do_not_duplicate_paths():
    status, body = _audit(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH + DIAMOND_GRAPH,
        advisories=[{"id": "ADV-1", "package": "shared", "affected": "==1.5"}],
    )
    assert status == 200
    paths = [_names(p) for p in body["matches"][0]["paths"]]
    assert len(paths) == len({tuple(p) for p in paths}) == 2


def test_cyclic_graph_terminates_with_simple_paths():
    status, body = _audit(
        resolved={"a": "1.0", "b": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "a", "1.0"),
            _edge("a", "1.0", "b", "1.0"),
            _edge("b", "1.0", "a", "1.0"),  # cycle back into a
            _edge("a", "1.0", "a", "1.0"),  # self loop
        ],
        advisories=[
            {"id": "ADV-A", "package": "a", "affected": ">=1.0"},
            {"id": "ADV-B", "package": "b", "affected": ">=1.0"},
        ],
    )
    assert status == 200
    assert body["summary"]["matches"] == 2
    by_id = {m["advisory"]["id"]: m for m in body["matches"]}
    assert [_names(p) for p in by_id["ADV-A"]["paths"]] == [["<root>", "a"]]
    assert [_names(p) for p in by_id["ADV-B"]["paths"]] == [["<root>", "a", "b"]]


def test_unreachable_hit_is_orphaned():
    status, body = _audit(
        resolved={"app": "1.0", "ghost": "1.0"},
        dependency_graph=[_edge("<root>", "", "app", "1.0")],
        advisories=[
            {"id": "ADV-G", "package": "ghost", "affected": "<2.0"},
            {"id": "ADV-A", "package": "app", "affected": ">=1.0"},
        ],
    )
    assert status == 200
    assert body["summary"] == {"advisories": 2, "matches": 1, "orphaned": 1}
    (orphan,) = body["orphaned"]
    assert orphan["advisory"]["id"] == "ADV-G"
    assert orphan["package"] == "ghost"
    assert orphan["version"] == "1.0"
    assert "paths" not in orphan
    assert body["matches"][0]["advisory"]["id"] == "ADV-A"


def test_non_matching_advisories_are_skipped():
    status, body = _audit(
        resolved=DIAMOND_RESOLVED,
        dependency_graph=DIAMOND_GRAPH,
        advisories=[
            {"id": "OUT-OF-RANGE", "package": "shared", "affected": ">=2.0"},
            {"id": "NOT-INSTALLED", "package": "numpy", "affected": ""},
        ],
    )
    assert status == 200
    assert body["summary"] == {"advisories": 2, "matches": 0, "orphaned": 0}
    assert body["matches"] == []
    assert body["orphaned"] == []


def test_multiple_advisories_can_hit_the_same_package():
    status, body = _audit(
        resolved={"x": "1.5"},
        dependency_graph=[_edge("<root>", "", "x", "1.5")],
        advisories=[
            {"id": "B", "package": "x", "affected": ">=1.0"},
            {"id": "A", "package": "x", "affected": "==1.5"},
        ],
    )
    assert status == 200
    # Advisory input order is preserved.
    assert [m["advisory"]["id"] for m in body["matches"]] == ["B", "A"]


def test_prerelease_resolved_version_matches_like_the_resolver():
    status, body = _audit(
        resolved={"x": "2.0rc1"},
        dependency_graph=[_edge("<root>", "", "x", "2.0rc1")],
        advisories=[{"id": "PRE", "package": "x", "affected": ">=1.0"}],
    )
    assert status == 200
    assert body["summary"]["matches"] == 1


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
        advisories=[{"id": "CVE-0001", "package": "common", "affected": "<1.6"}],
    )
    assert status == 200
    (match,) = body["matches"]
    assert match["package"] == "common"
    assert match["version"] == "1.5"
    paths = [_names(p) for p in match["paths"]]
    assert paths == [
        ["<root>", "app", "db", "common"],
        ["<root>", "app", "web", "common"],
    ]


def test_deterministic_results():
    payload = {
        "resolved": DIAMOND_RESOLVED,
        "dependency_graph": DIAMOND_GRAPH,
        "advisories": [{"id": "ADV-1", "package": "shared", "affected": "<2.0"}],
    }
    results = [client.post("/audit/vulnerabilities", json=payload).json() for _ in range(5)]
    assert all(r == results[0] for r in results)


# ---------------------------------------------------------------------------
# 400s
# ---------------------------------------------------------------------------


def test_invalid_resolved_version_returns_400():
    status, body = _audit(
        resolved={"x": "not-a-version"},
        dependency_graph=[],
        advisories=[],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "PEP 440" in body["error"]["message"]


def test_invalid_advisory_specifier_returns_400():
    status, body = _audit(
        resolved={"x": "1.0"},
        dependency_graph=[_edge("<root>", "", "x", "1.0")],
        advisories=[{"id": "BAD", "package": "x", "affected": ">>>1"}],
    )
    assert status == 400
    assert "specifier" in body["error"]["message"]


def test_dangling_target_returns_400():
    status, body = _audit(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "ghost", "1.0")],
        advisories=[],
    )
    assert status == 400
    assert "dangling" in body["error"]["message"]


def test_dangling_source_returns_400():
    status, body = _audit(
        resolved={"app": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("ghost", "1.0", "app", "1.0"),
        ],
        advisories=[],
    )
    assert status == 400
    assert "dangling" in body["error"]["message"]


def test_edge_target_version_inconsistent_with_resolved_returns_400():
    status, body = _audit(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "", "app", "2.0")],
        advisories=[],
    )
    assert status == 400
    assert "inconsistent" in body["error"]["message"]


def test_edge_source_version_inconsistent_with_resolved_returns_400():
    status, body = _audit(
        resolved={"app": "1.0", "lib": "1.0"},
        dependency_graph=[
            _edge("<root>", "", "app", "1.0"),
            _edge("app", "9.9", "lib", "1.0"),
        ],
        advisories=[],
    )
    assert status == 400
    assert "inconsistent" in body["error"]["message"]


def test_root_edge_with_source_version_returns_400():
    status, body = _audit(
        resolved={"app": "1.0"},
        dependency_graph=[_edge("<root>", "1.0", "app", "1.0")],
        advisories=[],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_extra_fields_rejected():
    response = client.post(
        "/audit/vulnerabilities",
        json={"resolved": {}, "dependency_graph": [], "advisories": [], "nope": 1},
    )
    assert response.status_code == 422
