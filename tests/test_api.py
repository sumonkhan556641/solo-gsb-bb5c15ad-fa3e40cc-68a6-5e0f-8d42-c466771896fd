"""End-to-end API tests for the resolver service."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _resolve(**payload):
    response = client.post("/resolve", json=payload)
    return response.status_code, response.json()


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_simple_transitive_and_graph():
    status, body = _resolve(
        packages={
            "app": {"1.0": {"dependencies": {"lib": ">=1.0"}}},
            "lib": {
                "1.0": {"dependencies": {"util": ">=1.0"}},
                "2.0": {"dependencies": {"util": ">=1.0"}},
            },
            "util": {"1.0": {}, "2.0": {}},
        },
        root={"app": ""},
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["resolved"] == {"app": "1.0", "lib": "2.0", "util": "2.0"}
    pairs = {(e["source"], e["target"]) for e in body["dependency_graph"]}
    assert ("<root>", "app") in pairs
    assert ("app", "lib") in pairs
    assert ("lib", "util") in pairs


def test_lock_is_preferred_when_compatible():
    status, body = _resolve(
        packages={"x": {"1.0": {}, "1.5": {}, "2.0": {}}},
        root={"x": ">=1.0"},
        locks={"x": "1.0"},
    )
    assert status == 200
    assert body["resolved"]["x"] == "1.0"
    assert body["locks"]["x"] == "applied"


def test_lock_is_abandoned_when_unsatisfiable():
    status, body = _resolve(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ">=2.0"},
        locks={"x": "1.0"},
    )
    assert status == 200
    assert body["resolved"]["x"] == "2.0"
    assert body["locks"]["x"] == "unsatisfiable"


def test_backtracking_finds_solution():
    status, body = _resolve(
        packages={
            "app": {"1.0": {"dependencies": {"left": ">=1.0", "right": ">=1.0"}}},
            "left": {
                "1.0": {"dependencies": {"shared": ">=2.0"}},
                "2.0": {"dependencies": {"shared": "<2.0"}},
            },
            "right": {"1.0": {"dependencies": {"shared": "==1.5"}}},
            "shared": {"1.5": {}, "2.0": {}},
        },
        root={"app": ""},
    )
    assert status == 200
    assert body["resolved"] == {
        "app": "1.0",
        "left": "2.0",
        "right": "1.0",
        "shared": "1.5",
    }


def test_prereleases_excluded_by_default_included_on_request():
    packages = {"x": {"1.0a1": {}, "0.9": {}}}
    status, body = _resolve(packages=packages, root={"x": ""})
    assert body["resolved"] == {"x": "0.9"}

    status, body = _resolve(packages=packages, root={"x": ""}, allow_prereleases=True)
    assert body["resolved"] == {"x": "1.0a1"}


def test_explicit_prerelease_pin_in_index_allows_prerelease():
    status, body = _resolve(
        packages={
            "app": {"1.0": {"dependencies": {"x": "==1.0a1"}}},
            "x": {"1.0a1": {}, "0.9": {}},
        },
        root={"app": ""},
    )
    assert status == 200
    assert body["resolved"]["x"] == "1.0a1"


def test_conflict_reports_paths_and_mutually_exclusive_constraints():
    status, body = _resolve(
        packages={
            "a": {"1.0": {"dependencies": {"x": ">=2.0"}}},
            "b": {"1.0": {"dependencies": {"x": "<2.0"}}},
            "x": {"1.0": {}, "2.0": {}, "3.0": {}},
        },
        root={"a": "", "b": ""},
    )
    assert status == 409
    assert body["status"] == "conflict"
    terminals = body["conflict"]["terminal_conflicts"]
    assert len(terminals) == 1
    terminal = terminals[0]
    assert terminal["package"] == "x"
    specs = sorted(entry["specifier"] for entry in terminal["active_constraints"])
    assert specs == ["<2.0", ">=2.0"]
    # Each constraint carries a concrete dependency path.
    for entry in terminal["active_constraints"]:
        names = [node["name"] for node in entry["path"]]
        assert names[0] == "<root>"
        assert names[-1] in ("a", "b")


def test_missing_package_conflict_is_actionable():
    status, body = _resolve(
        packages={"a": {"1.0": {"dependencies": {"ghost": ">=1.0"}}}},
        root={"a": ""},
    )
    assert status == 409
    terminals = body["conflict"]["terminal_conflicts"]
    assert terminals[0]["package"] == "ghost"
    assert terminals[0]["reason"] == "not-found"
    path_names = [n["name"] for n in terminals[0]["active_constraints"][0]["path"]]
    assert path_names == ["<root>", "a"]


def test_deterministic_results():
    payload = {
        "packages": {
            "app": {"1.0": {"dependencies": {"left": ">=1.0", "right": ">=1.0"}}},
            "left": {
                "1.0": {"dependencies": {"shared": ">=2.0"}},
                "2.0": {"dependencies": {"shared": "<2.0"}},
            },
            "right": {"1.0": {"dependencies": {"shared": "==1.5"}}},
            "shared": {"1.5": {}, "2.0": {}},
        },
        "root": {"app": ""},
    }
    results = []
    for _ in range(5):
        response = client.post("/resolve", json=payload)
        results.append(response.json())
    assert all(r == results[0] for r in results)


def test_cyclic_dependencies_resolve():
    status, body = _resolve(
        packages={
            "a": {"1.0": {"dependencies": ["b>=1.0"]}},
            "b": {"1.0": {"dependencies": ["a>=1.0"]}},
        },
        root=["a"],
    )
    assert status == 200
    assert body["resolved"] == {"a": "1.0", "b": "1.0"}


def test_pep508_list_form_and_markers():
    status, body = _resolve(
        packages={
            "a": {
                "1.0": {
                    "dependencies": [
                        "b>=1.0; sys_platform == 'linux'",
                        "c; sys_platform == 'win32'",
                    ]
                }
            },
            "b": {"1.0": {}},
            "c": {"1.0": {}},
        },
        root=["a"],
    )
    assert status == 200
    assert set(body["resolved"]) == {"a", "b"}


def test_marker_env_override():
    status, body = _resolve(
        packages={
            "a": {"1.0": {"dependencies": ["b; sys_platform == 'win32'"]}},
            "b": {"1.0": {}},
        },
        root=["a"],
        marker_env={"sys_platform": "win32"},
    )
    assert status == 200
    assert set(body["resolved"]) == {"a", "b"}


def test_invalid_version_returns_400():
    status, body = _resolve(
        packages={"x": {"not-a-version": {}}},
        root={"x": ""},
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "PEP 440" in body["error"]["message"]


def test_invalid_specifier_returns_400():
    status, body = _resolve(
        packages={"x": {"1.0": {"dependencies": {"y": ">>>1"}}}, "y": {"1.0": {}}},
        root={"x": ""},
    )
    assert status == 400
    assert "specifier" in body["error"]["message"]


def test_extra_fields_rejected():
    response = client.post(
        "/resolve",
        json={"packages": {}, "root": {}, "unexpected": 1},
    )
    assert response.status_code == 422


def test_search_limit_returns_structured_conflict():
    # A chain wide enough to force many evaluations with a tiny limit.
    packages = {}
    for i in range(3):
        packages[f"p{i}"] = {
            f"{major}.0": {"dependencies": {f"p{i+1}": ""}}
            for major in range(1, 4)
        }
    packages["p3"] = {f"{major}.0": {} for major in range(1, 4)}
    status, body = _resolve(packages=packages, root={"p0": ""}, max_attempts=3)
    assert status == 409
    assert body["status"] == "limit"
    assert body["error"]["code"] == "search_limit_exceeded"


def test_empty_root_resolves_nothing():
    status, body = _resolve(packages={"x": {"1.0": {}}}, root={})
    assert status == 200
    assert body["resolved"] == {}
