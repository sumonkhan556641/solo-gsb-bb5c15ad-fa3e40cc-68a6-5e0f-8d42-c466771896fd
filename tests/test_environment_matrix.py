"""End-to-end tests for ``POST /analyze/environment-matrix``.

Each environment is solved independently under its own PEP 508 marker
environment with the full ``max_attempts`` budget; the version matrix is
aggregated over successful environments only, distinguishing absence
(``null``) from a concrete version.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

# ``tomli`` is only needed on Python < 3.11; ``common`` is needed everywhere.
MARKER_PACKAGES = {
    "app": {
        "1.0": {
            "dependencies": [
                "tomli>=1.0; python_version < '3.11'",
                "common>=1.0",
            ]
        }
    },
    "tomli": {"1.0": {}, "2.0": {}},
    "common": {"1.0": {}, "2.0": {}},
}


def _matrix(**payload):
    response = client.post("/analyze/environment-matrix", json=payload)
    return response.status_code, response.json()


def _env(name, **marker_env):
    return {"name": name, "marker_env": marker_env}


def test_presence_difference_across_environments():
    status, body = _matrix(
        packages=MARKER_PACKAGES,
        root=["app"],
        environments=[
            _env("py310", python_version="3.10"),
            _env("py311", python_version="3.11"),
        ],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["summary"] == {"environments": 2, "ok": 2, "conflict": 0, "limit": 0}

    envs = body["environments"]
    assert [e["name"] for e in envs] == ["py310", "py311"]  # input order
    assert all(e["status"] == "ok" for e in envs)
    assert envs[0]["resolved"] == {"app": "1.0", "common": "2.0", "tomli": "2.0"}
    assert envs[1]["resolved"] == {"app": "1.0", "common": "2.0"}
    assert all(isinstance(e["attempts"], int) and e["attempts"] > 0 for e in envs)

    matrix = body["matrix"]
    assert matrix["environments"] == ["py310", "py311"]
    rows = {row["package"]: row["versions"] for row in matrix["packages"]}
    # Packages sorted by canonical name; absence is an explicit null.
    assert [row["package"] for row in matrix["packages"]] == ["app", "common", "tomli"]
    assert rows["app"] == {"py310": "1.0", "py311": "1.0"}
    assert rows["common"] == {"py310": "2.0", "py311": "2.0"}
    assert rows["tomli"] == {"py310": "2.0", "py311": None}
    assert matrix["differences"] == ["tomli"]


def test_version_difference_across_environments():
    packages = {
        "app": {
            "1.0": {
                "dependencies": [
                    "common>=2.0; sys_platform == 'linux'",
                    "common<2.0; sys_platform == 'win32'",
                ]
            }
        },
        "common": {"1.0": {}, "2.0": {}},
    }
    status, body = _matrix(
        packages=packages,
        root=["app"],
        environments=[
            _env("linux", sys_platform="linux"),
            _env("windows", sys_platform="win32"),
        ],
    )
    assert status == 200
    rows = {row["package"]: row["versions"] for row in body["matrix"]["packages"]}
    assert rows["common"] == {"linux": "2.0", "windows": "1.0"}
    assert body["matrix"]["differences"] == ["common"]


def test_identical_environments_have_no_differences():
    status, body = _matrix(
        packages=MARKER_PACKAGES,
        root=["app"],
        environments=[_env("a", python_version="3.11"), _env("b", python_version="3.11")],
    )
    assert status == 200
    assert body["matrix"]["differences"] == []
    rows = {row["package"]: row["versions"] for row in body["matrix"]["packages"]}
    assert rows == {
        "app": {"a": "1.0", "b": "1.0"},
        "common": {"a": "2.0", "b": "2.0"},
    }


def test_conflict_environment_is_preserved_and_excluded_from_matrix():
    packages = {
        "app": {
            "1.0": {
                "dependencies": [
                    "ghost>=1.0; sys_platform == 'linux'",
                    "common>=1.0",
                ]
            }
        },
        "common": {"1.0": {}},
    }
    status, body = _matrix(
        packages=packages,
        root=["app"],
        environments=[
            _env("linux", sys_platform="linux"),
            _env("windows", sys_platform="win32"),
        ],
    )
    assert status == 200
    assert body["summary"] == {"environments": 2, "ok": 1, "conflict": 1, "limit": 0}

    linux, windows = body["environments"]
    assert linux["status"] == "conflict"
    assert linux["attempts"] > 0
    terminals = linux["conflict"]["terminal_conflicts"]
    assert terminals[0]["package"] == "ghost"
    assert terminals[0]["reason"] == "not-found"
    assert windows["status"] == "ok"
    assert windows["resolved"] == {"app": "1.0", "common": "1.0"}

    # Only the successful environment feeds the matrix; with fewer than two
    # successful environments the differences are empty.
    matrix = body["matrix"]
    assert matrix["environments"] == ["windows"]
    rows = {row["package"]: row["versions"] for row in matrix["packages"]}
    assert rows == {"app": {"windows": "1.0"}, "common": {"windows": "1.0"}}
    assert matrix["differences"] == []


def test_limit_environment_does_not_affect_others():
    # A wide chain forces many candidate evaluations, but only under linux.
    packages = {
        "app": {
            "1.0": {
                "dependencies": [
                    "p0; sys_platform == 'linux'",
                    "common>=1.0",
                ]
            }
        },
        "common": {"1.0": {}},
    }
    for i in range(3):
        packages[f"p{i}"] = {
            f"{major}.0": {"dependencies": {f"p{i+1}": ""}}
            for major in range(1, 4)
        }
    packages["p3"] = {f"{major}.0": {} for major in range(1, 4)}

    status, body = _matrix(
        packages=packages,
        root=["app"],
        max_attempts=3,
        environments=[
            _env("linux", sys_platform="linux"),
            _env("windows", sys_platform="win32"),
        ],
    )
    assert status == 200
    assert body["summary"] == {"environments": 2, "ok": 1, "conflict": 0, "limit": 1}

    linux, windows = body["environments"]
    assert linux["status"] == "limit"
    # The evaluation that trips the budget is counted, like /resolve.
    assert linux["attempts"] == 4
    assert linux["error"]["code"] == "search_limit_exceeded"
    # The other environment keeps its own full budget and result.
    assert windows["status"] == "ok"
    assert windows["resolved"] == {"app": "1.0", "common": "1.0"}

    assert body["matrix"]["environments"] == ["windows"]
    assert body["matrix"]["differences"] == []


def test_no_successful_environment_yields_empty_matrix():
    packages = {
        "a": {"1.0": {"dependencies": {"x": ">=2.0"}}},
        "b": {"1.0": {"dependencies": {"x": "<2.0"}}},
        "x": {"1.0": {}, "2.0": {}},
    }
    status, body = _matrix(
        packages=packages,
        root=["a", "b"],
        environments=[_env("one"), _env("two")],
    )
    assert status == 200
    assert body["summary"] == {"environments": 2, "ok": 0, "conflict": 2, "limit": 0}
    assert all(e["status"] == "conflict" for e in body["environments"])
    assert body["matrix"] == {"environments": [], "packages": [], "differences": []}


def test_root_markers_are_evaluated_per_environment():
    status, body = _matrix(
        packages={"a": {"1.0": {}}},
        root=["a; sys_platform == 'linux'"],
        environments=[
            _env("linux", sys_platform="linux"),
            _env("windows", sys_platform="win32"),
        ],
    )
    assert status == 200
    linux, windows = body["environments"]
    assert linux["resolved"] == {"a": "1.0"}
    assert windows["resolved"] == {}
    rows = {row["package"]: row["versions"] for row in body["matrix"]["packages"]}
    assert rows == {"a": {"linux": "1.0", "windows": None}}
    assert body["matrix"]["differences"] == ["a"]


def test_locks_apply_to_every_environment():
    status, body = _matrix(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ">=1.0"},
        locks={"x": "1.0"},
        environments=[_env("one"), _env("two")],
    )
    assert status == 200
    for env in body["environments"]:
        assert env["resolved"] == {"x": "1.0"}
        assert env["locks"] == {"x": "applied"}
    assert body["matrix"]["differences"] == []


def test_environment_and_package_ordering():
    packages = {
        "Zeta": {"1.0": {}},
        "alpha": {"1.0": {"dependencies": {"Zeta": "", "Foo_Bar": ""}}},
        "Foo_Bar": {"2.0": {}},
    }
    status, body = _matrix(
        packages=packages,
        root=["alpha"],
        environments=[_env("b-env"), _env("a-env"), _env("c-env")],
    )
    assert status == 200
    # Environments keep input order everywhere.
    assert [e["name"] for e in body["environments"]] == ["b-env", "a-env", "c-env"]
    assert body["matrix"]["environments"] == ["b-env", "a-env", "c-env"]
    # Packages sorted by canonical (normalized) name.
    assert [row["package"] for row in body["matrix"]["packages"]] == [
        "alpha",
        "foo-bar",
        "zeta",
    ]
    versions = body["matrix"]["packages"][0]["versions"]
    assert list(versions) == ["b-env", "a-env", "c-env"]


def test_deterministic_results():
    payload = {
        "packages": MARKER_PACKAGES,
        "root": ["app"],
        "environments": [
            _env("py310", python_version="3.10"),
            _env("py311", python_version="3.11"),
        ],
    }
    results = [
        client.post("/analyze/environment-matrix", json=payload).json()
        for _ in range(3)
    ]
    assert all(r == results[0] for r in results)


def test_attempts_are_reported_per_environment():
    status, body = _matrix(
        packages=MARKER_PACKAGES,
        root=["app"],
        environments=[
            _env("py310", python_version="3.10"),
            _env("py311", python_version="3.11"),
        ],
    )
    assert status == 200
    attempts = {e["name"]: e["attempts"] for e in body["environments"]}
    # py310 resolves one more package (tomli) than py311.
    assert attempts["py310"] == attempts["py311"] + 1


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_environment_count_is_bounded():
    base = {"packages": {"x": {"1.0": {}}}, "root": {"x": ""}}
    for count in (0, 1, 9):
        payload = {**base, "environments": [_env(f"env{i}") for i in range(count)]}
        response = client.post("/analyze/environment-matrix", json=payload)
        assert response.status_code == 422, count
    for count in (2, 8):
        payload = {**base, "environments": [_env(f"env{i}") for i in range(count)]}
        response = client.post("/analyze/environment-matrix", json=payload)
        assert response.status_code == 200, count


def test_duplicate_environment_names_rejected():
    status, body = _matrix(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        environments=[_env("same"), _env("other"), _env("same")],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "same" in body["error"]["message"]


def test_environment_shape_validation():
    base = {"packages": {"x": {"1.0": {}}}, "root": {"x": ""}}
    # Missing name.
    response = client.post(
        "/analyze/environment-matrix",
        json={**base, "environments": [{"marker_env": {}}, _env("b")]},
    )
    assert response.status_code == 422
    # Empty name.
    response = client.post(
        "/analyze/environment-matrix",
        json={**base, "environments": [_env(""), _env("b")]},
    )
    assert response.status_code == 422
    # Unexpected field inside an environment.
    response = client.post(
        "/analyze/environment-matrix",
        json={**base, "environments": [{**_env("a"), "extra": 1}, _env("b")]},
    )
    assert response.status_code == 422
    # Top-level marker_env belongs to /resolve, not to this endpoint.
    response = client.post(
        "/analyze/environment-matrix",
        json={**base, "environments": [_env("a"), _env("b")], "marker_env": {}},
    )
    assert response.status_code == 422


def test_resolve_input_validation_is_reused():
    envs = [_env("a"), _env("b")]
    status, body = _matrix(
        packages={"x": {"not-a-version": {}}}, root={"x": ""}, environments=envs
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"

    status, body = _matrix(
        packages={"x": {"1.0": {}}}, root={"x": ">>>1"}, environments=envs
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"

    status, body = _matrix(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        locks={"x": "not-a-version"},
        environments=envs,
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_default_marker_env_used_when_not_overridden():
    # No marker_env at all: the fixed default environment (linux) applies.
    status, body = _matrix(
        packages={
            "a": {"1.0": {"dependencies": ["b; sys_platform == 'linux'"]}},
            "b": {"1.0": {}},
        },
        root=["a"],
        environments=[{"name": "one"}, {"name": "two"}],
    )
    assert status == 200
    for env in body["environments"]:
        assert env["resolved"] == {"a": "1.0", "b": "1.0"}
    assert body["matrix"]["differences"] == []
