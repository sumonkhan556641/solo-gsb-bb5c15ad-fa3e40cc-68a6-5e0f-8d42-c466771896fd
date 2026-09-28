"""End-to-end tests for ``POST /resolve/avoid-vulnerabilities``.

Advisory-affected versions are removed from a request-local copy of the
index (union over advisories) before the ordinary exhaustive backtracking
solver runs; a locked version that is excluded can never be re-selected.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

# web 3.0 is the natural highest pick pulling common>=2.0; advisories can
# push the solve down to web 2.0 / common 1.5.
PACKAGES = {
    "app": {"1.0": {"dependencies": {"web": ""}}},
    "web": {
        "3.0": {"dependencies": {"common": ">=2.0"}},
        "2.0": {"dependencies": {"common": "<2.0"}},
    },
    "common": {"1.5": {}, "2.0": {}},
}


def _avoid(**payload):
    response = client.post("/resolve/avoid-vulnerabilities", json=payload)
    return response.status_code, response.json()


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------


def test_excludes_hit_versions_and_resolves_safely():
    status, body = _avoid(
        packages=PACKAGES,
        root={"app": ""},
        advisories=[{"id": "ADV-WEB", "package": "web", "affected": ">=3.0"}],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["allow_prereleases"] is False
    assert body["resolved"] == {"app": "1.0", "common": "1.5", "web": "2.0"}
    edges = {(e["source"], e["target"]) for e in body["dependency_graph"]}
    assert edges == {("<root>", "app"), ("app", "web"), ("web", "common")}
    assert all(
        e["target_version"] == body["resolved"][e["target"]]
        for e in body["dependency_graph"]
    )
    assert body["locks"] == {}
    assert body["attempts"] > 0
    assert body["excluded_versions"] == {"web": ["3.0"]}
    assert body["advisory_exclusions"] == [
        {
            "advisory": {
                "id": "ADV-WEB",
                "package": "web",
                "affected": ">=3.0",
            },
            "excluded_versions": ["3.0"],
        }
    ]


def test_no_affected_version_means_ordinary_resolution():
    status, body = _avoid(
        packages=PACKAGES,
        root={"app": ""},
        advisories=[{"id": "ADV-OLD", "package": "web", "affected": "<2.0"}],
    )
    assert status == 200
    assert body["resolved"] == {"app": "1.0", "common": "2.0", "web": "3.0"}
    assert body["excluded_versions"] == {}
    assert body["advisory_exclusions"][0]["excluded_versions"] == []


def test_empty_advisories_equals_plain_resolve():
    plain = client.post(
        "/resolve", json={"packages": PACKAGES, "root": {"app": ""}}
    ).json()
    status, body = _avoid(
        packages=PACKAGES, root={"app": ""}, advisories=[]
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["resolved"] == plain["resolved"]
    assert body["dependency_graph"] == plain["dependency_graph"]
    assert body["attempts"] == plain["attempts"]
    assert body["excluded_versions"] == {}
    assert body["advisory_exclusions"] == []


def test_multiple_advisories_union_exclusions():
    packages = {"x": {"1.0": {}, "2.0": {}, "3.0": {}}}
    status, body = _avoid(
        packages=packages,
        root={"x": ""},
        advisories=[
            {"id": "A", "package": "X", "affected": ">=3.0"},
            {"id": "B", "package": "x", "affected": "==2.0"},
        ],
    )
    assert status == 200
    assert body["resolved"] == {"x": "1.0"}
    # Per-advisory view preserves input order ...
    assert [e["advisory"]["id"] for e in body["advisory_exclusions"]] == ["A", "B"]
    assert body["advisory_exclusions"][0]["excluded_versions"] == ["3.0"]
    assert body["advisory_exclusions"][1]["excluded_versions"] == ["2.0"]
    # ... while the union feeds the solver.
    assert body["excluded_versions"] == {"x": ["3.0", "2.0"]}


def test_overlapping_advisories_do_not_double_count_union():
    packages = {"x": {"1.0": {}, "2.0": {}}}
    status, body = _avoid(
        packages=packages,
        root={"x": ""},
        advisories=[
            {"id": "A", "package": "x", "affected": ">=1.0"},
            {"id": "B", "package": "x", "affected": "<3"},
        ],
    )
    assert status == 409
    # Both advisories independently match both versions; the union still
    # contains each version exactly once.
    assert body["advisory_exclusions"][0]["excluded_versions"] == ["2.0", "1.0"]
    assert body["advisory_exclusions"][1]["excluded_versions"] == ["2.0", "1.0"]
    assert body["excluded_versions"] == {"x": ["2.0", "1.0"]}
    # Both versions banned -> the root requirement cannot be satisfied.
    assert body["status"] == "conflict"


def test_union_drives_solver_when_any_advisory_blocks_the_pick():
    # web 3.0 alone is fine, but the second advisory bans common 2.0, so the
    # solver must backtrack web 3.0 -> 2.0 and common -> 1.5.
    status, body = _avoid(
        packages=PACKAGES,
        root={"app": ""},
        advisories=[
            {"id": "ADV-NOISE", "package": "common", "affected": "<1.0"},
            {"id": "ADV-COMMON", "package": "common", "affected": ">=2.0,<3"},
        ],
    )
    assert status == 200
    assert body["resolved"] == {"app": "1.0", "common": "1.5", "web": "2.0"}
    assert body["excluded_versions"] == {"common": ["2.0"]}
    exclusions = {e["advisory"]["id"]: e["excluded_versions"] for e in body["advisory_exclusions"]}
    assert exclusions == {"ADV-NOISE": [], "ADV-COMMON": ["2.0"]}


def test_advisory_on_transitive_dependency_forces_backtracking():
    status, body = _avoid(
        packages=PACKAGES,
        root={"app": ""},
        advisories=[{"id": "ADV-C", "package": "common", "affected": ">=2.0"}],
    )
    assert status == 200
    assert body["resolved"]["common"] == "1.5"
    assert body["resolved"]["web"] == "2.0"


def test_versions_are_reported_using_index_strings_and_sorted_desc():
    packages = {"Foo_Bar": {"1.0.0": {}, "1.10.0": {}, "2.0a1": {}}}
    status, body = _avoid(
        packages=packages,
        root={"foo-bar": ""},
        allow_prereleases=True,
        advisories=[{"id": "A", "package": "FOO-BAR", "affected": "==2.0a1"}],
    )
    assert status == 200
    # Canonical package name; the index's own normalized version string.
    assert body["excluded_versions"] == {"foo-bar": ["2.0a1"]}
    assert body["resolved"] == {"foo-bar": "1.10.0"}


def test_excluded_versions_sorted_highest_first():
    packages = {"x": {"1.0.0": {}, "1.10.0": {}, "2.0": {}}}
    status, body = _avoid(
        packages=packages,
        root={"x": "<2"},
        advisories=[{"id": "A", "package": "x", "affected": "<2"}],
    )
    assert status == 409
    assert body["status"] == "conflict"
    assert body["excluded_versions"] == {"x": ["1.10.0", "1.0.0"]}


def test_prerelease_is_excluded_even_without_global_prerelease_flag():
    # The pre-release is not a candidate anyway, but exclusion reporting must
    # still match concrete index versions (same convention as the audit).
    packages = {"x": {"1.0": {}, "2.0rc1": {}}}
    status, body = _avoid(
        packages=packages,
        root={"x": ""},
        advisories=[{"id": "A", "package": "x", "affected": ">=2.0rc1"}],
    )
    assert status == 200
    assert body["resolved"] == {"x": "1.0"}
    assert body["excluded_versions"] == {"x": ["2.0rc1"]}


def test_surviving_lock_is_still_applied_first():
    packages = {"x": {"1.0": {}, "2.0": {}, "3.0": {}}}
    status, body = _avoid(
        packages=packages,
        root={"x": ""},
        locks={"x": "1.0"},
        advisories=[{"id": "A", "package": "x", "affected": ">=2.0"}],
    )
    assert status == 200
    assert body["resolved"] == {"x": "1.0"}
    assert body["locks"] == {"x": "applied"}


def test_excluded_locked_version_is_never_reselected():
    packages = {"x": {"1.0": {}, "2.0": {}}}
    status, body = _avoid(
        packages=packages,
        root={"x": ">=1.0"},
        locks={"x": "2.0"},
        advisories=[{"id": "A", "package": "x", "affected": ">=2.0"}],
    )
    assert status == 200
    assert body["resolved"] == {"x": "1.0"}
    # The pinned version is absent from the reduced index: not silently
    # re-applied, not backtracked from — missing-version.
    assert body["locks"] == {"x": "missing-version"}


def test_locked_version_excluded_with_no_safe_alternative_conflicts():
    packages = {"x": {"2.0": {}}}
    status, body = _avoid(
        packages=packages,
        root={"x": ""},
        locks={"x": "2.0"},
        advisories=[{"id": "A", "package": "x", "affected": ">=2.0"}],
    )
    assert status == 409
    assert body["status"] == "conflict"
    assert body["locks"] == {"x": "missing-version"}
    terminal = body["conflict"]["terminal_conflicts"][0]
    assert terminal["package"] == "x"
    assert terminal["reason"] == "no-versions"


def test_marker_env_and_prerelease_flag_are_honored():
    packages = {
        "app": {"1.0": {"dependencies": ["dep>=2.0; python_version >= '3.11'"]}},
        "dep": {"1.0": {}, "2.0": {}},
    }
    status, body = _avoid(
        packages=packages,
        root=["app"],
        marker_env={"python_version": "3.10"},
        advisories=[{"id": "A", "package": "dep", "affected": ""}],
    )
    assert status == 200
    # The marker excludes dep under 3.10, so banning all dep versions is moot.
    assert body["resolved"] == {"app": "1.0"}

    packages = {"x": {"1.0": {}, "2.0rc1": {}}}
    status, body = _avoid(
        packages=packages,
        root={"x": ""},
        allow_prereleases=True,
        advisories=[{"id": "A", "package": "x", "affected": "==2.0rc1"}],
    )
    assert status == 200
    assert body["allow_prereleases"] is True
    assert body["resolved"] == {"x": "1.0"}


def test_advisory_for_unknown_package_excludes_nothing():
    status, body = _avoid(
        packages=PACKAGES,
        root={"app": ""},
        advisories=[{"id": "GHOST", "package": "never-heard-of-it", "affected": ""}],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["resolved"] == {"app": "1.0", "common": "2.0", "web": "3.0"}
    assert body["excluded_versions"] == {}
    assert body["advisory_exclusions"][0]["excluded_versions"] == []


def test_supplied_index_is_not_mutated():
    payload = {
        "packages": PACKAGES,
        "root": {"app": ""},
        "advisories": [{"id": "A", "package": "web", "affected": ">=3.0"}],
    }
    status, body = _avoid(**payload)
    assert status == 200 and body["resolved"]["web"] == "2.0"
    followup = client.post(
        "/resolve", json={"packages": PACKAGES, "root": {"app": ""}}
    ).json()
    assert followup["resolved"]["web"] == "3.0"


def test_deterministic_results():
    payload = {
        "packages": PACKAGES,
        "root": {"app": ""},
        "advisories": [
            {"id": "A", "package": "web", "affected": ">=3.0"},
            {"id": "B", "package": "common", "affected": ">=2.0"},
        ],
    }
    results = [client.post("/resolve/avoid-vulnerabilities", json=payload).json()
               for _ in range(3)]
    assert all(r == results[0] for r in results)


# ---------------------------------------------------------------------------
# Conflict / search limit
# ---------------------------------------------------------------------------


def test_all_versions_affected_is_a_conflict():
    packages = {
        "app": {"1.0": {"dependencies": {"web": ""}}},
        "web": {"2.0": {}, "3.0": {}},
    }
    status, body = _avoid(
        packages=packages,
        root={"app": ""},
        advisories=[{"id": "A", "package": "web", "affected": ""}],
    )
    assert status == 409
    assert body["status"] == "conflict"
    terminal = body["conflict"]["terminal_conflicts"][0]
    assert terminal["package"] == "web"
    assert terminal["reason"] == "no-versions"
    assert "resolved" not in body


def test_advisory_can_create_unsatisfiable_constraint_conflict():
    packages = {
        "app": {"1.0": {"dependencies": {"web": ">=3.0"}}},
        "web": {"2.0": {}, "3.0": {}},
    }
    status, body = _avoid(
        packages=packages,
        root={"app": ""},
        advisories=[{"id": "A", "package": "web", "affected": ">=3.0"}],
    )
    assert status == 409
    assert body["status"] == "conflict"
    terminal = body["conflict"]["terminal_conflicts"][0]
    assert terminal["package"] == "web"
    assert terminal["reason"] == "unsatisfiable"
    # 3.0 was removed; only 2.0 remains visible.
    assert terminal["available_versions"] == ["2.0"]


def test_max_attempts_returns_undetermined_not_conflict():
    # Banning p0 3.0 forces an exponential failing re-search through a chain
    # ending in a dependency that does not exist.
    packages = {
        "app": {"1.0": {"dependencies": {"p0": ""}}},
        "p0": {
            "3.0": {},
            "2.0": {"dependencies": {"p1": ""}},
            "1.0": {"dependencies": {"p1": ""}},
        },
        "p1": {
            "2.0": {"dependencies": {"missing": ""}},
            "1.0": {"dependencies": {"missing": ""}},
        },
    }
    status, body = _avoid(
        packages=packages,
        root={"app": ""},
        max_attempts=5,
        advisories=[{"id": "A", "package": "p0", "affected": "==3.0"}],
    )
    assert status == 409
    assert body["status"] == "undetermined"
    assert body["error"]["code"] == "search_limit_exceeded"
    assert "5" in body["error"]["message"]
    assert body["excluded_versions"] == {"p0": ["3.0"]}
    assert "resolved" not in body
    assert "conflict" in body  # diagnostic conflict info, like /resolve


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_invalid_affected_specifier_returns_400():
    status, body = _avoid(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        advisories=[{"id": "A", "package": "x", "affected": ">>>1"}],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "A" in body["error"]["message"]


def test_empty_advisory_id_returns_400():
    status, body = _avoid(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        advisories=[{"id": "", "package": "x", "affected": ""}],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_empty_advisory_package_returns_400():
    status, body = _avoid(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        advisories=[{"id": "A", "package": "", "affected": ""}],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_resolve_input_validation_is_reused():
    advisories = [{"id": "A", "package": "x", "affected": ""}]
    status, body = _avoid(
        packages={"x": {"not-a-version": {}}},
        root={"x": ""},
        advisories=advisories,
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"

    status, body = _avoid(
        packages={"x": {"1.0": {}}},
        root=">>>1",
        advisories=advisories,
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_shape_validation():
    base = {"packages": {"x": {"1.0": {}}}, "root": {"x": ""}}
    # advisories is required.
    assert client.post("/resolve/avoid-vulnerabilities", json=base).status_code == 422
    # Missing / extra fields on an advisory.
    assert client.post(
        "/resolve/avoid-vulnerabilities",
        json={**base, "advisories": [{"id": "A", "package": "x"}]},
    ).status_code == 422
    assert client.post(
        "/resolve/avoid-vulnerabilities",
        json={**base, "advisories": [
            {"id": "A", "package": "x", "affected": "", "extra": 1}
        ]},
    ).status_code == 422
    # Unexpected top-level field.
    assert client.post(
        "/resolve/avoid-vulnerabilities",
        json={**base, "advisories": [], "extra": 1},
    ).status_code == 422
