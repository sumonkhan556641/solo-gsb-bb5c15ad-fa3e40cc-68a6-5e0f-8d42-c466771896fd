"""End-to-end tests for ``POST /analyze/version-withdrawal``.

The baseline is solved on the unmodified index; the withdrawal solve
re-resolves the same roots/locks/options against a copy of this request's
index with exactly the withdrawn version removed.  Backtracking caused by
the withdrawal is recomputed by the solver against the full dependency
constraints — never inferred from the old dependency graph.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

# Baseline picks web 3.0 (highest) pulling common>=2.0; withdrawing web 3.0
# forces a full re-solve in which web 2.0 needs common<2.0 *and* pulls the
# previously unneeded ``extra`` package in.
PACKAGES = {
    "app": {"1.0": {"dependencies": {"web": ""}}},
    "web": {
        "3.0": {"dependencies": {"common": ">=2.0"}},
        "2.0": {"dependencies": {"common": "<2.0", "extra": ""}},
    },
    "common": {"1.5": {}, "2.0": {}},
    "extra": {"1.0": {}},
}


def _withdraw(**payload):
    response = client.post("/analyze/version-withdrawal", json=payload)
    return response.status_code, response.json()


def test_withdrawal_recomputes_full_closure():
    status, body = _withdraw(
        packages=PACKAGES, root={"app": ""}, withdraw={"package": "web", "version": "3.0"}
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["withdraw"] == {"package": "web", "version": "3.0"}
    assert body["allow_prereleases"] is False

    assert body["baseline_resolved"] == {"app": "1.0", "common": "2.0", "web": "3.0"}
    assert body["resolved"] == {
        "app": "1.0",
        "common": "1.5",
        "extra": "1.0",
        "web": "2.0",
    }

    changes = body["changes"]
    assert changes["added"] == [{"package": "extra", "version": "1.0"}]
    assert changes["removed"] == []
    assert changes["changed"] == [
        {"package": "common", "from": "2.0", "to": "1.5"},
        {"package": "web", "from": "3.0", "to": "2.0"},
    ]

    # The post-withdrawal dependency graph and lock disposition are returned.
    edges = {(e["source"], e["target"]) for e in body["dependency_graph"]}
    assert edges == {
        ("<root>", "app"),
        ("app", "web"),
        ("web", "common"),
        ("web", "extra"),
    }
    assert all(e["target_version"] == body["resolved"][e["target"]] for e in body["dependency_graph"])
    assert body["locks"] == {}
    assert body["attempts"] > 0


def test_withdrawal_can_drop_transitive_packages():
    packages = {
        "app": {"1.0": {"dependencies": {"web": ""}}},
        "web": {"3.0": {"dependencies": {"common": ""}}, "2.0": {}},
        "common": {"1.0": {}},
    }
    status, body = _withdraw(
        packages=packages, root={"app": ""}, withdraw={"package": "web", "version": "3.0"}
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["resolved"] == {"app": "1.0", "web": "2.0"}
    assert body["changes"] == {
        "added": [],
        "removed": [{"package": "common", "version": "1.0"}],
        "changed": [{"package": "web", "from": "3.0", "to": "2.0"}],
    }


def test_changes_lists_are_sorted_by_package_name():
    packages = {
        "app": {"1.0": {"dependencies": {"web": ""}}},
        "web": {
            "2.0": {"dependencies": {"zeta": "", "alpha": ""}},
            "1.0": {"dependencies": {"beta": "", "alpha": "<2.0"}},
        },
        "zeta": {"1.0": {}},
        "alpha": {"2.0": {}, "1.0": {}},
        "beta": {"1.0": {}},
    }
    status, body = _withdraw(
        packages=packages, root={"app": ""}, withdraw={"package": "web", "version": "2.0"}
    )
    assert status == 200
    changes = body["changes"]
    assert changes["added"] == [{"package": "beta", "version": "1.0"}]
    assert changes["removed"] == [{"package": "zeta", "version": "1.0"}]
    assert changes["changed"] == [
        {"package": "alpha", "from": "2.0", "to": "1.0"},
        {"package": "web", "from": "2.0", "to": "1.0"},
    ]


def test_withdrawing_unused_version_changes_nothing():
    status, body = _withdraw(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": "<2.0"},
        withdraw={"package": "x", "version": "2.0"},
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["baseline_resolved"] == {"x": "1.0"}
    assert body["resolved"] == {"x": "1.0"}
    assert body["changes"] == {"added": [], "removed": [], "changed": []}


def test_attempts_are_summed_over_both_solves():
    status, body = _withdraw(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ""},
        withdraw={"package": "x", "version": "2.0"},
    )
    assert status == 200
    # One candidate evaluation per solve (x==2.0, then x==1.0).
    assert body["attempts"] == 2


def test_lock_on_withdrawn_version_is_reported():
    status, body = _withdraw(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root={"x": ""},
        locks={"x": "2.0"},
        withdraw={"package": "x", "version": "2.0"},
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["baseline_resolved"] == {"x": "2.0"}
    # The lock survives as input but its version is gone from the index.
    assert body["resolved"] == {"x": "1.0"}
    assert body["locks"] == {"x": "missing-version"}
    assert body["changes"]["changed"] == [{"package": "x", "from": "2.0", "to": "1.0"}]


def test_locks_still_apply_after_withdrawal():
    status, body = _withdraw(
        packages={"x": {"1.0": {}, "2.0": {}, "3.0": {}}},
        root={"x": ""},
        locks={"x": "1.0"},
        withdraw={"package": "x", "version": "3.0"},
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["resolved"] == {"x": "1.0"}
    assert body["locks"] == {"x": "applied"}
    assert body["changes"] == {"added": [], "removed": [], "changed": []}


def test_baseline_conflict_is_reported_without_re_solving():
    packages = {
        "a": {"1.0": {"dependencies": {"x": ">=2.0"}}},
        "b": {"1.0": {"dependencies": {"x": "<2.0"}}},
        "x": {"1.0": {}, "2.0": {}},
    }
    status, body = _withdraw(
        packages=packages,
        root=["a", "b"],
        withdraw={"package": "x", "version": "1.0"},
    )
    assert status == 200
    assert body["status"] == "baseline_conflict"
    terminals = body["conflict"]["terminal_conflicts"]
    assert terminals[0]["package"] == "x"
    assert terminals[0]["reason"] == "unsatisfiable"
    # No comparison is possible without a baseline solution.
    assert "changes" not in body
    assert "baseline_resolved" not in body
    assert "resolved" not in body


def test_withdrawn_conflict_keeps_baseline_solution():
    packages = {
        "app": {"1.0": {"dependencies": {"web": ">=3.0"}}},
        "web": {"3.0": {}, "2.0": {}},
    }
    status, body = _withdraw(
        packages=packages, root={"app": ""}, withdraw={"package": "web", "version": "3.0"}
    )
    assert status == 200
    assert body["status"] == "withdrawn_conflict"
    assert body["baseline_resolved"] == {"app": "1.0", "web": "3.0"}
    terminals = body["conflict"]["terminal_conflicts"]
    assert terminals[0]["package"] == "web"
    assert terminals[0]["reason"] == "unsatisfiable"
    assert terminals[0]["available_versions"] == ["2.0"]
    assert "changes" not in body


def test_withdrawing_last_version_leaves_package_without_versions():
    packages = {
        "app": {"1.0": {"dependencies": {"web": ""}}},
        "web": {"1.0": {}},
    }
    status, body = _withdraw(
        packages=packages, root={"app": ""}, withdraw={"package": "web", "version": "1.0"}
    )
    assert status == 200
    assert body["status"] == "withdrawn_conflict"
    terminals = body["conflict"]["terminal_conflicts"]
    # The package is still in the index, it just has no versions left.
    assert terminals[0]["package"] == "web"
    assert terminals[0]["reason"] == "no-versions"


def _backtracking_chain(depth=3):
    """Baseline is trivial (p0 3.0 has no dependencies); withdrawing p0 3.0
    forces an exponential re-search through the chain."""
    packages = {
        "app": {"1.0": {"dependencies": {"p0": ""}}},
        "p0": {
            "3.0": {},
            "2.0": {"dependencies": {"p1": ""}},
            "1.0": {"dependencies": {"p1": ""}},
        },
    }
    for i in range(1, depth):
        packages[f"p{i}"] = {
            "2.0": {"dependencies": {f"p{i+1}": ""}},
            "1.0": {"dependencies": {f"p{i+1}": ""}},
        }
    # Every version of the last package demands a package absent from the
    # index, so the whole subtree fails and the search backtracks fully.
    packages[f"p{depth}"] = {
        "2.0": {"dependencies": {"missing": ""}},
        "1.0": {"dependencies": {"missing": ""}},
    }
    return packages


def test_baseline_limit_is_undetermined_not_conflict():
    status, body = _withdraw(
        packages=_backtracking_chain(),
        root={"app": ""},
        max_attempts=1,
        withdraw={"package": "p0", "version": "3.0"},
    )
    assert status == 200
    assert body["status"] == "undetermined"
    assert body["error"]["code"] == "search_limit_exceeded"
    assert "baseline" in body["error"]["message"]
    assert "baseline_resolved" not in body
    assert "changes" not in body


def test_withdrawal_limit_is_undetermined_not_conflict():
    status, body = _withdraw(
        packages=_backtracking_chain(),
        root={"app": ""},
        max_attempts=10,
        withdraw={"package": "p0", "version": "3.0"},
    )
    assert status == 200
    # The baseline is cheap and succeeds; the post-withdrawal re-search
    # exhausts the budget.  Hitting the limit is not treated as a conflict.
    assert body["status"] == "undetermined"
    assert body["baseline_resolved"] == {"app": "1.0", "p0": "3.0"}
    assert body["error"]["code"] == "search_limit_exceeded"
    assert "post-withdrawal" in body["error"]["message"]
    assert "changes" not in body
    assert "conflict" not in body


def test_marker_env_is_honored_in_both_solves():
    packages = {
        "app": {"1.0": {"dependencies": ["dep; python_version < '3.11'"]}},
        "dep": {"1.0": {}, "2.0": {}},
    }
    status, body = _withdraw(
        packages=packages,
        root=["app"],
        marker_env={"python_version": "3.10"},
        withdraw={"package": "dep", "version": "2.0"},
    )
    assert status == 200
    assert body["changes"]["changed"] == [{"package": "dep", "from": "2.0", "to": "1.0"}]

    status, body = _withdraw(
        packages=packages,
        root=["app"],
        marker_env={"python_version": "3.11"},
        withdraw={"package": "dep", "version": "2.0"},
    )
    assert status == 200
    # The marker excludes ``dep`` entirely under Python 3.11.
    assert body["baseline_resolved"] == {"app": "1.0"}
    assert body["resolved"] == {"app": "1.0"}
    assert body["changes"] == {"added": [], "removed": [], "changed": []}


def test_allow_prereleases_is_honored():
    packages = {"x": {"1.0": {}, "2.0rc1": {}}}
    status, body = _withdraw(
        packages=packages,
        root={"x": ""},
        allow_prereleases=True,
        withdraw={"package": "x", "version": "2.0rc1"},
    )
    assert status == 200
    assert body["allow_prereleases"] is True
    assert body["baseline_resolved"] == {"x": "2.0rc1"}
    assert body["resolved"] == {"x": "1.0"}
    assert body["changes"]["changed"] == [{"package": "x", "from": "2.0rc1", "to": "1.0"}]

    # Without the flag the pre-release is invisible in both solves.
    status, body = _withdraw(
        packages=packages,
        root={"x": ""},
        withdraw={"package": "x", "version": "2.0rc1"},
    )
    assert status == 200
    assert body["baseline_resolved"] == {"x": "1.0"}
    assert body["resolved"] == {"x": "1.0"}
    assert body["changes"] == {"added": [], "removed": [], "changed": []}


def test_withdraw_target_is_normalized():
    packages = {"Foo_Bar": {"1.0.0": {}, "2.0": {}}}
    status, body = _withdraw(
        packages=packages,
        root={"foo-bar": ""},
        withdraw={"package": "FOO-BAR", "version": "1.0"},
    )
    assert status == 200
    assert body["status"] == "ok"
    # Canonical package name and the index's own (normalized) version string.
    assert body["withdraw"] == {"package": "foo-bar", "version": "1.0.0"}


def test_deterministic_results():
    payload = {
        "packages": PACKAGES,
        "root": {"app": ""},
        "withdraw": {"package": "web", "version": "3.0"},
    }
    results = [
        client.post("/analyze/version-withdrawal", json=payload).json()
        for _ in range(3)
    ]
    assert all(r == results[0] for r in results)


def test_baseline_index_is_not_mutated():
    # The withdrawal must only affect this request's re-solve: a later
    # /resolve with the same index still sees the withdrawn version.
    payload = {
        "packages": PACKAGES,
        "root": {"app": ""},
        "withdraw": {"package": "web", "version": "3.0"},
    }
    status, body = _withdraw(**payload)
    assert status == 200
    assert body["status"] == "ok"
    followup = client.post(
        "/resolve",
        json={"packages": PACKAGES, "root": {"app": ""}},
    ).json()
    assert followup["resolved"]["web"] == "3.0"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_unknown_package_is_an_input_error():
    status, body = _withdraw(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        withdraw={"package": "ghost", "version": "1.0"},
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "ghost" in body["error"]["message"]


def test_unknown_version_is_an_input_error():
    status, body = _withdraw(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        withdraw={"package": "x", "version": "9.9"},
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "9.9" in body["error"]["message"]
    assert "1.0" in body["error"]["message"]  # available versions are listed


def test_invalid_withdraw_version_is_an_input_error():
    status, body = _withdraw(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        withdraw={"package": "x", "version": "not-a-version"},
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"


def test_withdraw_shape_validation():
    base = {
        "packages": {"x": {"1.0": {}}},
        "root": {"x": ""},
    }
    # Missing withdraw.
    response = client.post("/analyze/version-withdrawal", json=base)
    assert response.status_code == 422
    # Empty package / version.
    response = client.post(
        "/analyze/version-withdrawal",
        json={**base, "withdraw": {"package": "", "version": "1.0"}},
    )
    assert response.status_code == 422
    response = client.post(
        "/analyze/version-withdrawal",
        json={**base, "withdraw": {"package": "x", "version": ""}},
    )
    assert response.status_code == 422
    # Unexpected field inside withdraw.
    response = client.post(
        "/analyze/version-withdrawal",
        json={**base, "withdraw": {"package": "x", "version": "1.0", "extra": 1}},
    )
    assert response.status_code == 422
    # Unexpected top-level field.
    response = client.post(
        "/analyze/version-withdrawal",
        json={**base, "withdraw": {"package": "x", "version": "1.0"}, "extra": 1},
    )
    assert response.status_code == 422


def test_resolve_input_validation_is_reused():
    withdraw = {"package": "x", "version": "1.0"}
    status, body = _withdraw(
        packages={"x": {"not-a-version": {}}}, root={"x": ""}, withdraw=withdraw
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"

    status, body = _withdraw(
        packages={"x": {"1.0": {}}}, root={"x": ">>>1"}, withdraw=withdraw
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"

    status, body = _withdraw(
        packages={"x": {"1.0": {}}},
        root={"x": ""},
        locks={"x": "not-a-version"},
        withdraw=withdraw,
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
