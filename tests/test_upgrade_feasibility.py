"""End-to-end tests for ``POST /analyze/upgrade-feasibility``.

For every candidate version an exact-version root constraint is temporarily
*added* to the original roots and the whole project is re-solved with the
full transitive constraints, the original locks and a fresh, independent
``max_attempts`` budget.  Candidates are reported in input order as
``ok`` / ``conflict`` / ``undetermined``.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _analyze(**payload):
    response = client.post("/analyze/upgrade-feasibility", json=payload)
    return response.status_code, response.json()


# app requires web (unconstrained) and db; db pins common==1.5.  web 3.0
# pulls common>=2.0, so forcing web==3.0 is impossible for *transitive*
# reasons even though web 3.0 exists and satisfies app's own unconstrained
# "web" requirement.  web 2.0 needs common<2.0 and fits.
PACKAGES = {
    "app": {"1.0": {"dependencies": {"web": "", "db": ""}}},
    "web": {
        "3.0": {"dependencies": {"common": ">=2.0"}},
        "2.0": {"dependencies": {"common": "<2.0"}},
    },
    "db": {"1.0": {"dependencies": {"common": "==1.5"}}},
    "common": {"1.5": {}, "2.0": {}},
}
BASE = {"packages": PACKAGES, "root": {"app": ""}}


def test_mixed_ok_and_conflict_in_input_order():
    status, body = _analyze(**BASE, package="web", candidates=["3.0", "2.0"])
    assert status == 200
    assert body["status"] == "ok"
    assert body["allow_prereleases"] is False
    assert body["target"] == {"package": "web"}
    assert body["summary"] == {
        "candidates": 2, "ok": 1, "conflict": 1, "undetermined": 0
    }

    first, second = body["candidates"]
    assert first["candidate"] == "3.0"
    assert first["status"] == "conflict"
    assert first["attempts"] > 0
    # The conflict summary explains the *transitive* contradiction.
    terminals = first["conflict"]["terminal_conflicts"]
    assert {t["package"] for t in terminals} == {"common"}
    assert terminals[0]["reason"] == "unsatisfiable"
    requirements = {
        c["requirement"] for c in terminals[0]["active_constraints"]
    }
    assert "common>=2.0" in requirements
    assert "common==1.5" in requirements
    # Failure must not leak resolved/graph/changes fields.
    assert "resolved" not in first
    assert "changes" not in first

    assert second["candidate"] == "2.0"
    assert second["status"] == "ok"
    assert second["resolved"] == {
        "app": "1.0", "common": "1.5", "db": "1.0", "web": "2.0"
    }
    assert all(
        e["target_version"] == second["resolved"][e["target"]]
        for e in second["dependency_graph"]
    )
    assert "conflict" not in second
    # The baseline is the unmodified project, which backtracks to web 2.0;
    # a successful candidate states what its changes were measured against.
    assert body["baseline"]["status"] == "ok"
    assert second["changes_relative_to"] == "baseline"


def test_candidate_order_is_preserved_and_sorted_input_is_not_assumed():
    status, body = _analyze(**BASE, package="web", candidates=["2.0", "3.0"])
    assert status == 200
    assert [item["candidate"] for item in body["candidates"]] == ["2.0", "3.0"]
    assert [item["status"] for item in body["candidates"]] == ["ok", "conflict"]
    assert body["summary"] == {
        "candidates": 2, "ok": 1, "conflict": 1, "undetermined": 0
    }


def test_original_root_constraints_still_participate():
    # The pin alone (web==2.0) is satisfiable, but the original root
    # requires web>=3.0; feasibility must keep the original constraint.
    packages = {
        "app": {"1.0": {"dependencies": {"web": ">=3.0"}}},
        "web": {"2.0": {}, "3.0": {}},
    }
    status, body = _analyze(
        packages=packages,
        root={"app": ""},
        package="web",
        candidates=["2.0", "3.0"],
    )
    assert status == 200
    statuses = {item["candidate"]: item["status"] for item in body["candidates"]}
    assert statuses == {"2.0": "conflict", "3.0": "ok"}
    terminals = body["candidates"][0]["conflict"]["terminal_conflicts"]
    requirements = {
        c["requirement"] for c in terminals[0]["active_constraints"]
    }
    assert "web==2.0" in requirements
    assert "web>=3.0" in requirements


def test_conflict_within_target_package_itself():
    # Root demands web!=3.0, so pinning exactly 3.0 is a direct
    # root-vs-pin contradiction; the pin is added, not replacing.
    status, body = _analyze(
        packages={"web": {"2.0": {}, "3.0": {}}},
        root={"web": "!=3.0"},
        package="web",
        candidates=["3.0"],
    )
    assert status == 200
    item = body["candidates"][0]
    assert item["status"] == "conflict"
    terminals = item["conflict"]["terminal_conflicts"]
    assert terminals[0]["package"] == "web"


def test_version_changes_against_the_locked_baseline():
    # Baseline picks web 3.0 (highest) pulling common 2.0; downgrading to
    # web 2.0 changes common and adds the previously-unneeded "extra" pkg.
    packages = {
        "app": {"1.0": {"dependencies": {"web": ""}}},
        "web": {
            "3.0": {"dependencies": {"common": ">=2.0"}},
            "2.0": {"dependencies": {"common": "<2.0", "extra": ""}},
        },
        "common": {"1.5": {}, "2.0": {}},
        "extra": {"1.0": {}},
    }
    status, body = _analyze(
        packages=packages, root={"app": ""},
        package="web", candidates=["2.0"],
    )
    assert status == 200
    assert body["baseline"]["status"] == "ok"
    item = body["candidates"][0]
    assert item["status"] == "ok"
    assert item["changes_relative_to"] == "baseline"
    assert item["changes"] == {
        "added": [{"package": "extra", "version": "1.0"}],
        "removed": [],
        "changed": [
            {"package": "common", "from": "2.0", "to": "1.5"},
            {"package": "web", "from": "3.0", "to": "2.0"},
        ],
    }


def test_successful_candidate_equal_to_baseline_has_no_changes():
    status, body = _analyze(**BASE, package="web", candidates=["2.0"])
    assert status == 200
    item = body["candidates"][0]
    assert item["status"] == "ok"
    assert item["resolved"]["web"] == "2.0"
    assert item["changes"] == {"added": [], "removed": [], "changed": []}


def test_lock_consistent_with_pin_is_applied_and_unchanged():
    status, body = _analyze(
        **BASE, locks={"web": "2.0"},
        package="web", candidates=["2.0"],
    )
    assert status == 200
    item = body["candidates"][0]
    assert item["status"] == "ok"
    assert item["resolved"]["web"] == "2.0"
    assert item["locks"]["web"] == "applied"
    assert item["changes"] == {"added": [], "removed": [], "changed": []}


def test_other_locks_participate_in_every_solve():
    # common is locked at 1.5 while web 3.0 hard-requires common>=2.0 (db
    # pins common==1.5).  Forcing web==3.0 must fail: the *other* package's
    # lock (and db's hard pin) is still in force; locks are not rewritten.
    status, body = _analyze(
        **BASE, locks={"common": "1.5"},
        package="web", candidates=["2.0", "3.0"],
    )
    assert status == 200
    first, second = body["candidates"]
    assert first["status"] == "ok"
    assert first["resolved"] == {
        "app": "1.0", "common": "1.5", "db": "1.0", "web": "2.0"
    }
    assert first["locks"]["common"] == "applied"
    assert second["status"] == "conflict"
    terminals = second["conflict"]["terminal_conflicts"]
    assert {t["package"] for t in terminals} == {"common"}


def test_removed_packages_are_reported_when_closure_shrinks():
    # Pinning web 2.0 (which has no deps here) drops common entirely.
    packages = {
        "app": {"1.0": {"dependencies": {"web": ""}}},
        "web": {"3.0": {"dependencies": {"common": ""}}, "2.0": {}},
        "common": {"1.0": {}, "2.0": {}},
    }
    status, body = _analyze(
        packages=packages, root={"app": ""},
        package="web", candidates=["2.0"],
    )
    assert status == 200
    assert body["baseline"]["status"] == "ok"
    item = body["candidates"][0]
    assert item["status"] == "ok"
    assert item["changes_relative_to"] == "baseline"
    assert item["resolved"] == {"app": "1.0", "web": "2.0"}
    assert item["changes"]["removed"] == [
        {"package": "common", "version": "2.0"}
    ]
    assert item["changes"]["changed"] == [
        {"package": "web", "from": "3.0", "to": "2.0"}
    ]


def test_target_lock_contradicting_pin_is_falsified():
    # web is locked at 3.0, which is infeasible for the project; the
    # baseline backtracks and ignores the soft lock.  Pinning web==2.0
    # succeeds and the lock note records why the lock was not applied.
    status, body = _analyze(
        **BASE, locks={"web": "3.0"},
        package="web", candidates=["2.0"],
    )
    assert status == 200
    item = body["candidates"][0]
    assert item["status"] == "ok"
    assert item["locks"]["web"] == "unsatisfiable"


def test_baseline_conflict_is_reported_and_blocks_no_candidate():
    # The unmodified project is hard-unsatisfiable: the root demands
    # common>=2.0 while db pins common==1.5.  Candidate solves still run
    # independently with the same original root constraints, so both
    # candidates conflict (neither can satisfy both common constraints).
    packages = {
        "app": {"1.0": {"dependencies": {"web": ">=2.0", "db": ""}}},
        "web": {
            "3.0": {"dependencies": {"common": ">=2.0"}},
            "2.0": {"dependencies": {"common": "<2.0"}},
        },
        "db": {"1.0": {"dependencies": {"common": "==1.5"}}},
        "common": {"1.5": {}, "2.0": {}},
    }
    status, body = _analyze(
        packages=packages,
        root={"app": "", "common": ">=2.0"},
        package="web", candidates=["3.0", "2.0"],
    )
    assert status == 200
    assert body["baseline"]["status"] == "conflict"
    assert "conflict" in body["baseline"]
    assert all(item["status"] == "conflict" for item in body["candidates"])
    assert body["summary"] == {
        "candidates": 2, "ok": 0, "conflict": 2, "undetermined": 0
    }


def test_baseline_conflict_successful_candidate_uses_locks_basis():
    # The solver is non-monotone in one documented way: an exact pre-release
    # pin relaxes pre-release exclusion for that package.  With
    # allow_prereleases=false the only final web (3.0) forces common>=2.0 and
    # clashes with db's ==1.5, so the baseline has no solution.  Pinning the
    # pre-release web 2.0rc1 makes that version eligible and the independent
    # candidate solve succeeds; its changes then fall back to the explicit
    # request locks mapping.
    packages = {
        "app": {"1.0": {"dependencies": {"web": "", "db": ""}}},
        "web": {
            "3.0": {"dependencies": {"common": ">=2.0"}},
            "2.0rc1": {},
        },
        "db": {"1.0": {"dependencies": {"common": "==1.5"}}},
        "common": {"1.5": {}, "2.0": {}},
    }
    status, body = _analyze(
        packages=packages, root={"app": ""},
        locks={"web": "3.0"},
        package="web", candidates=["2.0rc1"],
    )
    assert status == 200
    assert body["baseline"]["status"] == "conflict"
    item = body["candidates"][0]
    assert item["status"] == "ok"
    assert item["resolved"] == {
        "app": "1.0", "common": "1.5", "db": "1.0", "web": "2.0rc1"
    }
    assert item["changes_relative_to"] == "locks"
    assert item["changes"] == {
        "added": [
            {"package": "app", "version": "1.0"},
            {"package": "common", "version": "1.5"},
            {"package": "db", "version": "1.0"},
        ],
        "removed": [],
        "changed": [{"package": "web", "from": "3.0", "to": "2.0rc1"}],
    }


def test_each_candidate_gets_independent_full_attempt_budget():
    status_first, first = _analyze(**BASE, package="web", candidates=["3.0"])
    status_second, second = _analyze(**BASE, package="web", candidates=["2.0"])
    assert status_first == status_second == 200
    alone_3 = first["candidates"][0]["attempts"]
    alone_2 = second["candidates"][0]["attempts"]
    status, body = _analyze(**BASE, package="web", candidates=["3.0", "2.0"])
    combined = {i["candidate"]: i["attempts"] for i in body["candidates"]}
    # A previous candidate's search must not consume the next one's budget.
    assert combined["3.0"] == alone_3
    assert combined["2.0"] == alone_2


def _backtracking_chain(depth=3):
    """Pinning p0 to 2.0 (or 1.0) forces an exponential re-search."""
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
    packages[f"p{depth}"] = {
        "2.0": {"dependencies": {"missing": ""}},
        "1.0": {"dependencies": {"missing": ""}},
    }
    return packages


def test_hitting_max_attempts_is_undetermined_never_conflict():
    # Candidate 2.0 exhausts the tiny budget, so it must be reported as
    # undetermined, not as "cannot be installed".
    status, body = _analyze(
        packages=_backtracking_chain(),
        root={"app": ""},
        package="p0",
        candidates=["2.0"],
        max_attempts=1,
    )
    assert status == 200
    item = body["candidates"][0]
    assert item["status"] == "undetermined"
    assert item["error"]["code"] == "search_limit_exceeded"
    assert "2.0" in item["error"]["message"]
    assert item["attempts"] >= 1
    assert "conflict" in item  # diagnostic detail still attached
    assert "resolved" not in item
    assert body["summary"] == {
        "candidates": 1, "ok": 0, "conflict": 0, "undetermined": 1
    }


def test_undetermined_candidate_does_not_affect_the_others():
    status, body = _analyze(
        packages=_backtracking_chain(),
        root={"app": ""},
        package="p0",
        candidates=["3.0", "2.0"],
        max_attempts=2,
    )
    assert status == 200
    first, second = body["candidates"]
    assert first["status"] == "ok"
    assert first["resolved"] == {"app": "1.0", "p0": "3.0"}
    assert second["status"] == "undetermined"
    assert body["summary"] == {
        "candidates": 2, "ok": 1, "conflict": 0, "undetermined": 1
    }


def test_marker_env_is_honored_per_candidate():
    # app's own dependency on dep is marker-gated.  Under 3.10 dep belongs
    # to the closure, so the exact pin selects the requested version.
    packages = {
        "app": {"1.0": {"dependencies": ["dep; python_version < '3.11'"]}},
        "dep": {"1.0": {}, "2.0": {}},
    }
    status, body = _analyze(
        packages=packages, root=["app"],
        marker_env={"python_version": "3.10"},
        package="dep", candidates=["2.0", "1.0"],
    )
    assert status == 200
    assert [i["resolved"]["dep"] for i in body["candidates"]] == ["2.0", "1.0"]

    # Under 3.11 nothing requires dep; the standalone exact root pin still
    # resolves, but app is the only other package.
    status, body = _analyze(
        packages=packages, root=["app"],
        marker_env={"python_version": "3.11"},
        package="dep", candidates=["2.0"],
    )
    assert status == 200
    item = body["candidates"][0]
    assert item["status"] == "ok"
    assert item["resolved"] == {"app": "1.0", "dep": "2.0"}
    assert item["changes"] == {
        "added": [{"package": "dep", "version": "2.0"}],
        "removed": [],
        "changed": [],
    }


def test_prerelease_candidate_pins_pre_release():
    packages = {"x": {"1.0": {}, "2.0rc1": {}}}
    status, body = _analyze(
        packages=packages, root={"x": ""},
        package="x", candidates=["2.0rc1", "1.0"],
    )
    assert status == 200
    first, second = body["candidates"]
    # The explicit ==2.0rc1 pin relaxes pre-release exclusion for x.
    assert first["status"] == "ok"
    assert first["resolved"]["x"] == "2.0rc1"
    assert second["resolved"]["x"] == "1.0"


def test_target_and_versions_are_normalized():
    packages = {"Foo_Bar": {"1.0.0": {}, "2.0": {}}}
    status, body = _analyze(
        packages=packages, root={"foo-bar": ""},
        package="FOO-BAR", candidates=["1.0"],
    )
    assert status == 200
    assert body["target"] == {"package": "foo-bar"}
    # The index's own normalized version string is echoed.
    assert body["candidates"][0]["candidate"] == "1.0.0"
    assert body["candidates"][0]["resolved"]["foo-bar"] == "1.0.0"


def test_single_and_eight_candidates_are_allowed():
    packages = {"x": {str(v): {} for v in range(1, 9)}}
    status, body = _analyze(
        packages=packages, root={"x": ""},
        package="x", candidates=[str(v) for v in range(1, 9)],
    )
    assert status == 200
    assert len(body["candidates"]) == 8
    assert body["summary"]["candidates"] == 8


def test_deterministic_results():
    payload = {**BASE, "package": "web", "candidates": ["3.0", "2.0"]}
    results = [
        client.post("/analyze/upgrade-feasibility", json=payload).json()
        for _ in range(3)
    ]
    assert all(r == results[0] for r in results)


def test_supplied_index_and_inputs_are_not_mutated():
    packages = {"x": {"1.0": {}, "2.0": {}, "3.0": {}}}
    payload = {
        "packages": packages,
        "root": {"x": "<=2.0"},
        "package": "x",
        "candidates": ["3.0"],
    }
    status, body = _analyze(**payload)
    assert status == 200
    # The temporary pin made the candidate conflict with root "<=2.0"; a
    # follow-up /resolve with the same index must not remember that pin.
    followup = client.post(
        "/resolve",
        json={"packages": packages, "root": {"x": ""}},
    ).json()
    assert followup["status"] == "ok"
    assert followup["resolved"]["x"] == "3.0"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_unknown_target_package_is_400():
    status, body = _analyze(**BASE, package="ghost", candidates=["1.0"])
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "ghost" in body["error"]["message"]


def test_candidate_absent_from_index_is_400():
    status, body = _analyze(**BASE, package="web", candidates=["9.9"])
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "9.9" in body["error"]["message"]
    assert "3.0" in body["error"]["message"]  # available versions listed


def test_non_pep440_candidate_is_400():
    status, body = _analyze(**BASE, package="web", candidates=["nope"])
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "nope" in body["error"]["message"]


def test_duplicate_candidates_after_normalization_are_400():
    packages = {"x": {"1.0.0": {}, "2.0": {}}}
    status, body = _analyze(
        packages=packages, root={"x": ""},
        package="x", candidates=["1.0.0", "1.0"],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    message = body["error"]["message"]
    assert "duplicate" in message
    assert "1.0" in message


def test_duplicate_literal_candidates_are_400():
    status, body = _analyze(**BASE, package="web", candidates=["2.0", "2.0"])
    assert status == 400
    assert "duplicate" in body["error"]["message"]


def test_validation_errors_are_batched():
    status, body = _analyze(
        **BASE, package="web", candidates=["nope", "9.9", "3.0", "2.0"]
    )
    assert status == 400
    message = body["error"]["message"]
    # Both invalid candidates are reported in one error, even though the
    # request also contains valid candidates.
    assert "nope" in message
    assert "9.9" in message


def test_empty_candidates_list_and_too_many_are_422():
    response = client.post(
        "/analyze/upgrade-feasibility",
        json={**BASE, "package": "web", "candidates": []},
    )
    assert response.status_code == 422
    nine = [str(v) for v in range(1, 10)]
    response = client.post(
        "/analyze/upgrade-feasibility",
        json={
            "packages": {"x": {v: {} for v in nine}},
            "root": {"x": ""},
            "package": "x",
            "candidates": nine,
        },
    )
    assert response.status_code == 422


def test_shape_validation():
    # Missing package / candidates.
    response = client.post(
        "/analyze/upgrade-feasibility", json=BASE
    )
    assert response.status_code == 422
    # Empty package name.
    response = client.post(
        "/analyze/upgrade-feasibility",
        json={**BASE, "package": "", "candidates": ["1.0"]},
    )
    assert response.status_code == 422
    # Unexpected top-level field.
    response = client.post(
        "/analyze/upgrade-feasibility",
        json={**BASE, "package": "web", "candidates": ["2.0"], "extra": 1},
    )
    assert response.status_code == 422


def test_resolve_input_validation_is_reused():
    packages = {"x": {"not-a-version": {}}}
    status, body = _analyze(
        packages=packages, root={"x": ""},
        package="x", candidates=["1.0"],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"

    status, body = _analyze(
        packages={"x": {"1.0": {}}}, root=">>>1",
        package="x", candidates=["1.0"],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"

    status, body = _analyze(
        packages={"x": {"1.0": {}}}, root={"x": ""},
        locks={"x": "not-a-version"},
        package="x", candidates=["1.0"],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
