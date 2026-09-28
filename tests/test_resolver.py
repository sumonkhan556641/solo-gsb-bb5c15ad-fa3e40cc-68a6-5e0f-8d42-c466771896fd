"""Unit tests for solver behaviour that is easier to assert at the core layer."""

from app.resolver import (
    parse_index,
    parse_locks,
    parse_requirements,
    resolve,
)


def solve(packages, root, locks=None, **kwargs):
    index, errors = parse_index(packages)
    assert not errors, errors
    roots = parse_requirements(root, "root")
    parsed_locks, lock_errors = parse_locks(locks or {})
    assert not lock_errors, lock_errors
    return resolve(index, roots, parsed_locks, **kwargs)


def test_highest_version_selected_first():
    result = solve(
        {"x": {"1.0": {}, "1.5": {}, "2.0": {}, "2.0.1": {}}},
        {"x": ">=1.0"},
    )
    assert result.chosen == {"x": "2.0.1"}


def test_pep440_version_ordering():
    # Post-releases sort after their release; epochs are respected.
    result = solve(
        {"x": {"1.0": {}, "1.0.post1": {}, "2!1.0": {}}},
        {"x": ""},
    )
    assert result.chosen == {"x": "2!1.0"}


def test_deep_transitive_backtracking():
    # app -> top 1.x and hard==1.0; top 2.0 forces hard>=2.0, so the
    # resolver must backtrack from top 2.0 to top 1.0.
    packages = {
        "app": {"1.0": {"dependencies": {"top": ">=1.0", "hard": "==1.0"}}},
        "top": {
            "1.0": {"dependencies": {"hard": ">=1.0"}},
            "2.0": {"dependencies": {"hard": ">=2.0"}},
        },
        "hard": {"1.0": {}, "2.0": {}},
    }
    result = solve(packages, {"app": ""})
    assert result.status == "ok"
    assert result.chosen == {"app": "1.0", "top": "1.0", "hard": "1.0"}


def test_conflict_bubbles_to_correct_ancestor():
    # A conflict involving "left" must not discard the unrelated "right" choice.
    packages = {
        "app": {"1.0": {"dependencies": {"left": "", "right": ""}}},
        "left": {
            "1.0": {"dependencies": {"mid": ""}},
            "2.0": {},
        },
        "mid": {"1.0": {"dependencies": {"leaf": ">=2.0"}}},
        "right": {"1.0": {}},
        "leaf": {"1.0": {}},
    }
    result = solve(packages, {"app": ""})
    assert result.status == "ok"
    assert result.chosen == {
        "app": "1.0",
        "left": "2.0",
        "right": "1.0",
    }
    assert "mid" not in result.chosen
    assert "leaf" not in result.chosen


def test_impossible_conflict_is_structured():
    packages = {
        "a": {"1.0": {"dependencies": {"x": ">=2.0"}}},
        "x": {"1.0": {}, "2.0": {}},
    }
    result = solve(packages, {"a": "", "x": "<2.0"})
    assert result.status == "conflict"
    leaf = result.conflict
    # walk composites to the terminal leaf
    while hasattr(leaf, "children"):
        leaf = leaf.children[0]
    assert leaf.package == "x"
    sources = {c.source for c in leaf.constraints} | {c.source for c in leaf.rejected}
    assert {"<root>", "a"} <= sources


def test_lock_prerelease_honoured_even_without_global_flag():
    result = solve(
        {"x": {"1.0a1": {}, "0.9": {}}},
        {"x": ""},
        locks={"x": "1.0a1"},
    )
    assert result.status == "ok"
    assert result.chosen["x"] == "1.0a1"
    assert result.lock_notes["x"] == "applied"


def test_lock_for_unknown_package_is_note_but_not_error():
    result = solve(
        {"x": {"1.0": {}}},
        {"x": ""},
        locks={"ghost": "9.9"},
    )
    assert result.status == "ok"
    assert result.lock_notes["ghost"] == "not-found"


def test_lock_backtracked_note_when_locked_choice_fails_deeper():
    packages = {
        "x": {
            "1.0": {"dependencies": {"y": ">=2.0"}},
            "2.0": {},
        },
        "y": {"1.0": {}},
    }
    # Locked x==1.0 is compatible with the root constraint but its
    # dependency is impossible, so it must be abandoned for x==2.0.
    result = solve(packages, {"x": ""}, locks={"x": "1.0"})
    assert result.status == "ok"
    assert result.chosen["x"] == "2.0"
    assert result.lock_notes["x"] == "backtracked"


def test_lock_used_only_in_abandoned_branch_is_unused_not_applied():
    # A higher candidate adopts the locked package first, but an unrelated
    # transitive requirement of that same candidate is impossible.  The
    # winning fallback branch never needs the locked package at all, so the
    # "applied" verdict the dead branch produced must not leak: the lock is
    # unused in the final resolution.
    packages = {
        "app": {
            "2.0": {"dependencies": {"locked-pkg": "", "blocked": ""}},
            "1.0": {"dependencies": {"plain": ""}},
        },
        "locked-pkg": {"1.0": {}, "2.0": {}},
        "blocked": {"1.0": {"dependencies": {"missing": ">=2.0"}}},
        "missing": {"1.0": {}},
        "plain": {"1.0": {}},
    }
    result = solve(
        packages, {"app": ""}, locks={"locked-pkg": "2.0"}
    )
    assert result.status == "ok"
    assert result.chosen == {"app": "1.0", "plain": "1.0"}
    assert "locked-pkg" not in result.chosen
    assert result.lock_notes["locked-pkg"] == "unused"


def test_lock_applied_deep_in_abandoned_branch_is_rolled_back():
    # Same as above, but the locked package is pulled in one level deeper:
    # its "applied" note has to travel up the surviving frame chain and be
    # undone together with the losing top-level candidate.
    packages = {
        "app": {
            "2.0": {"dependencies": {"middle": "", "blocked": ""}},
            "1.0": {"dependencies": {"plain": ""}},
        },
        "middle": {"1.0": {"dependencies": {"locked-pkg": ""}}},
        "locked-pkg": {"1.0": {}},
        "blocked": {"1.0": {"dependencies": {"missing": ">=2.0"}}},
        "missing": {"1.0": {}},
        "plain": {"1.0": {}},
    }
    result = solve(packages, {"app": ""}, locks={"locked-pkg": "1.0"})
    assert result.status == "ok"
    assert result.chosen == {"app": "1.0", "plain": "1.0"}
    assert result.lock_notes["locked-pkg"] == "unused"


def test_locked_version_backtracked_after_immediate_conflict():
    # The locked version is selected, then a package demanded later in the
    # same branch requires an incompatible version of it ("rejected by prior
    # choice").  The package is re-choosing to another version, so the lock
    # was applied and disproven: backtracked, not unsatisfiable/unused.
    packages = {
        "app": {"2.0": {"dependencies": {"locked-pkg": "", "pinner": ""}}},
        "pinner": {"1.0": {"dependencies": {"locked-pkg": "==1.0"}}},
        "locked-pkg": {"1.0": {}, "2.0": {}},
    }
    result = solve(packages, {"app": ""}, locks={"locked-pkg": "2.0"})
    assert result.status == "ok"
    assert result.chosen["locked-pkg"] == "1.0"
    assert result.lock_notes["locked-pkg"] == "backtracked"


def test_failed_resolution_does_not_report_branch_lock_states():
    # No solution: the lock was applied in every explored branch, but there
    # is no successful branch to own that disposition, so it must not be
    # reported as applied/backtracked.
    packages = {
        "app": {
            "2.0": {"dependencies": {"locked-pkg": "", "blocked": ""}},
            "1.0": {"dependencies": {"locked-pkg": "", "blocked": ""}},
        },
        "locked-pkg": {"1.0": {}, "2.0": {}},
        "blocked": {"1.0": {"dependencies": {"missing": ">=2.0"}}},
        "missing": {"1.0": {}},
    }
    result = solve(
        packages,
        {"app": ""},
        locks={"locked-pkg": "2.0", "ghost": "1.0"},
    )
    assert result.status == "conflict"
    assert "locked-pkg" not in result.lock_notes
    assert result.lock_notes["ghost"] == "not-found"


def test_search_limit_does_not_report_branch_lock_states():
    packages = {
        "app": {
            "2.0": {"dependencies": {"locked-pkg": "", "blocked": ""}},
            "1.0": {"dependencies": {"locked-pkg": "", "blocked": ""}},
        },
        "locked-pkg": {"1.0": {}, "2.0": {}},
        "blocked": {"1.0": {"dependencies": {"missing": ">=2.0"}}},
        "missing": {"1.0": {}},
    }
    result = solve(
        packages, {"app": ""}, locks={"locked-pkg": "2.0"}, max_attempts=1
    )
    assert result.status == "limit"
    assert "locked-pkg" not in result.lock_notes


def test_failed_resolution_reports_root_unsatisfiable_lock():
    # The root requirement alone rules the lock out; that fact holds on
    # every branch and is therefore safe to report even on overall failure.
    packages = {
        "a": {"1.0": {"dependencies": {"missing": ">=2.0"}}},
        "missing": {"1.0": {}},
    }
    result = solve(
        packages,
        {"a": "", "x": ">=2.0"},
        locks={"x": "1.0", "ghost": "1.0"},
    )
    assert result.status == "conflict"
    assert result.lock_notes["x"] == "unsatisfiable"
    assert result.lock_notes["ghost"] == "not-found"


def test_exhaustive_conflict_reports_transitive_unsatisfiable_lock():
    # The lock is ruled out only by constraints accumulated along the
    # explored branches.  An exhaustive conflict proves impossibility, so the
    # verdict is factual and preserved (same as the historical behaviour).
    packages = {
        "a": {"1.0": {"dependencies": {"x": ">=2.0"}}},
        "b": {"1.0": {"dependencies": {"x": "<2.0"}}},
        "x": {"1.0": {}, "2.0": {}},
    }
    result = solve(packages, ["a", "b"], locks={"x": "1.0"})
    assert result.status == "conflict"
    assert result.lock_notes["x"] == "unsatisfiable"


def test_search_limit_omits_transitive_unsatisfiable_lock():
    # Same constraints, but the budget runs out before exhaustion: the
    # transitive "unsatisfiable" verdict may not hold on unexplored branches,
    # so it must be omitted (static index facts are still reported).
    packages = {
        "a": {"1.0": {"dependencies": {"x": ">=2.0"}}},
        "b": {"1.0": {"dependencies": {"x": "<2.0"}}},
        "x": {"1.0": {}, "2.0": {}},
    }
    result = solve(
        packages, ["a", "b"], locks={"x": "1.0"}, max_attempts=1
    )
    assert result.status == "limit"
    assert "x" not in result.lock_notes




def test_self_dependency_does_not_deadlock():
    result = solve(
        {"x": {"1.0": {"dependencies": {"x": ">=1.0"}}}},
        {"x": ""},
    )
    assert result.status == "ok"
    assert result.chosen == {"x": "1.0"}


def test_no_versions_reason():
    result = solve({"x": {}}, {"x": ""})
    assert result.status == "conflict"
    assert result.conflict.reason == "no-versions"


def test_unsatisfiable_dependency_against_prior_choice_reports_rejected_by():
    packages = {
        "app": {"1.0": {"dependencies": {"lib": "==1.0"}}},
        "lib": {
            "1.0": {"dependencies": {"util": ">=2.0"}},
            "2.0": {},
        },
        "util": {"1.0": {}},
    }
    result = solve(packages, {"app": ""})
    assert result.status == "conflict"
    leaf = result.conflict
    while hasattr(leaf, "children"):
        leaf = leaf.children[0]
    assert leaf.package == "util"
    assert leaf.reason == "unsatisfiable"
    assert any(
        c.source == "lib" and c.specifier_text == ">=2.0"
        for c in leaf.constraints
    )


def test_constraint_rejected_by_prior_choice_is_reported():
    # lib==1.0 is selected first (a demands it before z); deeper down z ->
    # app later requires lib==2.0, contradicting the already chosen version.
    # The new constraint must appear in rejected_by with its full path.
    packages = {
        "a": {"1.0": {"dependencies": {"lib": "==1.0", "z": ""}}},
        "z": {"1.0": {"dependencies": {"app": ""}}},
        "app": {"1.0": {"dependencies": {"lib": "==2.0"}}},
        "lib": {"1.0": {}, "2.0": {}},
    }
    result = solve(packages, {"a": ""})
    assert result.status == "conflict"
    leaf = result.conflict
    while hasattr(leaf, "children"):
        leaf = leaf.children[0]
    assert leaf.package == "lib"
    assert any(
        c.source == "app" and c.specifier_text == "==2.0" for c in leaf.rejected
    )


def test_max_attempts_limit():
    packages = {
        "p0": {f"{n}.0": {"dependencies": {"p1": ""}} for n in range(1, 5)},
        "p1": {f"{n}.0": {} for n in range(1, 5)},
    }
    result = solve(packages, {"p0": ""}, max_attempts=1)
    assert result.status == "limit"


def test_determinism_repeated_runs():
    packages = {
        "app": {"1.0": {"dependencies": {"a": "", "b": ""}}},
        "a": {
            "1.0": {"dependencies": {"s": "<2.0"}},
            "2.0": {"dependencies": {"s": ">=2.0"}},
        },
        "b": {"1.0": {"dependencies": {"s": "==1.0"}}},
        "s": {"1.0": {}, "2.0": {}},
    }
    first = solve(packages, {"app": ""})
    for _ in range(4):
        again = solve(packages, {"app": ""})
        assert again.chosen == first.chosen
        assert again.attempts == first.attempts
