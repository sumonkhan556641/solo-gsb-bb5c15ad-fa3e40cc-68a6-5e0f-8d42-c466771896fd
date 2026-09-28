"""End-to-end tests for ``POST /diagnose/root-conflict``.

The diagnosis must return a *minimal* conflicting root set: the set itself
is unsatisfiable, but deleting any single entry from it makes the remainder
solvable.  This is checked directly, against a brute-force oracle, and
around the solver's non-monotone pre-release-pin rule.
"""

import itertools
import random

from fastapi.testclient import TestClient
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from app.main import app
from app.resolver import parse_index, parse_root_entries, resolve
from app.diagnose import diagnose_root_conflict

client = TestClient(app)

CONFLICT_PACKAGES = {
    "service-a": {"1.0": {"dependencies": {"libfoo": ">=2.0"}}},
    "service-b": {"1.0": {"dependencies": {"libfoo": "<2.0"}}},
    "libfoo": {"1.0": {}, "2.0": {}, "3.0": {}},
}


def _diagnose(**payload):
    response = client.post("/diagnose/root-conflict", json=payload)
    return response.status_code, response.json()


def _resolve(root, **extra):
    payload = {"packages": CONFLICT_PACKAGES, "root": root, **extra}
    response = client.post("/resolve", json=payload)
    return response.json()


def test_solvable_input_returns_ok_and_empty_set():
    status, body = _diagnose(packages={"x": {"1.0": {}, "2.0": {}}}, root={"x": ">=1.0"})
    assert status == 200
    assert body["status"] == "ok"
    assert body["conflicting_roots"] == []


def test_empty_root_is_ok():
    status, body = _diagnose(packages={"x": {"1.0": {}}}, root=[])
    assert status == 200
    assert body["status"] == "ok"
    assert body["conflicting_roots"] == []


def test_conflict_returns_minimal_conflicting_roots():
    status, body = _diagnose(packages=CONFLICT_PACKAGES, root=["service-a", "service-b"])
    assert status == 200
    assert body["status"] == "conflict"
    entries = body["conflicting_roots"]
    assert [e["index"] for e in entries] == [0, 1]
    assert [e["requirement"] for e in entries] == ["service-a", "service-b"]
    assert [e["package"] for e in entries] == ["service-a", "service-b"]
    for entry in entries:
        assert entry["specifier"] == ""
        assert entry["marker"] is None


def test_reported_set_is_unsatisfiable_but_minimal():
    status, body = _diagnose(packages=CONFLICT_PACKAGES, root=["service-a", "service-b"])
    assert status == 200
    indices = [e["index"] for e in body["conflicting_roots"]]
    roots = ["service-a", "service-b"]

    # The reported set itself still has no solution.
    assert _resolve([roots[i] for i in indices])["status"] == "conflict"
    # Removing any single entry makes it solvable: the set is inclusion-minimal.
    for i in indices:
        remaining = [roots[j] for j in indices if j != i]
        assert _resolve(remaining)["status"] == "ok"


def test_innocent_root_is_not_reported():
    # An unrelated, perfectly satisfiable requirement must not end up in the
    # core even though the full solve fails.
    packages = dict(CONFLICT_PACKAGES)
    packages["extra"] = {"1.0": {}, "2.0": {}}
    roots = ["extra>=1.0", "service-a", "service-b"]
    status, body = _diagnose(packages=packages, root=roots)
    assert status == 200
    assert body["status"] == "conflict"
    assert [e["index"] for e in body["conflicting_roots"]] == [1, 2]
    assert all(e["package"] != "extra" for e in body["conflicting_roots"])


def test_core_is_not_just_one_backtracking_branch():
    # Two independent clashes (a/b on x, c/d on y).  A single backtracking
    # path only witnesses one clash; the diagnosis must find one full
    # minimal set rather than a path-shaped partial answer.
    packages = {
        "a": {"1.0": {"dependencies": {"x": ">=2.0"}}},
        "b": {"1.0": {"dependencies": {"x": "<2.0"}}},
        "c": {"1.0": {"dependencies": {"y": ">=2.0"}}},
        "d": {"1.0": {"dependencies": {"y": "<2.0"}}},
        "x": {"1.0": {}, "2.0": {}},
        "y": {"1.0": {}, "2.0": {}},
    }
    roots = ["a", "b", "c", "d"]
    status, body = _diagnose(packages=packages, root=roots)
    assert status == 200
    indices = {e["index"] for e in body["conflicting_roots"]}
    assert indices == {2, 3}  # stable deletion order keeps the second clash
    # Minimal: the core itself is unsatisfiable, but dropping either member
    # of it is solvable.  ({a,b} outside the core is an independent clash,
    # not part of this minimal set.)
    assert _resolve([roots[j] for j in indices])["status"] == "conflict"
    for dropped in indices:
        remaining = [roots[j] for j in indices if j != dropped]
        response = client.post(
            "/resolve", json={"packages": packages, "root": remaining}
        )
        assert response.json()["status"] == "ok"


def test_duplicate_requirements_distinguished_by_input_position():
    # The same requirement appears twice; positions 0 and 1 are distinct
    # entries.  Deleting one duplicate keeps the clash, so the stable
    # deletion walk drops the earlier copy and keeps the later one.
    status, body = _diagnose(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root=["x>=2.0", "x>=2.0", "x<2.0"],
    )
    assert status == 200
    assert body["status"] == "conflict"
    indices = [e["index"] for e in body["conflicting_roots"]]
    assert indices == [1, 2]
    assert body["conflicting_roots"][0]["requirement"] == "x>=2.0"
    assert body["conflicting_roots"][1]["requirement"] == "x<2.0"


def test_single_self_unsatisfiable_root():
    status, body = _diagnose(
        packages={"x": {"1.0": {}}},
        root=["x==2.0"],
    )
    assert status == 200
    assert body["status"] == "conflict"
    entries = body["conflicting_roots"]
    assert [e["index"] for e in entries] == [0]
    # Removing the only entry leaves an empty, solvable root.
    assert _resolve([])["status"] == "ok"


def test_missing_package_is_a_singleton_core():
    status, body = _diagnose(
        packages={"x": {"1.0": {}}},
        root=["ghost>=1.0", "x"],
    )
    assert status == 200
    assert [e["index"] for e in body["conflicting_roots"]] == [0]


def test_dict_form_preserves_position_and_original_text():
    # Mapping insertion order is the position; the original (pre-normalized)
    # key spelling is retained in the requirement text.
    status, body = _diagnose(
        packages={"x": {"1.0": {}}, "y": {"1.0": {}}},
        root={"X": "==2.0", "y": ""},
    )
    assert status == 200
    assert body["status"] == "conflict"
    (entry,) = body["conflicting_roots"]
    assert entry == {
        "index": 0,
        "package": "x",
        "requirement": "X ==2.0",
        "specifier": "==2.0",
        "marker": None,
    }


def test_marker_inactive_requirement_cannot_be_in_core():
    # The first requirement never applies in the default linux env; only
    # x<2.0 remains and is solvable.
    status, body = _diagnose(
        packages={"x": {"1.0": {}, "2.0": {}}},
        root=["x>=2.0; sys_platform == 'win32'", "x<2.0"],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["conflicting_roots"] == []


def test_locks_are_passed_through_and_do_not_change_diagnosis():
    status, body = _diagnose(
        packages=CONFLICT_PACKAGES,
        root=["service-a", "service-b"],
        locks={"libfoo": "3.0"},
    )
    assert status == 200
    assert body["status"] == "conflict"
    assert [e["package"] for e in body["conflicting_roots"]] == [
        "service-a",
        "service-b",
    ]


def test_initial_search_limit_is_undetermined_not_conflict():
    packages = {
        f"p{i}": {
            f"{major}.0": {"dependencies": {f"p{i+1}": ""}}
            for major in range(1, 4)
        }
        for i in range(3)
    }
    packages["p3"] = {f"{major}.0": {} for major in range(1, 4)}
    status, body = _diagnose(packages=packages, root={"p0": ""}, max_attempts=2)
    assert status == 200
    assert body["status"] == "undetermined"
    assert body["conflicting_roots"] is None
    assert body["error"]["code"] == "search_limit_exceeded"


def test_resolve_search_limit_during_minimization_is_undetermined():
    # ghost_pkg clashes immediately (0 evaluations), while p0 opens the wide
    # search chain: dropping ghost_pkg re-solves the chain and hits the limit.
    packages = {
        f"p{i}": {
            f"{major}.0": {"dependencies": {f"p{i+1}": ""}}
            for major in range(1, 4)
        }
        for i in range(3)
    }
    packages["p3"] = {f"{major}.0": {} for major in range(1, 4)}
    packages["ghost_pkg"] = {}
    status, body = _diagnose(
        packages=packages, root=["ghost_pkg", "p0"], max_attempts=2
    )
    assert status == 200
    assert body["status"] == "undetermined"
    assert body["conflicting_roots"] is None
    assert "ghost_pkg" in body["error"]["message"]


def test_undetermined_never_pretends_the_input_is_unsolvable():
    packages = {
        f"p{i}": {
            f"{major}.0": {"dependencies": {f"p{i+1}": ""}}
            for major in range(1, 4)
        }
        for i in range(3)
    }
    packages["p3"] = {f"{major}.0": {} for major in range(1, 4)}
    # The chain is genuinely solvable; a tiny limit must not flip it to conflict.
    status, body = _diagnose(packages=packages, root={"p0": ""}, max_attempts=1)
    assert status == 200
    assert body["status"] == "undetermined"
    assert body["conflicting_roots"] is None


def test_prerelease_pin_nonmonotonicity_still_yields_minimal_core():
    # x ships final 2.0 and pre-release 2.0rc1.
    #   e: x==2.0      (satisfiable alone)
    #   p: x==2.0rc1   (satisfiable alone; enables the pre-release globally)
    #   q: x!=2.0      (unsatisfiable alone: only the excluded rc1 remains)
    # A single deletion pass in this order would report the non-minimal
    # {e, q}; re-solving to a fixpoint must reduce it to the true core {q}.
    packages = {"x": {"2.0": {}, "2.0rc1": {}}}
    roots = ["x==2.0", "x==2.0rc1", "x!=2.0"]
    status, body = _diagnose(packages=packages, root=roots)
    assert status == 200
    assert body["status"] == "conflict"
    assert [e["index"] for e in body["conflicting_roots"]] == [2]
    # Sanity-check the underlying subset semantics the minimization relies on.
    assert _resolve_with(packages, ["x!=2.0"]).status == "conflict"
    assert _resolve_with(packages, ["x==2.0", "x!=2.0"]).status == "conflict"
    assert _resolve_with(packages, ["x==2.0rc1", "x!=2.0"]).status == "ok"


def _resolve_with(packages, root):
    index, errors = parse_index(packages)
    assert not errors
    return resolve(
        index,
        [e.dep for e in parse_root_entries(root, "root")],
        {},
    )


def test_results_are_deterministic():
    roots = ["a", "b", "c", "d"]
    packages = {
        "a": {"1.0": {"dependencies": {"x": ">=2.0"}}},
        "b": {"1.0": {"dependencies": {"x": "<2.0"}}},
        "c": {"1.0": {"dependencies": {"y": ">=2.0"}}},
        "d": {"1.0": {"dependencies": {"y": "<2.0"}}},
        "x": {"1.0": {}, "2.0": {}},
        "y": {"1.0": {}, "2.0": {}},
    }
    payload = {"packages": packages, "root": roots}
    responses = [
        client.post("/diagnose/root-conflict", json=payload).json()
        for _ in range(5)
    ]
    assert all(r == responses[0] for r in responses)


def test_core_function_reports_total_attempts():
    index, errors = parse_index(CONFLICT_PACKAGES)
    assert not errors
    entries = parse_root_entries(["service-a", "service-b"], "root requirements")
    diagnosis = diagnose_root_conflict(index, entries, {})
    assert diagnosis.status == "conflict"
    assert [e.index for e in diagnosis.core] == [0, 1]
    assert diagnosis.attempts >= 1


def test_invalid_input_uses_same_400_handler_as_resolve():
    invalid = {"packages": {"x": {"not-a-version": {}}}, "root": {"x": ""}}
    diagnosed = client.post("/diagnose/root-conflict", json=invalid)
    resolved = client.post("/resolve", json=invalid)
    assert diagnosed.status_code == resolved.status_code == 400
    assert diagnosed.json() == resolved.json()
    assert diagnosed.json()["error"]["code"] == "invalid_request"


def test_extra_fields_rejected_like_resolve():
    response = client.post(
        "/diagnose/root-conflict",
        json={"packages": {}, "root": {}, "unexpected": 1},
    )
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# Brute-force oracle: the reported set must be unsatisfiable but minimal
# ---------------------------------------------------------------------------

OPS = [">=", "==", "<", ">", "<=", "!="]


def _brute_force(packages, root_specs):
    """Return a feasible assignment or None.

    ``root_specs`` maps a package to a list of specifiers that must all hold.
    Only the closure reachable from the roots must be assignable, mirroring
    the solver semantics used in test_oracle.py.
    """
    names = list(packages)
    per_package = {
        n: [
            v
            for v in sorted(packages[n], key=Version, reverse=True)
            if not Version(v).is_prerelease
        ]
        for n in names
    }
    root_sets = {
        n: [SpecifierSet(s) for s in specs] for n, specs in root_specs.items()
    }

    def feasible(assign):
        chosen, frontier = set(), set(root_sets)
        while frontier:
            pkg = frontier.pop()
            if pkg in chosen:
                continue
            if pkg not in assign or assign[pkg] is None:
                return False
            chosen.add(pkg)
            version = Version(assign[pkg])
            if any(
                not spec.contains(version, prereleases=True)
                for spec in root_sets.get(pkg, [])
            ):
                return False
            for dep, dep_spec in packages[pkg][assign[pkg]].get(
                "dependencies", {}
            ).items():
                if dep not in assign or assign[dep] is None:
                    return False
                if not SpecifierSet(dep_spec).contains(
                    Version(assign[dep]), prereleases=True
                ):
                    return False
                if dep not in chosen:
                    frontier.add(dep)
        return True

    for combo in itertools.product(
        *[(per_package[n] or [None]) for n in names]
    ):
        assignment = dict(zip(names, combo))
        if feasible(assignment):
            return assignment
    return None


def _grouped(specs):
    grouped: dict[str, list[str]] = {}
    for text in specs:
        req = Requirement(text)
        grouped.setdefault(req.name, []).append(str(req.specifier))
    return grouped


def test_diagnosis_matches_brute_force_on_random_graphs():
    rng = random.Random(20260926)
    checked = 0
    for _ in range(300):
        n = rng.randint(1, 4)
        names = [f"p{i}" for i in range(n)]
        packages = {}
        for name in names:
            versions = {}
            for major in range(1, rng.randint(2, 4) + 1):
                deps = {}
                for other in names:
                    if other != name and rng.random() < 0.3:
                        deps[other] = f"{rng.choice(OPS)}{rng.randint(1, 3)}.0"
                versions[f"{major}.0"] = {"dependencies": deps}
            packages[name] = versions

        roots = [
            f"{rng.choice(names)}{rng.choice(OPS)}{rng.randint(1, 3)}.0"
            for _ in range(rng.randint(1, 4))
        ]

        response = client.post(
            "/diagnose/root-conflict", json={"packages": packages, "root": roots}
        )
        assert response.status_code == 200
        body = response.json()
        full_feasible = _brute_force(packages, _grouped(roots)) is not None

        if full_feasible:
            assert body["status"] == "ok"
            assert body["conflicting_roots"] == []
            continue

        assert body["status"] == "conflict"
        checked += 1
        entries = body["conflicting_roots"]
        indices = [entry["index"] for entry in entries]
        assert len(indices) == len(set(indices))
        assert all(0 <= i < len(roots) for i in indices)
        for entry in entries:
            # Original text and input position are preserved.
            assert entry["requirement"] == roots[entry["index"]]
        # The core itself must be infeasible.
        assert _brute_force(packages, _grouped(roots[i] for i in indices)) is None
        # Deleting any single member must make it feasible.
        for dropped in indices:
            rest = [roots[i] for i in indices if i != dropped]
            assert _brute_force(packages, _grouped(rest)) is not None

    assert checked > 50  # the random suite actually exercised conflicts
