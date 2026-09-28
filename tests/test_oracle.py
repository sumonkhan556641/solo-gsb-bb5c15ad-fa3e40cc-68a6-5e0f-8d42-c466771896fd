"""Differential testing: solver vs. an exhaustive brute-force oracle.

Small random dependency graphs are generated with a fixed seed; every
result is checked for (a) validity of every produced assignment and
(b) agreement with brute force on feasibility.
"""

import itertools
import random

from packaging.specifiers import SpecifierSet
from packaging.version import Version

from app.resolver import parse_index, parse_locks, parse_requirements, resolve

OPS = [">=", "==", "<", ">", "<=", "!="]


def _candidate_versions(packages, name, allow_pre, lock_v):
    return [
        str(v)
        for v in sorted((Version(v) for v in packages[name]), reverse=True)
        if allow_pre
        or not v.is_prerelease
        or (name in lock_v and v == lock_v[name])
    ]


def _brute_force(packages, root, allow_pre=False, locks=None):
    """Return one feasible assignment or None.

    Locks are preferences, so feasibility ignores whether the lock is used.
    Only the closure reachable from the root must be assignable; packages
    absent from that closure are irrelevant (and may have no candidates).
    """
    names = list(packages)
    lock_v = locks or {}
    per_package = {
        n: _candidate_versions(packages, n, allow_pre, lock_v) for n in names
    }
    root_spec = {n: SpecifierSet(s) for n, s in root.items()}

    for combo in itertools.product(
        *[(per_package[n] or [None]) for n in names]
    ):
        assign = dict(zip(names, combo))
        chosen, frontier, valid = {}, set(root), True
        while frontier:
            pkg = frontier.pop()
            if pkg in chosen:
                continue
            if pkg not in assign or assign[pkg] is None:
                valid = False
                break
            chosen[pkg] = assign[pkg]
            if pkg in root_spec and not root_spec[pkg].contains(
                Version(assign[pkg]), prereleases=True
            ):
                valid = False
                break
            for dep, spec in packages[pkg][assign[pkg]].get(
                "dependencies", {}
            ).items():
                if dep not in assign or assign[dep] is None:
                    valid = False
                    break
                if not SpecifierSet(spec).contains(
                    Version(assign[dep]), prereleases=True
                ):
                    valid = False
                    break
                if dep not in chosen:
                    frontier.add(dep)
            if not valid:
                break
        if valid:
            return chosen
    return None


def _valid_assignment(packages, assign):
    for pkg, version in assign.items():
        if pkg not in packages or version not in packages[pkg]:
            return False
        for dep, spec in packages[pkg][version].get("dependencies", {}).items():
            if dep not in assign:
                return False
            if not SpecifierSet(spec).contains(
                Version(assign[dep]), prereleases=True
            ):
                return False
    return True


def _closure(packages, root, assign):
    seen, frontier = set(), set(root)
    while frontier:
        pkg = frontier.pop()
        if pkg in seen:
            continue
        seen.add(pkg)
        for dep in packages[pkg][assign[pkg]].get("dependencies", {}):
            if dep not in seen:
                frontier.add(dep)
    return seen


def test_solver_matches_brute_force_on_random_graphs():
    rng = random.Random(20260917)
    missed = false_solutions = 0
    for _ in range(300):
        n = rng.randint(1, 5)
        names = [f"p{i}" for i in range(n)]
        packages = {}
        for name in names:
            count = rng.randint(1, 3)
            versions = {}
            for vi in range(1, count + 1):
                vstr = f"{vi}.0"
                if rng.random() < 0.15:
                    vstr = f"{vi}.0rc1"
                deps = {}
                for other in names:
                    if other != name and rng.random() < 0.3:
                        deps[other] = f"{rng.choice(OPS)}{rng.randint(1, 3)}.0"
                versions[vstr] = {"dependencies": deps}
            packages[name] = versions

        root = {names[0]: ""}
        allow_pre = rng.random() < 0.4
        locks_raw = {}
        if rng.random() < 0.4:
            target = rng.choice(names)
            locks_raw = {target: rng.choice(list(packages[target]))}

        index, errors = parse_index(packages)
        assert not errors
        parsed_locks, lock_errors = parse_locks(locks_raw)
        assert not lock_errors
        result = resolve(
            index,
            parse_requirements(root, "root"),
            parsed_locks,
            allow_prereleases=allow_pre,
        )
        oracle = _brute_force(
            packages, root, allow_pre=allow_pre, locks=parsed_locks
        )

        if result.status == "ok":
            if not _valid_assignment(packages, result.chosen):
                false_solutions += 1
            if oracle is None:
                false_solutions += 1
            else:
                # Every reachable package must be present in the solution.
                closure = _closure(packages, root, result.chosen)
                if not closure <= set(result.chosen):
                    false_solutions += 1
        elif oracle is not None:
            missed += 1

    assert false_solutions == 0
    assert missed == 0
