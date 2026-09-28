"""Version-withdrawal impact analysis.

Given the same input as ``/resolve`` plus one ``withdraw`` target (a package
and one of its versions), this module answers: *what happens to the
resolution if that version disappears from the package index?*

Semantics
---------
* The baseline solve runs on the unmodified index.
* The withdrawal solve runs on a copy of this request's index with exactly
  the withdrawn (package, version) removed; every other version, the root
  requirements, locks, marker environment and attempt budget are unchanged.
  Only this request's in-memory index is touched.
* The withdrawal solve is a full re-resolution against the complete
  dependency constraints — never an inference along the old dependency
  graph — so any backtracking the withdrawal triggers (fallback versions,
  newly pulled-in or dropped transitive packages) is recomputed by the
  solver from scratch.
* Only when both solves succeed does the response list the packages that
  were added, removed or changed version, together with the post-withdrawal
  dependency graph and lock disposition.
* A baseline conflict, a post-withdrawal conflict and either solve hitting
  the search limit are reported as distinct statuses; hitting the limit is
  not treated as unsatisfiable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .resolver import (
    PackageIndex,
    ResolutionInputError,
    RootEntry,
    SolveResult,
    resolve,
)
from .serialize import conflict_summary


@dataclass(frozen=True)
class WithdrawTarget:
    """The validated (package, version) pair to remove from the index."""

    package: str  # canonical name
    version: Version  # the matching index version


def parse_withdraw_target(
    index: PackageIndex, package: str, version: str
) -> WithdrawTarget:
    """Validate the withdraw target against the parsed index.

    Names and versions are normalized with the same rules as the index
    itself, so ``Foo_Bar``/``foo-bar`` and ``1.0``/``1.0.0`` refer to the
    same entry.  An unknown package or version is an input error (400).
    """
    canonical = canonicalize_name(package)
    if canonical not in index.versions:
        raise ResolutionInputError(
            f"withdraw: package {package!r} is not present in the supplied index"
        )
    try:
        parsed = Version(version)
    except InvalidVersion as exc:
        raise ResolutionInputError(
            f"withdraw: version {version!r} is not PEP 440: {exc}"
        )
    for candidate, _record in index.versions[canonical]:
        if candidate == parsed:
            return WithdrawTarget(package=canonical, version=candidate)
    available = ", ".join(
        str(v) for v, _ in sorted(index.versions[canonical], reverse=True)
    )
    raise ResolutionInputError(
        f"withdraw: package {canonical!r} has no version {version!r} "
        f"in the supplied index (available: {available or 'none'})"
    )


def _withdrawn_index(index: PackageIndex, target: WithdrawTarget) -> PackageIndex:
    """Copy of the index with exactly the withdrawn version removed.

    The package itself stays in the index even when its last version is
    withdrawn, so the solver reports it as "no versions left" rather than
    "package not found".
    """
    reduced = PackageIndex()
    for name, records in index.versions.items():
        if name == target.package:
            reduced.versions[name] = [
                (version, record)
                for version, record in records
                if version != target.version
            ]
        else:
            reduced.versions[name] = list(records)
    return reduced


def _changes(baseline: dict[str, str], withdrawn: dict[str, str]) -> dict[str, Any]:
    """Diff two successful resolutions; every list is sorted by package name."""
    added = [
        {"package": name, "version": withdrawn[name]}
        for name in sorted(withdrawn.keys() - baseline.keys())
    ]
    removed = [
        {"package": name, "version": baseline[name]}
        for name in sorted(baseline.keys() - withdrawn.keys())
    ]
    changed = [
        {"package": name, "from": baseline[name], "to": withdrawn[name]}
        for name in sorted(baseline.keys() & withdrawn.keys())
        if baseline[name] != withdrawn[name]
    ]
    return {"added": added, "removed": removed, "changed": changed}


def run_version_withdrawal(
    index: PackageIndex,
    entries: list[RootEntry],
    locks: dict[str, Version],
    *,
    allow_prereleases: bool,
    marker_env: Optional[dict[str, str]],
    max_attempts: int,
    withdraw_package: str,
    withdraw_version: str,
) -> dict[str, Any]:
    """Solve baseline and post-withdrawal, then render the public JSON body."""
    target = parse_withdraw_target(index, withdraw_package, withdraw_version)
    roots = [entry.dep for entry in entries]

    def solve(idx: PackageIndex) -> SolveResult:
        return resolve(
            idx,
            roots,
            locks,
            allow_prereleases=allow_prereleases,
            marker_env=marker_env,
            max_attempts=max_attempts,
        )

    def body(status: str, attempts: int, **extra: Any) -> dict[str, Any]:
        return {
            "status": status,
            "attempts": attempts,
            "allow_prereleases": allow_prereleases,
            "withdraw": {"package": target.package, "version": str(target.version)},
            **extra,
        }

    baseline = solve(index)
    if baseline.status == "limit":
        return body(
            "undetermined",
            baseline.attempts,
            error={
                "code": "search_limit_exceeded",
                "message": (
                    f"baseline solve exceeded {max_attempts} candidate "
                    "evaluations; the input may still be satisfiable"
                ),
            },
        )
    if baseline.status == "conflict":
        return body(
            "baseline_conflict",
            baseline.attempts,
            locks=baseline.lock_notes,
            conflict=conflict_summary(baseline),
        )

    withdrawn = solve(_withdrawn_index(index, target))
    attempts = baseline.attempts + withdrawn.attempts

    if withdrawn.status == "limit":
        return body(
            "undetermined",
            attempts,
            baseline_resolved=baseline.chosen,
            error={
                "code": "search_limit_exceeded",
                "message": (
                    f"post-withdrawal solve exceeded {max_attempts} candidate "
                    "evaluations; the withdrawn input may still be satisfiable"
                ),
            },
        )
    if withdrawn.status == "conflict":
        return body(
            "withdrawn_conflict",
            attempts,
            baseline_resolved=baseline.chosen,
            locks=withdrawn.lock_notes,
            conflict=conflict_summary(withdrawn),
        )

    return body(
        "ok",
        attempts,
        changes=_changes(baseline.chosen, withdrawn.chosen),
        baseline_resolved=baseline.chosen,
        resolved=withdrawn.chosen,
        dependency_graph=withdrawn.edges,
        locks=withdrawn.lock_notes,
    )
