"""Upgrade-feasibility analysis.

Given the same package index, root requirements, locks and solve options as
``/resolve`` plus a target package and 1-8 candidate versions, this module
answers: *which of these exact versions of the target package can the whole
project be re-resolved to?*

Semantics
---------
* Every candidate version must exist in the supplied index for the target
  package, and candidates may not repeat after PEP 440 normalization.
  Anything else is a 400 input error.
* For each candidate, in input order, an **additional** root requirement
  pinning the target package to exactly that version is temporarily added
  to the *original* root requirements — the original roots are kept, not
  replaced — and the whole project is solved independently with the
  ordinary exhaustive backtracking.  The original locks, marker
  environment, pre-release policy and a *full* ``max_attempts`` budget
  participate in every candidate solve.  Feasibility is therefore decided
  by a complete re-resolution against every transitive constraint, never by
  merely checking the target package's own version range.
* A lock on the target package that contradicts the temporary pin is
  falsified by the solver as usual (reported as ``unsatisfiable``) and the
  pinned candidate is tried instead; other locks keep lock-first behaviour.
* A baseline solve first establishes the *current locked state* from the
  unmodified input (original roots and locks, no temporary pin).  Each
  successful candidate then reports the version changes against that
  baseline (added / removed / changed).  When the baseline itself has no
  solution or stays undetermined, successful candidates fall back to a
  diff against the request's explicit ``locks`` mapping (``changes_relative_to``
  records which basis was used).
* Each candidate keeps its own ``ok`` / ``conflict`` / ``undetermined``
  status and ``attempts`` count.  On success the item carries the complete
  resolution and the version changes; on conflict it carries the structured
  conflict summary; hitting ``max_attempts`` is reported as ``undetermined``
  and is never treated as "not installable".
* The supplied index, roots and locks are never mutated; identical input
  always produces identical output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .resolver import (
    PackageIndex,
    ParsedDependency,
    ResolutionInputError,
    RootEntry,
    resolve,
)
from .serialize import conflict_summary


@dataclass(frozen=True)
class UpgradeCandidate:
    """One candidate exact version of the target package."""

    package: str  # canonical target name
    version: Version  # the matching index version


def parse_upgrade_target(
    index: PackageIndex,
    package: str,
    raw_versions: list[str],
) -> tuple[str, list[UpgradeCandidate]]:
    """Validate the target package and its candidate versions.

    Names and versions use the same normalization rules as the index, so
    ``Foo_Bar``/``foo-bar`` and ``1.0``/``1.0.0`` refer to the same entry.
    The target package must be present in the index and every candidate must
    be a valid PEP 440 version that exists for that package; candidates
    denoting the same PEP 440 version are rejected as duplicates.  Every
    problem is gathered into one :class:`ResolutionInputError` (HTTP 400).
    """
    canonical = canonicalize_name(package)
    if canonical not in index.versions:
        raise ResolutionInputError(
            f"upgrade: package {package!r} is not present in the supplied index"
        )

    index_versions = {version for version, _record in index.versions[canonical]}
    available = ", ".join(str(v) for v in sorted(index_versions, reverse=True))

    errors: list[str] = []
    seen: dict[Version, int] = {}
    candidates: list[UpgradeCandidate] = []
    for position, raw in enumerate(raw_versions):
        label = f"candidate #{position + 1} {raw!r}"
        try:
            parsed = Version(raw)
        except InvalidVersion as exc:
            errors.append(f"{label}: not a valid PEP 440 version: {exc}")
            continue
        previous = seen.get(parsed)
        if previous is not None:
            errors.append(
                f"{label}: duplicate version {str(parsed)!r} after PEP 440 "
                f"normalization (first given as candidate #{previous + 1})"
            )
            continue
        seen[parsed] = position
        match = next((v for v in index_versions if v == parsed), None)
        if match is None:
            errors.append(
                f"{label}: package {canonical!r} has no such version in the "
                f"supplied index (available: {available or 'none'})"
            )
            continue
        candidates.append(UpgradeCandidate(package=canonical, version=match))

    if errors:
        raise ResolutionInputError("upgrade: " + "; ".join(errors))
    return canonical, candidates


def _pin_dependency(package: str, version: Version) -> ParsedDependency:
    """Temporary exact-version root requirement added for one candidate."""
    spec = f"=={version}"
    return ParsedDependency(
        name=package,
        specifier=SpecifierSet(spec),
        specifier_text=spec,
        prerelease_pin=version.is_prerelease,
        marker_text=None,
        # A root pin applies unconditionally, like a marker-less root entry.
        applies=lambda _env: True,
    )


def _changes(before: dict[str, str], after: dict[str, str]) -> dict[str, Any]:
    """Diff two successful resolutions; every list is sorted by package."""
    added = [
        {"package": name, "version": after[name]}
        for name in sorted(after.keys() - before.keys())
    ]
    removed = [
        {"package": name, "version": before[name]}
        for name in sorted(before.keys() - after.keys())
    ]
    changed = [
        {"package": name, "from": before[name], "to": after[name]}
        for name in sorted(before.keys() & after.keys())
        if before[name] != after[name]
    ]
    return {"added": added, "removed": removed, "changed": changed}


def _locked_resolution(locks: dict[str, Version]) -> dict[str, str]:
    """The explicit request locks rendered as a resolved-version mapping."""
    return {pkg: str(version) for pkg, version in locks.items()}


def _candidate_body(
    candidate: UpgradeCandidate,
    result: Any,
    basis: str,
    before: dict[str, str],
    max_attempts: int,
) -> dict[str, Any]:
    """Render one candidate's independently-solved outcome.

    Successful items diff their resolution against ``before`` (the baseline
    locked resolution, or the explicit request locks when the baseline could
    not be solved); ``basis`` records which comparison basis was used.
    """
    item: dict[str, Any] = {
        "candidate": str(candidate.version),
        "attempts": result.attempts,
    }
    if result.status == "ok":
        item["status"] = "ok"
        item["resolved"] = result.chosen
        item["dependency_graph"] = result.edges
        item["locks"] = result.lock_notes
        item["changes_relative_to"] = basis
        item["changes"] = _changes(before, result.chosen)
        return item
    if result.status == "conflict":
        item["status"] = "conflict"
        item["locks"] = result.lock_notes
        item["conflict"] = conflict_summary(result)
        return item
    # limit: the search budget ran out, which is not a proof of conflict.
    item["status"] = "undetermined"
    item["locks"] = result.lock_notes
    item["conflict"] = conflict_summary(result)
    item["error"] = {
        "code": "search_limit_exceeded",
        "message": (
            f"resolution with {candidate.package}=={candidate.version} "
            f"exceeded {max_attempts} candidate evaluations; this candidate "
            "may still be installable"
        ),
    }
    return item


def run_upgrade_feasibility(
    index: PackageIndex,
    entries: list[RootEntry],
    locks: dict[str, Version],
    *,
    allow_prereleases: bool,
    marker_env: Optional[dict[str, str]],
    max_attempts: int,
    target_package: str,
    candidate_versions: list[str],
) -> dict[str, Any]:
    """Solve once per candidate and render the public JSON response body."""
    canonical, candidates = parse_upgrade_target(
        index, target_package, candidate_versions
    )
    roots = [entry.dep for entry in entries]

    # Baseline: the current locked state of the unmodified input.  It only
    # provides the "what changed" comparison basis, so a conflict/limit here
    # never prevents the independent candidate solves from running.
    baseline = resolve(
        index,
        roots,
        locks,
        allow_prereleases=allow_prereleases,
        marker_env=marker_env,
        max_attempts=max_attempts,
    )
    baseline_body: dict[str, Any] = {"attempts": baseline.attempts}
    if baseline.status == "ok":
        baseline_body["status"] = "ok"
        basis = "baseline"
        before: dict[str, str] = baseline.chosen
    elif baseline.status == "conflict":
        baseline_body["status"] = "conflict"
        baseline_body["locks"] = baseline.lock_notes
        baseline_body["conflict"] = conflict_summary(baseline)
        basis = "locks"
        before = _locked_resolution(locks)
    else:
        baseline_body["status"] = "undetermined"
        baseline_body["locks"] = baseline.lock_notes
        baseline_body["conflict"] = conflict_summary(baseline)
        baseline_body["error"] = {
            "code": "search_limit_exceeded",
            "message": (
                f"baseline solve exceeded {max_attempts} candidate "
                "evaluations; candidate changes are reported relative to the "
                "explicit request locks"
            ),
        }
        basis = "locks"
        before = _locked_resolution(locks)

    items: list[dict[str, Any]] = []
    counts = {"ok": 0, "conflict": 0, "undetermined": 0}
    for candidate in candidates:
        # The pin is *added* to the original roots: feasibility is judged
        # with every original root constraint and lock still in force, and
        # each candidate gets an independent full re-resolution (and its own
        # full attempt budget).
        result = resolve(
            index,
            roots + [_pin_dependency(canonical, candidate.version)],
            locks,
            allow_prereleases=allow_prereleases,
            marker_env=marker_env,
            max_attempts=max_attempts,
        )
        item = _candidate_body(candidate, result, basis, before, max_attempts)
        counts[item["status"]] += 1
        items.append(item)

    return {
        "status": "ok",
        "allow_prereleases": allow_prereleases,
        "target": {"package": canonical},
        "summary": {
            "candidates": len(candidates),
            "ok": counts["ok"],
            "conflict": counts["conflict"],
            "undetermined": counts["undetermined"],
        },
        "baseline": baseline_body,
        "candidates": items,
    }
