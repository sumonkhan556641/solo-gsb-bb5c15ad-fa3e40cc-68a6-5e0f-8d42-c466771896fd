"""Vulnerability-avoiding resolution.

Given the same input as ``/resolve`` plus a list of local advisories (an id,
a package name and a PEP 440 *affected* specifier each), this module answers:
*resolve the roots while never selecting a version that any advisory marks as
affected.*

Semantics
---------
* Advisory package names are canonicalized with the same rules as the index;
  each affected specifier is a PEP 440 ``SpecifierSet``.  Every index version
  of the named package that falls inside the range is excluded **from this
  request's copy of the index** before solving; the supplied index itself is
  never mutated.
* Several advisories may hit the same package; exclusion is a **union** — a
  version is kept only when no advisory excludes it.
* The response reports, for every advisory in input order, the versions that
  advisory actually excluded from this index, plus the merged union.
* The remaining candidates go through the resolver's ordinary exhaustive
  depth-first backtracking against the full dependency constraints.  A locked
  version that an advisory excludes is simply absent from the reduced index,
  so it cannot be chosen again (the lock is reported as ``missing-version``);
  surviving locks keep their lock-first behaviour.
* No solution and hitting ``max_attempts`` are reported as distinct statuses
  (``conflict`` / ``undetermined``); hitting the search limit is not treated
  as unsatisfiable.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from packaging.version import Version

from .audit import Advisory, parse_advisories
from .resolver import (
    PackageIndex,
    ResolutionInputError,
    RootEntry,
    resolve,
)
from .serialize import conflict_summary


def _versions_matching(index: PackageIndex, package: str, specifier) -> list[Version]:
    """Index versions of ``package`` inside the advisory's affected range.

    ``prereleases=True`` mirrors the vulnerability audit: the concrete index
    versions are facts being filtered, so a pre-release inside the range is
    excluded regardless of ``allow_prereleases`` (it would not be a candidate
    anyway when pre-releases are disallowed).
    """
    hits = [
        version
        for version, _record in index.versions.get(package, [])
        if specifier.contains(version, prereleases=True)
    ]
    hits.sort(reverse=True)
    return hits


def _filtered_index(
    index: PackageIndex, excluded: dict[str, set[Version]]
) -> PackageIndex:
    """Copy of the index with the advisory hit versions removed.

    A package whose versions are all excluded stays in the index with an empty
    version list, so the solver reports "no versions left" rather than
    "package not found".
    """
    reduced = PackageIndex()
    for name, records in index.versions.items():
        blocked = excluded.get(name, ())
        reduced.versions[name] = [
            (version, record)
            for version, record in records
            if version not in blocked
        ]
    return reduced


def run_avoid_vulnerabilities(
    index: PackageIndex,
    entries: list[RootEntry],
    locks: dict[str, Version],
    advisories_raw: Iterable[Any],
    *,
    allow_prereleases: bool,
    marker_env: Optional[dict[str, str]],
    max_attempts: int,
) -> tuple[dict[str, Any], int]:
    """Exclude every advisory-hit version, solve once, render the JSON body.

    Returns ``(body, http_status)`` with ``http_status`` 200 for ``ok`` and
    409 for both ``conflict`` and ``undetermined``, mirroring ``/resolve``.
    """
    for item in advisories_raw:
        if not item.id:
            raise ResolutionInputError(
                "advisories: every advisory requires a non-empty 'id'"
            )
        if not item.package:
            raise ResolutionInputError(
                f"advisory {item.id!r}: 'package' must be a non-empty name"
            )
    advisories = parse_advisories(advisories_raw)

    # Per-advisory exclusions (input order) and their union per package.
    advisory_exclusions: list[dict[str, Any]] = []
    union: dict[str, set[Version]] = {}
    for advisory in advisories:
        hits = _versions_matching(index, advisory.package, advisory.affected)
        advisory_exclusions.append(
            {
                "advisory": {
                    "id": advisory.id,
                    "package": advisory.package,
                    "affected": advisory.affected_text,
                },
                "excluded_versions": [str(version) for version in hits],
            }
        )
        if hits:
            union.setdefault(advisory.package, set()).update(hits)

    excluded_versions = {
        package: [str(version) for version in sorted(versions, reverse=True)]
        for package, versions in sorted(union.items())
    }

    result = resolve(
        _filtered_index(index, union),
        [entry.dep for entry in entries],
        locks,
        allow_prereleases=allow_prereleases,
        marker_env=marker_env,
        max_attempts=max_attempts,
    )

    body: dict[str, Any] = {
        "status": "ok" if result.status == "ok" else (
            "undetermined" if result.status == "limit" else "conflict"
        ),
        "attempts": result.attempts,
        "allow_prereleases": allow_prereleases,
        "advisory_exclusions": advisory_exclusions,
        "excluded_versions": excluded_versions,
    }
    if result.status == "ok":
        body["resolved"] = result.chosen
        body["dependency_graph"] = result.edges
        body["locks"] = result.lock_notes
        return body, 200

    body["locks"] = result.lock_notes
    body["conflict"] = conflict_summary(result)
    if result.status == "limit":
        body["error"] = {
            "code": "search_limit_exceeded",
            "message": (
                f"resolution exceeded {max_attempts} candidate evaluations "
                "while avoiding the supplied advisories; a safe solution may "
                "still exist"
            ),
        }
    return body, 409
