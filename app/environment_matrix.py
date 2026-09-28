"""Per-environment resolution matrix.

Given the same package index, root requirements, locks and attempt budget
as ``/resolve`` plus 2-8 uniquely named marker environments, this module
resolves the full dependency closure independently under each environment's
PEP 508 marker environment and compares the outcomes.

Semantics
---------
* Every environment gets its own independent solve with the full
  ``max_attempts`` budget: one environment exhausting the search limit or
  conflicting never affects the others.
* Each environment keeps its own ``ok`` / ``conflict`` / ``limit`` result
  and ``attempts`` count, rendered exactly like the synchronous ``/resolve``
  body for that outcome.
* The version matrix is aggregated over *successful* environments only.
  For every package resolved in at least one of them, each environment
  column holds either the concrete resolved version or JSON ``null``
  ("absent" — the package was not part of that environment's solution).
* ``differences`` lists the packages whose version vector is not uniform
  across the successful environments — a version mismatch and a
  presence/absence mismatch both count.  With fewer than two successful
  environments no comparison is possible and ``differences`` is empty.
* Environments appear in input order everywhere; packages are sorted by
  canonical name.  Identical input always produces identical output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from packaging.version import Version

from .resolver import (
    PackageIndex,
    ResolutionInputError,
    RootEntry,
    resolve,
)
from .serialize import conflict_summary


@dataclass(frozen=True)
class EnvironmentSpec:
    """One named marker environment to resolve under."""

    name: str
    marker_env: Optional[dict[str, str]]


def parse_environments(raw: Any) -> list[EnvironmentSpec]:
    """Normalize the environment list and reject duplicate names.

    Count (2-8) and field shape are enforced by the request model; the
    semantic uniqueness rule lives here so violations map to the same 400
    ``invalid_request`` shape as the other semantic input errors.  Accepts
    pydantic models (API path) or plain dicts (direct calls).
    """
    specs: list[EnvironmentSpec] = []
    seen: set[str] = set()
    duplicates: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            name, marker_env = item["name"], item.get("marker_env")
        else:
            name, marker_env = item.name, item.marker_env
        if name in seen and name not in duplicates:
            duplicates.append(name)
        seen.add(name)
        specs.append(EnvironmentSpec(name=name, marker_env=marker_env))
    if duplicates:
        raise ResolutionInputError(
            "environments: duplicate name(s): "
            + ", ".join(repr(name) for name in duplicates)
        )
    return specs


def _environment_body(
    spec: EnvironmentSpec, result: Any, max_attempts: int
) -> dict[str, Any]:
    """Render one environment's outcome like the ``/resolve`` body."""
    body: dict[str, Any] = {
        "name": spec.name,
        "status": result.status,
        "attempts": result.attempts,
    }
    if result.status == "ok":
        body["resolved"] = result.chosen
        body["dependency_graph"] = result.edges
        body["locks"] = result.lock_notes
        return body
    body["locks"] = result.lock_notes
    body["conflict"] = conflict_summary(result)
    if result.status == "limit":
        body["error"] = {
            "code": "search_limit_exceeded",
            "message": f"resolution exceeded {max_attempts} candidate evaluations",
        }
    return body


def _version_matrix(solutions: list[tuple[str, dict[str, str]]]) -> dict[str, Any]:
    """Aggregate the per-package version matrix over successful environments."""
    names = [name for name, _chosen in solutions]
    packages = sorted({pkg for _name, chosen in solutions for pkg in chosen})
    rows: list[dict[str, Any]] = []
    differences: list[str] = []
    for pkg in packages:
        # Insertion order follows the successful environments' input order;
        # a missing key would be ambiguous, so absence is an explicit null.
        versions = {name: chosen.get(pkg) for name, chosen in solutions}
        rows.append({"package": pkg, "versions": versions})
        if len(solutions) >= 2 and len(set(versions.values())) > 1:
            differences.append(pkg)
    return {
        "environments": names,
        "packages": rows,
        "differences": differences,
    }


def run_environment_matrix(
    index: PackageIndex,
    entries: list[RootEntry],
    locks: dict[str, Version],
    *,
    allow_prereleases: bool,
    max_attempts: int,
    environments: list[EnvironmentSpec],
) -> dict[str, Any]:
    """Resolve under every environment and render the public JSON body."""
    roots = [entry.dep for entry in entries]
    bodies: list[dict[str, Any]] = []
    solutions: list[tuple[str, dict[str, str]]] = []
    counts = {"ok": 0, "conflict": 0, "limit": 0}
    for spec in environments:
        result = resolve(
            index,
            roots,
            locks,
            allow_prereleases=allow_prereleases,
            marker_env=spec.marker_env,
            max_attempts=max_attempts,
        )
        bodies.append(_environment_body(spec, result, max_attempts))
        counts[result.status] += 1
        if result.status == "ok":
            solutions.append((spec.name, result.chosen))

    return {
        "status": "ok",
        "allow_prereleases": allow_prereleases,
        "summary": {
            "environments": len(environments),
            "ok": counts["ok"],
            "conflict": counts["conflict"],
            "limit": counts["limit"],
        },
        "environments": bodies,
        "matrix": _version_matrix(solutions),
    }
