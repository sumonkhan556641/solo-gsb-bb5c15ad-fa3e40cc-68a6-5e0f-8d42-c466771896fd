"""Minimal conflicting-root-set diagnosis.

Given the same input as ``/resolve``, this module determines *which* root
requirements are responsible when the full root set cannot be solved.

Algorithm
---------
Deletion-based minimization in a stable order (the original input order):

1. Solve the full input.  If it is satisfiable, no root conflicts.
2. Otherwise walk the root requirements in input order and temporarily
   delete each one in turn, re-solving the remaining set with the same
   PEP 440/508 rules, locks, marker environment and attempt budget.  When
   the remaining set is still unsatisfiable, the dropped entry is not
   needed for the conflict and stays deleted; when it becomes solvable,
   the entry is part of the conflict core and is restored.
3. The deletion pass is repeated until a full pass deletes nothing.  The
   fixpoint is required because the solver's pre-release filtering is not
   strictly monotone in the root set (an explicit pre-release pin on one
   root entry relaxes pre-release exclusion for the package as a whole),
   so the property "the rest is still unsatisfiable" is always established
   by an explicit re-solve rather than inferred.  With a monotone solver a
   single pass would suffice; the fixpoint keeps the guarantee exact for
   the real solver.

The result is a *minimal* conflicting root set: the set itself is
unsatisfiable, but deleting any single entry from it makes the remainder
solvable.  The set is found by actually solving subsets — never by reading
the conflict path of one backtracking branch, which shows only one of
possibly many independent ways the solve failed.

If the initial solve or any re-solve exhausts ``max_attempts``, the
diagnosis is reported as ``undetermined``: hitting the search limit is not
proof of unsatisfiability, so it must never be treated as a contradiction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from packaging.version import Version

from .resolver import (
    PackageIndex,
    RootEntry,
    resolve,
)


@dataclass
class Diagnosis:
    status: str  # ok | conflict | undetermined
    core: list[RootEntry]  # minimal conflicting entries; empty unless "conflict"
    attempts: int  # candidate evaluations summed over every re-solve
    limit_detail: Optional[str] = None  # explanation when undetermined


def diagnose_root_conflict(
    index: PackageIndex,
    entries: list[RootEntry],
    locks: dict[str, Version],
    *,
    allow_prereleases: bool = False,
    marker_env: Optional[dict[str, str]] = None,
    max_attempts: int = 100_000,
) -> Diagnosis:
    """Return a minimal conflicting root set, an empty set, or undetermined."""

    def solve_with(subset: list[RootEntry]):
        return resolve(
            index,
            [entry.dep for entry in subset],
            locks,
            allow_prereleases=allow_prereleases,
            marker_env=marker_env,
            max_attempts=max_attempts,
        )

    total_attempts = 0

    full = solve_with(entries)
    total_attempts += full.attempts
    if full.status == "ok":
        return Diagnosis("ok", [], total_attempts)
    if full.status == "limit":
        return Diagnosis(
            "undetermined",
            [],
            total_attempts,
            (
                f"initial solve exceeded {max_attempts} candidate evaluations; "
                "the full input may still be satisfiable"
            ),
        )

    # Deletion-based minimization until a full pass removes no entry.
    core = list(entries)
    while True:
        removed_any = False
        for entry in entries:
            if not any(entry is kept for kept in core):
                continue  # deleted in an earlier pass
            trial = [kept for kept in core if kept is not entry]
            result = solve_with(trial)
            total_attempts += result.attempts
            if result.status == "limit":
                return Diagnosis(
                    "undetermined",
                    [],
                    total_attempts,
                    (
                        f"re-solve without root requirement #{entry.index} "
                        f"({entry.requirement!r}) exceeded {max_attempts} "
                        "candidate evaluations; the input may still be "
                        "satisfiable"
                    ),
                )
            if result.status == "conflict":
                core = trial
                removed_any = True
        if not removed_any:
            break

    return Diagnosis("conflict", core, total_attempts)


def _entry_body(entry: RootEntry) -> dict[str, Any]:
    dep = entry.dep
    return {
        "index": entry.index,
        "package": dep.name,
        "requirement": entry.requirement,
        "specifier": dep.specifier_text,
        "marker": dep.marker_text,
    }


def run_root_conflict_diagnosis(
    index: PackageIndex,
    entries: list[RootEntry],
    locks: dict[str, Version],
    *,
    allow_prereleases: bool,
    marker_env: Optional[dict[str, str]],
    max_attempts: int,
) -> dict[str, Any]:
    """Run the diagnosis and render the public JSON response body."""
    diagnosis = diagnose_root_conflict(
        index,
        entries,
        locks,
        allow_prereleases=allow_prereleases,
        marker_env=marker_env,
        max_attempts=max_attempts,
    )

    body: dict[str, Any] = {
        "status": diagnosis.status,
        "attempts": diagnosis.attempts,
        "allow_prereleases": allow_prereleases,
    }
    if diagnosis.status == "ok":
        body["conflicting_roots"] = []
        return body
    if diagnosis.status == "conflict":
        body["conflicting_roots"] = [_entry_body(entry) for entry in diagnosis.core]
        return body
    # undetermined
    body["conflicting_roots"] = None
    body["error"] = {
        "code": "search_limit_exceeded",
        "message": diagnosis.limit_detail,
    }
    return body
