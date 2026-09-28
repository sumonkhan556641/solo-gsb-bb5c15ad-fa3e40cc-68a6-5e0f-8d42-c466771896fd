"""Serialization of solver results into the public JSON response shape."""

from __future__ import annotations

from typing import Any

from .resolver import (
    ROOT,
    CompositeConflict,
    Constraint,
    LeafConflict,
    SolveResult,
)


def _path_of(constraint: Constraint) -> list[dict[str, str]]:
    """Render the dependency path that introduced a constraint.

    ``path_nodes`` holds the hops leading to the requiring package; the
    requiring package itself is appended.  Root requirements render as a
    single ``<root>`` node.
    """
    path: list[dict[str, str]] = [{"name": ROOT, "version": ""}]
    for name, version in constraint.path_nodes:
        path.append({"name": name, "version": version})
    if constraint.source != ROOT:
        path.append({"name": constraint.source, "version": constraint.source_version or ""})
    return path


def _constraint_entry(constraint: Constraint, target: str) -> dict[str, Any]:
    spec = constraint.specifier_text or ""
    return {
        "requirement": f"{target}{spec}" if spec else target,
        "specifier": spec,
        "required_by": constraint.source,
        "required_by_version": constraint.source_version or "",
        "path": _path_of(constraint),
    }


def _all_constraints(leaf: LeafConflict) -> list[Constraint]:
    """Every constraint participating in the contradiction.

    ``rejected`` constraints are the ones that could not coexist with an
    already selected version; together with the active constraints they
    show the mutually-exclusive requirements.  Deduplicated because the
    same (source, version, specifier) can be observed on multiple branches.
    """
    combined = list(leaf.constraints) + list(leaf.rejected)
    unique: dict[tuple[str, str, str, tuple], Constraint] = {}
    for c in combined:
        key = (
            c.source,
            c.source_version or "",
            c.specifier_text,
            c.path_nodes,
        )
        unique.setdefault(key, c)
    return sorted(
        unique.values(),
        key=lambda c: (c.source, c.source_version or "", c.specifier_text),
    )


def _leaf_node(leaf: LeafConflict) -> dict[str, Any]:
    package = leaf.package
    return {
        "kind": "leaf",
        "package": package,
        "reason": leaf.reason,
        "message": leaf.detail,
        "available_versions": leaf.available,
        "attempted_versions": leaf.attempted,
        "active_constraints": [_constraint_entry(c, package) for c in _all_constraints(leaf)],
        "rejected_by": [_constraint_entry(c, package) for c in sorted(
            leaf.rejected,
            key=lambda c: (c.source, c.source_version or "", c.specifier_text),
        )],
    }


def _composite_node(
    composite: CompositeConflict, depth: int, seen: set[str]
) -> dict[str, Any]:
    package = composite.package
    return {
        "kind": "composite",
        "package": package,
        "reason": composite.reason,
        "message": (
            f"every eligible version of {package} failed: "
            + (", ".join(composite.attempted) if composite.attempted else "none tried")
        ),
        "attempted_versions": composite.attempted,
        "available_versions": composite.available,
        "active_constraints": [
            _constraint_entry(c, package)
            for c in sorted(
                composite.constraints,
                key=lambda c: (c.source, c.source_version or "", c.specifier_text),
            )
        ],
        "failed_branches": [
            serialize_conflict(child, depth + 1, seen) for child in composite.children
        ],
    }


def serialize_conflict(conflict: Any, depth: int = 0, seen: set[str] | None = None) -> dict[str, Any]:
    if seen is None:
        seen = set()
    if isinstance(conflict, LeafConflict):
        node = _leaf_node(conflict)
    else:
        node = _composite_node(conflict, depth, seen)
    return node


def _collect_leaves(conflict: Any, out: list[LeafConflict], seen: set[tuple[str, str]]) -> None:
    signature: tuple[str, str]
    if isinstance(conflict, LeafConflict):
        signature = (
            conflict.package,
            "|".join(
                sorted(
                    f"{c.source}:{c.source_version or ''}:{c.specifier_text}"
                    for c in conflict.constraints + conflict.rejected
                )
            ),
        )
        if signature not in seen:
            seen.add(signature)
            out.append(conflict)
        return
    for child in conflict.children:
        _collect_leaves(child, out, seen)


def conflict_summary(result: SolveResult) -> dict[str, Any]:
    assert result.conflict is not None
    leaves: list[LeafConflict] = []
    _collect_leaves(result.conflict, leaves, set())
    return {
        "tree": serialize_conflict(result.conflict),
        "terminal_conflicts": [
            {
                "package": leaf.package,
                "reason": leaf.reason,
                "message": leaf.detail,
                "available_versions": leaf.available,
                "attempted_versions": leaf.attempted,
                "active_constraints": [
                    _constraint_entry(c, leaf.package)
                    for c in _all_constraints(leaf)
                ],
                "rejected_by": [
                    _constraint_entry(c, leaf.package)
                    for c in sorted(
                        leaf.rejected,
                        key=lambda c: (c.source, c.source_version or "", c.specifier_text),
                    )
                ],
            }
            for leaf in sorted(leaves, key=lambda l: l.package)
        ],
    }
