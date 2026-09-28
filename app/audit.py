"""Vulnerability audit over a resolved dependency graph.

Consumes the ``resolved`` mapping and ``dependency_graph`` edges emitted by a
successful ``/resolve`` call together with a local list of advisories, and
reports which resolved versions fall inside an advisory's affected PEP 440
specifier.  For every hit, *all* shortest paths from ``<root>`` to the
affected package are enumerated.

The graph may contain cycles or diamond dependencies.  Paths are enumerated
over the BFS level DAG (only edges from distance ``k`` to ``k + 1``), so
cycles can never cause unbounded traversal and every reported path is simple.
Hits whose package cannot be reached from ``<root>`` are listed separately as
``orphaned``.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable, Protocol

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .resolver import ROOT, ResolutionInputError


class _AdvisoryLike(Protocol):
    id: str
    package: str
    affected: str


class _EdgeLike(Protocol):
    source: str
    source_version: str
    target: str
    target_version: str


@dataclass(frozen=True)
class Advisory:
    """One local advisory after validation."""

    id: str
    package: str  # canonical name
    affected_text: str
    affected: SpecifierSet


# ---------------------------------------------------------------------------
# Input validation (all failures -> ResolutionInputError -> HTTP 400)
# ---------------------------------------------------------------------------


def parse_resolved(raw: dict[str, str]) -> dict[str, Version]:
    """Validate the ``resolved`` mapping from a ``/resolve`` success body."""
    resolved: dict[str, Version] = {}
    for package, version in raw.items():
        canonical = canonicalize_name(package)
        if canonical == ROOT:
            raise ResolutionInputError(
                f"resolved: {ROOT!r} is reserved and cannot name a package"
            )
        if canonical in resolved:
            raise ResolutionInputError(
                f"resolved: package {package!r} duplicates {canonical!r} "
                "after name normalization"
            )
        try:
            resolved[canonical] = Version(version)
        except InvalidVersion as exc:
            raise ResolutionInputError(
                f"resolved: version for {package!r} is not a valid PEP 440 "
                f"version: {exc}"
            )
    return resolved


def parse_advisories(raw: Iterable[_AdvisoryLike]) -> list[Advisory]:
    """Validate local advisories; the ``affected`` field must be PEP 440."""
    advisories: list[Advisory] = []
    for item in raw:
        try:
            specifier = SpecifierSet(item.affected)
        except InvalidSpecifier as exc:
            raise ResolutionInputError(
                f"advisory {item.id!r}: invalid affected specifier "
                f"{item.affected!r}: {exc}"
            )
        advisories.append(
            Advisory(
                id=item.id,
                package=canonicalize_name(item.package),
                affected_text=item.affected,
                affected=specifier,
            )
        )
    return advisories


def parse_graph(
    raw_edges: Iterable[_EdgeLike], resolved: dict[str, Version]
) -> dict[str, list[str]]:
    """Validate edges against ``resolved`` and build a deduplicated adjacency.

    Every edge endpoint must be ``<root>`` or a package present in
    ``resolved`` (no dangling edges), and each edge's versions must match the
    resolved versions exactly (PEP 440 equality).
    """
    adjacency: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()

    for edge in raw_edges:
        source = canonicalize_name(edge.source)
        target = canonicalize_name(edge.target)
        origin = f"dependency_graph: edge {edge.source!r} -> {edge.target!r}"

        if target not in resolved:
            raise ResolutionInputError(
                f"{origin}: target {edge.target!r} is not present in resolved "
                "(dangling edge)"
            )
        _check_version(
            edge.target_version, resolved[target], f"{origin}: target_version"
        )

        if source == ROOT:
            if edge.source_version != "":
                raise ResolutionInputError(
                    f"{origin}: {ROOT!r} edges must carry an empty "
                    "source_version"
                )
        else:
            if source not in resolved:
                raise ResolutionInputError(
                    f"{origin}: source {edge.source!r} is not present in "
                    "resolved (dangling edge)"
                )
            _check_version(
                edge.source_version, resolved[source], f"{origin}: source_version"
            )

        key = (source, target)
        if key not in seen:
            seen.add(key)
            adjacency.setdefault(source, []).append(target)

    for node in adjacency:
        adjacency[node].sort()
    return adjacency


def _check_version(raw: str, expected: Version, origin: str) -> None:
    try:
        actual = Version(raw)
    except InvalidVersion as exc:
        raise ResolutionInputError(
            f"{origin} {raw!r} is not a valid PEP 440 version: {exc}"
        )
    if actual != expected:
        raise ResolutionInputError(
            f"{origin} {raw!r} is inconsistent with resolved version "
            f"{str(expected)!r}"
        )


# ---------------------------------------------------------------------------
# Shortest paths
# ---------------------------------------------------------------------------


def _bfs_distances(adjacency: dict[str, list[str]]) -> dict[str, int]:
    """Hop distance from ``<root>`` to every reachable node."""
    dist = {ROOT: 0}
    queue: deque[str] = deque([ROOT])
    while queue:
        node = queue.popleft()
        for nxt in adjacency.get(node, ()):
            if nxt not in dist:
                dist[nxt] = dist[node] + 1
                queue.append(nxt)
    return dist


def _shortest_paths(
    adjacency: dict[str, list[str]], dist: dict[str, int], target: str
) -> list[list[str]]:
    """Every shortest ``<root>`` -> ``target`` path, sorted by node sequence.

    Only edges from BFS level ``k`` to ``k + 1`` are followed, so the search
    space is a DAG even when the underlying graph has cycles: traversal
    always terminates and no path repeats a node.
    """
    if target not in dist:
        return []
    paths: list[list[str]] = []
    stack: list[tuple[str, list[str]]] = [(ROOT, [ROOT])]
    while stack:
        node, path = stack.pop()
        if node == target:
            paths.append(path)
            continue
        for nxt in adjacency.get(node, ()):
            if dist.get(nxt) == dist[node] + 1:
                stack.append((nxt, path + [nxt]))
    unique = {tuple(path) for path in paths}
    return [list(path) for path in sorted(unique)]


def _render_path(path: list[str], resolved: dict[str, Version]) -> list[dict[str, str]]:
    return [
        {"name": name, "version": "" if name == ROOT else str(resolved[name])}
        for name in path
    ]


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def run_audit(
    resolved_raw: dict[str, str],
    edges_raw: Iterable[_EdgeLike],
    advisories_raw: Iterable[_AdvisoryLike],
) -> dict[str, Any]:
    """Match advisories against resolved versions and locate each hit."""
    resolved = parse_resolved(resolved_raw)
    adjacency = parse_graph(edges_raw, resolved)
    advisories = parse_advisories(advisories_raw)
    dist = _bfs_distances(adjacency)

    matches: list[dict[str, Any]] = []
    orphaned: list[dict[str, Any]] = []
    for advisory in advisories:
        version = resolved.get(advisory.package)
        if version is None:
            continue  # package not installed -> advisory cannot apply
        # ``prereleases=True`` mirrors the resolver's constraint checks: the
        # resolved version is a concrete fact, so pre-release filtering of the
        # specifier itself must not hide a hit.
        if not advisory.affected.contains(version, prereleases=True):
            continue
        hit: dict[str, Any] = {
            "advisory": {
                "id": advisory.id,
                "package": advisory.package,
                "affected": advisory.affected_text,
            },
            "package": advisory.package,
            "version": str(version),
        }
        paths = _shortest_paths(adjacency, dist, advisory.package)
        if not paths:
            orphaned.append(hit)
        else:
            hit["paths"] = [_render_path(path, resolved) for path in paths]
            matches.append(hit)

    return {
        "status": "ok",
        "summary": {
            "advisories": len(advisories),
            "matches": len(matches),
            "orphaned": len(orphaned),
        },
        "matches": matches,
        "orphaned": orphaned,
    }
