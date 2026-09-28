"""Deterministic rebuild planning over a resolved dependency graph.

Consumes the ``resolved`` mapping and ``dependency_graph`` edges emitted by a
successful ``/resolve`` call together with a list of locally changed package
names, and produces a deterministic plan for rebuilding the affected local
packages.

Pipeline
--------
1. Validation reuses the audit pipeline verbatim: ``resolved`` versions are
   PEP 440-checked and every graph endpoint must be ``<root>`` or a package
   present in ``resolved`` with a matching version (no dangling edges).
2. Reverse-dependency propagation: starting from the changed packages that
   are actually installed, reverse edges (dependent -> dependency direction)
   are walked to collect every package that transitively depends on a change.
3. Strongly connected components collapse dependency cycles into groups that
   must be (re)built as one batch.  SCCs are found by an iterative Tarjan
   pass whose roots and adjacency are sorted, so components, component order
   and membership are stable for identical input.
4. Stages follow "dependencies before dependents": starting at the changed
   seed groups (stage 0), a group is placed one stage after the latest group
   that must precede it.  Groups inside one stage share no ordering edge and
   can be built in parallel.

For every affected package the response records the shortest reverse path to
the *nearest* changed package; ties are broken by lexicographically smallest
node sequence, so the reported path is stable.  Changed names that do not
name an installed (resolved) package are listed separately as
``uninstalled`` and never participate in propagation.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

from packaging.utils import canonicalize_name

from .audit import parse_graph, parse_resolved
from .resolver import ROOT, ResolutionInputError


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def parse_changed(raw: Iterable[str]) -> list[str]:
    """Normalize the changed package name list.

    Returns canonical names, sorted and deduplicated.  Empty/blank names and
    the reserved ``<root>`` name are rejected; names collapsing onto the same
    canonical package are merged.
    """
    errors: list[str] = []
    canonical: set[str] = set()
    for index, name in enumerate(raw):
        origin = f"changed[{index}]"
        if not name.strip():
            errors.append(f"{origin}: package name must not be empty")
            continue
        normalized = canonicalize_name(name)
        if normalized == ROOT:
            errors.append(f"{origin}: {ROOT!r} is reserved and cannot name a package")
            continue
        canonical.add(normalized)
    if errors:
        raise ResolutionInputError("; ".join(errors))
    return sorted(canonical)


# ---------------------------------------------------------------------------
# Reverse graph
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _GraphEdge:
    source: str
    source_version: str
    target: str
    target_version: str


def _edge_view(raw: Any):
    """Accept pydantic edge models (API path) or plain dicts (direct calls)."""
    if isinstance(raw, dict):
        return _GraphEdge(
            source=raw["source"],
            source_version=raw["source_version"],
            target=raw["target"],
            target_version=raw["target_version"],
        )
    return raw


def _reverse_adjacency(
    adjacency: dict[str, list[str]], nodes: Iterable[str]
) -> dict[str, list[str]]:
    """Build ``dependency -> [dependents]`` lists, ``<root>`` excluded.

    The forward graph lists are already sorted and deduplicated (audit
    pipeline); reversing preserves that determinism, and every node key is
    initialized so isolated packages still participate.
    """
    reverse: dict[str, list[str]] = {node: [] for node in nodes if node != ROOT}
    for source, targets in adjacency.items():
        if source == ROOT:
            continue
        for target in targets:
            reverse[target].append(source)
    for dependents in reverse.values():
        dependents.sort()
    return reverse


# ---------------------------------------------------------------------------
# Affected set and shortest reverse paths
# ---------------------------------------------------------------------------


def _affected_distances(
    reverse: dict[str, list[str]], seeds: list[str]
) -> dict[str, int]:
    """Multi-source BFS over reverse edges.

    Distance is the hop count from the node to the *nearest* changed package
    (0 for the changed packages themselves).
    """
    dist: dict[str, int] = {seed: 0 for seed in seeds}
    queue: deque[str] = deque(seeds)
    while queue:
        node = queue.popleft()
        for dependent in reverse.get(node, ()):
            if dependent not in dist:
                dist[dependent] = dist[node] + 1
                queue.append(dependent)
    return dist


def _shortest_path_to_changed(
    node: str, dist: dict[str, int], forward: dict[str, list[str]]
) -> list[str]:
    """Shortest ``node`` -> changed-package reverse path.

    Followed dependency hop by dependency hop (forward edges) toward the
    changed package: at each hop the lexicographically smallest dependency
    at the next (smaller) reverse-distance level is chosen, yielding the
    lexicographically smallest node sequence among all shortest paths.
    """
    path = [node]
    current = node
    while dist[current] > 0:
        nxt = min(dep for dep in forward[current] if dist.get(dep) == dist[current] - 1)
        path.append(nxt)
        current = nxt
    return path


# ---------------------------------------------------------------------------
# Strongly connected components (iterative, deterministic Tarjan)
# ---------------------------------------------------------------------------


def _tarjan_scc(nodes: list[str], edges: dict[str, list[str]]) -> list[list[str]]:
    """SCCs of the induced subgraph, in deterministic dependency-first order.

    Iterative Tarjan so adversarially deep dependency chains cannot exhaust
    the Python call stack.  Roots are visited in sorted order and adjacency
    lists are sorted; components are emitted with dependencies before their
    dependents (standard Tarjan output order).
    """
    index_of: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = 0

    # Frames: (node, adjacency iterator).  Iterators over sorted lists keep
    # exploration order fully deterministic.
    for root in nodes:
        if root in index_of:
            continue
        work: list[tuple[str, Any]] = [(root, iter(edges.get(root, ())))]
        index_of[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)

        while work:
            v, it = work[-1]
            advanced = False
            for w in it:
                if w not in index_of:
                    index_of[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on_stack.add(w)
                    work.append((w, iter(edges.get(w, ()))))
                    advanced = True
                    break
                if w in on_stack:
                    low[v] = min(low[v], index_of[w])
            if advanced:
                continue

            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
            if low[v] == index_of[v]:
                component: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    component.append(w)
                    if w == v:
                        break
                components.append(sorted(component))
    return components


# ---------------------------------------------------------------------------
# Rebuild plan
# ---------------------------------------------------------------------------


def run_rebuild_plan(
    resolved_raw: dict[str, str],
    edges_raw: Iterable[Any],
    changed_raw: Iterable[str],
) -> dict[str, Any]:
    """Build the deterministic rebuild plan (see module docstring)."""
    resolved = parse_resolved(resolved_raw)
    adjacency = parse_graph(
        (_edge_view(edge) for edge in edges_raw), resolved
    )

    changed_all = parse_changed(changed_raw)
    installed = [name for name in changed_all if name in resolved]
    uninstalled = [name for name in changed_all if name not in resolved]

    forward = {node: list(adjacency.get(node, ())) for node in resolved}
    reverse = _reverse_adjacency(adjacency, resolved)

    dist = _affected_distances(reverse, installed)
    affected = sorted(dist)

    # Restrict the SCC problem to the affected induced subgraph: packages
    # outside the reverse-propagation closure never need rebuilding.
    affected_set = set(affected)
    induced_forward = {
        node: [t for t in forward[node] if t in affected_set] for node in affected
    }
    components = _tarjan_scc(affected, induced_forward)

    component_of: dict[str, int] = {}
    for cid, members in enumerate(components):
        for member in members:
            component_of[member] = cid

    # Condensation DAG edges dependency-group -> dependent-group.  Tarjan
    # emits dependencies before dependents, so component ids already follow
    # that order; the *stage* labels are the longest condensation path from
    # the changed seed groups outward, because seeds may occur anywhere: a
    # changed package depending on another changed package rebuilds later.
    seed_components = {
        cid
        for cid, members in enumerate(components)
        if any(dist[n] == 0 for n in members)
    }
    cond_dependents: dict[int, set[int]] = {
        cid: set() for cid in range(len(components))
    }
    for node in affected:
        src = component_of[node]
        for target in induced_forward[node]:
            dst = component_of[target]
            if src != dst:
                cond_dependents[dst].add(src)

    # Multi-source longest-path relaxation on the condensation DAG: every
    # group rebuilds one stage after the latest group that must precede it.
    # Each affected SCC reaches some seed SCC by construction of the
    # affected closure, so every component receives a stage.
    stages_of = [-1] * len(components)
    for cid in seed_components:
        stages_of[cid] = 0
    pending: deque[int] = deque(seed_components)
    while pending:
        cid = pending.popleft()
        for dependent in cond_dependents[cid]:
            candidate = stages_of[cid] + 1
            if candidate > stages_of[dependent]:
                stages_of[dependent] = candidate
                pending.append(dependent)

    if components:
        assert all(stage >= 0 for stage in stages_of)

    groups: list[dict[str, Any]] = []
    for cid, members in enumerate(components):
        groups.append(
            {
                "id": cid,
                "packages": list(members),
                "changed": [name for name in members if dist[name] == 0],
            }
        )

    stage_count = max((stage + 1 for stage in stages_of), default=0)
    stages: list[list[int]] = [[] for _ in range(stage_count)]
    for cid, stage in enumerate(stages_of):
        stages[stage].append(cid)

    rebuild_paths: list[dict[str, Any]] = []
    for node in sorted(dist, key=lambda n: (dist[n], n)):
        chain = _shortest_path_to_changed(node, dist, induced_forward)
        rebuild_paths.append(
            {
                "package": node,
                "distance": dist[node],
                "path": [
                    {"name": name, "version": str(resolved[name])} for name in chain
                ],
            }
        )

    return {
        "status": "ok",
        "summary": {
            "changed": len(installed),
            "uninstalled": len(uninstalled),
            "affected": len(affected),
            "groups": len(groups),
            "stages": stage_count,
        },
        "changed": installed,
        "uninstalled": uninstalled,
        "affected": affected,
        "groups": groups,
        "stages": stages,
        "rebuild_paths": rebuild_paths,
    }
