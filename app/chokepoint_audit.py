"""Dependency chokepoint audit over a resolved dependency graph.

Consumes the ``resolved`` mapping and ``dependency_graph`` edges emitted by a
successful ``/resolve`` call and reports the *mandatory* dependencies of every
package reachable from ``<root>``.

Definitions
-----------
A package ``d`` *dominates* a package ``v`` when every directed path from
``<root>`` to ``v`` passes through ``d``: there is no path that can bypass it.
Such a ``d`` is a mandatory (chokepoint) dependency of ``v``.  Diamond
dependencies are therefore not chokepoints (the shared target has two parallel
routes), while a package that gates all traffic into a dependency cluster is.

Cycles do not need special handling structurally: domination is defined over
all paths and is computed with the classic iterative data-flow fixpoint
(intersection of dominator sets over predecessors), which is correct on
general directed graphs including SCCs and self loops.

For every chokepoint the audit also aggregates the packages it *exclusively*
dominates: the descendant set of that node in the dominator tree, i.e. every
package that cannot be reached from ``<root>`` without passing through the
chokepoint, excluding the chokepoint itself.  Packages in ``resolved`` that no
edge makes reachable from ``<root>`` participate in neither computation and
are listed separately.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Iterable

from .audit import parse_graph, parse_resolved
from .resolver import ROOT


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------


def _bfs_order(adjacency: dict[str, list[str]]) -> tuple[list[str], set[str]]:
    """Breadth-first traversal from ``<root>`` over sorted adjacency lists.

    Returns both the discovery order (a deterministic processing order) and
    the set of reachable nodes.  Sorted adjacency (guaranteed by
    ``parse_graph``) makes the order independent of the input edge order.
    """
    order: list[str] = [ROOT]
    reachable = {ROOT}
    queue: deque[str] = deque([ROOT])
    while queue:
        node = queue.popleft()
        for nxt in adjacency.get(node, ()):
            if nxt not in reachable:
                reachable.add(nxt)
                order.append(nxt)
                queue.append(nxt)
    return order, reachable


# ---------------------------------------------------------------------------
# Dominators (iterative data-flow fixpoint, valid on cyclic directed graphs)
# ---------------------------------------------------------------------------


def _dominators(
    order: list[str],
    reachable: set[str],
    adjacency: dict[str, list[str]],
) -> dict[str, set[str]]:
    """Dom sets for the subgraph reachable from ``<root>``.

    ``dom[v]`` contains exactly the nodes that lie on *every* ``<root>`` ->
    ``v`` path.  Predecessors are restricted to the reachable subgraph: an
    edge from an unreachable source can never be part of a root-to-node path
    and must not widen the intersection.
    """
    preds: dict[str, list[str]] = {node: [] for node in reachable}
    for source in reachable:
        for target in adjacency.get(source, ()):
            if target in reachable:
                preds[target].append(source)

    dom: dict[str, set[str]] = {ROOT: {ROOT}}
    top = set(reachable)
    for node in order[1:]:
        # Every non-root reachable node has at least its BFS parent as a
        # reachable predecessor, so the intersection below is always defined.
        dom[node] = set(top)

    changed = True
    while changed:
        changed = False
        for node in order[1:]:
            incoming = [dom[pred] for pred in preds[node]]
            updated = {node} | set.intersection(*incoming)
            if updated != dom[node]:
                dom[node] = updated
                changed = True
    return dom


def _immediate_dominators(
    dom: dict[str, set[str]], order: list[str]
) -> dict[str, str]:
    """Closest strict dominator of every node except ``<root>``.

    The strict dominators of a node are totally ordered by inclusion (they
    form the ancestor chain in the dominator tree); the one with the largest
    dominator set is the immediate dominator.  The name tie-break is
    defensive only and keeps the result deterministic regardless.
    """
    idom: dict[str, str] = {}
    for node in order[1:]:
        strict = [candidate for candidate in dom[node] if candidate != node]
        idom[node] = max(strict, key=lambda candidate: (len(dom[candidate]), candidate))
    return idom


def _dominator_tree_descendants(
    order: list[str], idom: dict[str, str]
) -> dict[str, set[str]]:
    """Exclusive dominatee sets: dominator-tree descendants of each node.

    Built with an iterative post-order traversal so adversarially deep
    dependency chains cannot exhaust the Python call stack.
    """
    children: dict[str, list[str]] = {node: [] for node in order}
    for node in order[1:]:
        children[idom[node]].append(node)
    for kids in children.values():
        kids.sort()

    descendants: dict[str, set[str]] = {}
    stack: list[tuple[str, bool]] = [(ROOT, False)]
    while stack:
        node, processed = stack.pop()
        if not processed:
            stack.append((node, True))
            for child in reversed(children[node]):
                stack.append((child, False))
            continue
        owned: set[str] = set()
        for child in children[node]:
            owned.add(child)
            owned |= descendants[child]
        descendants[node] = owned
    return descendants


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def run_dependency_chokepoints(
    resolved_raw: dict[str, str],
    edges_raw: Iterable[Any],
) -> dict[str, Any]:
    """Find mandatory dependencies and their exclusive downstream packages."""
    resolved = parse_resolved(resolved_raw)
    adjacency = parse_graph(edges_raw, resolved)

    order, reachable = _bfs_order(adjacency)
    reachable_packages = [node for node in order if node != ROOT]
    unreachable = sorted(set(resolved) - reachable)

    dom = _dominators(order, reachable, adjacency)
    idom = _immediate_dominators(dom, order)
    descendants = _dominator_tree_descendants(order, idom)

    packages: list[dict[str, Any]] = []
    for name in sorted(reachable_packages):
        mandatory = sorted(dom[name] - {name, ROOT})
        packages.append(
            {
                "package": name,
                "version": str(resolved[name]),
                "required_dependencies": mandatory,
            }
        )

    chokepoints: list[dict[str, Any]] = []
    for name in reachable_packages:
        dominated = descendants[name]
        if dominated:
            chokepoints.append(
                {
                    "package": name,
                    "version": str(resolved[name]),
                    "exclusive_count": len(dominated),
                    "exclusive_dominees": sorted(dominated),
                }
            )
    # Biggest gates first; ties and equal-size gates break by package name.
    chokepoints.sort(key=lambda entry: (-entry["exclusive_count"], entry["package"]))

    return {
        "status": "ok",
        "summary": {
            "packages": len(resolved),
            "reachable": len(reachable_packages),
            "unreachable": len(unreachable),
            "chokepoints": len(chokepoints),
        },
        "packages": packages,
        "chokepoints": chokepoints,
        "unreachable": [
            {"package": name, "version": str(resolved[name])} for name in unreachable
        ],
    }
