"""SHA-256 fingerprints of dependency closures over a resolved graph.

Consumes the ``resolved`` mapping and ``dependency_graph`` edges emitted by a
successful ``/resolve`` call and computes one content fingerprint for
``<root>`` and one for every resolved package: the SHA-256 over a canonical
serialization of that node's *full reachable dependency closure*.

Definitions
-----------
The closure of a node is the set of nodes reachable from it (itself
included) together with every deduplicated directed edge leaving those
nodes.  Nodes in cycles or diamonds appear exactly once — the closure is a
set, so shared or cyclic structure is never double-counted and traversal
always terminates.

Each closure is serialized as canonical JSON — nodes as
``[canonical_name, pep440_version]`` pairs sorted by name (``<root>``
carries an empty version), edges as ``[source, target]`` pairs sorted
lexicographically — and hashed with SHA-256.  Because every list is sorted
before hashing, the insertion order of ``resolved`` and the order (or
duplication) of the input edges cannot influence the fingerprint, while any
version or edge change inside a closure changes the fingerprints of exactly
the nodes that can reach it.

Validation reuses the audit pipeline verbatim: ``resolved`` versions are
PEP 440-checked and every graph endpoint must be ``<root>`` or a package
present in ``resolved`` with a matching version (no dangling edges).
Packages present in ``resolved`` but unreachable from ``<root>`` still
receive a fingerprint over their own closure and are additionally listed
under ``unreachable``.
"""

from __future__ import annotations

import hashlib
import json
from collections import deque
from typing import Any, Iterable

from .audit import parse_graph, parse_resolved
from .resolver import ROOT


# ---------------------------------------------------------------------------
# Closures
# ---------------------------------------------------------------------------


def _reachable_nodes(adjacency: dict[str, list[str]], start: str) -> set[str]:
    """Every node reachable from ``start`` (itself included).

    Iterative BFS, so arbitrarily deep chains cannot exhaust the call stack;
    the visited set makes cycles and diamonds terminate immediately.
    """
    seen = {start}
    queue: deque[str] = deque([start])
    while queue:
        node = queue.popleft()
        for nxt in adjacency.get(node, ()):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def _closure_fingerprint(
    adjacency: dict[str, list[str]],
    resolved: dict[str, Any],
    start: str,
) -> str:
    """SHA-256 over the canonical serialization of ``start``'s closure.

    The closure's nodes and edges are sorted before hashing, so the result
    depends only on the closure's content — never on input ordering — and
    each node/edge contributes exactly once.
    """
    nodes = _reachable_nodes(adjacency, start)
    node_entries = sorted(
        (name, "" if name == ROOT else str(resolved[name])) for name in nodes
    )
    # Edges leaving a closure node always land inside the closure, so this
    # is exactly the edge set of the reachable subgraph.  ``parse_graph``
    # already deduplicated the adjacency.
    edge_entries = sorted(
        (source, target)
        for source in nodes
        for target in adjacency.get(source, ())
    )
    blob = json.dumps(
        {"nodes": node_entries, "edges": edge_entries},
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def run_graph_fingerprints(
    resolved_raw: dict[str, str],
    edges_raw: Iterable[Any],
) -> dict[str, Any]:
    """Fingerprint the dependency closure of ``<root>`` and every package."""
    resolved = parse_resolved(resolved_raw)
    adjacency = parse_graph(edges_raw, resolved)

    root_closure = _reachable_nodes(adjacency, ROOT)
    unreachable = sorted(set(resolved) - root_closure)

    packages = [
        {
            "package": name,
            "version": str(resolved[name]),
            "fingerprint": _closure_fingerprint(adjacency, resolved, name),
        }
        for name in sorted(resolved)
    ]

    return {
        "status": "ok",
        "summary": {
            "packages": len(resolved),
            "reachable": len(root_closure) - 1,  # exclude <root> itself
            "unreachable": len(unreachable),
        },
        "root_fingerprint": _closure_fingerprint(adjacency, resolved, ROOT),
        "packages": packages,
        "unreachable": [
            {"package": name, "version": str(resolved[name])}
            for name in unreachable
        ],
    }
