"""Local license policy audit over resolved dependencies.

Consumes the ``resolved`` mapping emitted by a successful ``/resolve`` call
together with a package -> SPDX license expression mapping and a local policy
(``allowed`` / ``denied`` identifier sets), and decides a compliance status
for every resolved package.

SPDX expressions are parsed with the ``license-expression`` library, which
handles parentheses, ``AND``, ``OR`` and ``WITH``.  A ``WITH`` node is judged
like ``AND`` over its two operands: the license and the exception are
evaluated as separate identifiers.

Policy semantics
----------------
* A single identifier is a ``violation`` when it appears in ``denied``
  (denied wins if an identifier is listed in both sets), ``compliant`` when
  it appears in ``allowed``, and ``unknown`` otherwise.
* ``AND`` is a ``violation`` as soon as one operand is a violation, else
  ``unknown`` as soon as one operand is unknown, else ``compliant``.
* ``OR`` is ``compliant`` as soon as one operand is compliant, else
  ``unknown`` as soon as one operand is unknown, else ``violation``.
* A resolved package without an entry in the mapping is reported as
  ``missing``.

Every package also reports the *decisive* identifiers: the identifiers whose
individual status determined the package status (e.g. the denied identifiers
behind a violation, or the allowed identifiers behind a compliant ``OR``).

All parsing/validation failures raise :class:`ResolutionInputError` (mapped
to HTTP 400) before any package is evaluated, so an invalid expression never
produces partial results.
"""

from __future__ import annotations

from typing import Any, Optional

from license_expression import (
    OR,
    ExpressionError,
    LicenseSymbol,
    LicenseWithExceptionSymbol,
    get_spdx_licensing,
)
from packaging.utils import canonicalize_name
from packaging.version import Version

from .audit import parse_resolved
from .resolver import ROOT, ResolutionInputError

# Package statuses, in report order.
VIOLATION = "violation"
COMPLIANT = "compliant"
UNKNOWN = "unknown"
MISSING = "missing"

STATUS_ORDER = (VIOLATION, COMPLIANT, UNKNOWN, MISSING)

# SPDX-aware parser: known identifiers are normalized to their canonical
# key ("mit" -> "MIT"); unknown identifiers still parse and simply stay
# unmatched by the policy sets (i.e. they evaluate to "unknown").  Built
# once: the symbol table is immutable after construction.
_LICENSING = get_spdx_licensing()


# ---------------------------------------------------------------------------
# Input validation (all failures -> ResolutionInputError -> HTTP 400)
# ---------------------------------------------------------------------------


def _parse_expression(text: str, origin: str):
    """Parse one SPDX expression; anything unparseable is a 400."""
    if not text.strip():
        raise ResolutionInputError(f"{origin}: SPDX expression must not be empty")
    try:
        expression = _LICENSING.parse(text)
    except ExpressionError as exc:
        raise ResolutionInputError(
            f"{origin}: invalid SPDX expression {text!r}: {exc}"
        )
    if expression is None:  # defensive: blank input is rejected above
        raise ResolutionInputError(f"{origin}: SPDX expression must not be empty")
    return expression


def parse_license_mapping(raw: dict[str, str]) -> dict[str, tuple[Any, str]]:
    """Validate the package -> SPDX expression mapping.

    Returns canonical package name -> (parsed expression, normalized text).
    All invalid expressions are collected and reported together; nothing is
    evaluated until every expression parses.
    """
    expressions: dict[str, tuple[Any, str]] = {}
    errors: list[str] = []
    for package, text in raw.items():
        canonical = canonicalize_name(package)
        origin = f"licenses: package {package!r}"
        if canonical == ROOT:
            errors.append(f"{origin}: {ROOT!r} is reserved and cannot name a package")
            continue
        if canonical in expressions:
            errors.append(
                f"{origin}: duplicates {canonical!r} after name normalization"
            )
            continue
        try:
            expression = _parse_expression(text, origin)
        except ResolutionInputError as exc:
            errors.append(str(exc))
            continue
        expressions[canonical] = (expression, str(expression))
    if errors:
        raise ResolutionInputError("; ".join(errors))
    return expressions


def parse_identifier_set(raw: list[str], field: str) -> frozenset[str]:
    """Normalize an ``allowed``/``denied`` list to canonical identifier keys.

    Each entry must parse as a single SPDX identifier (not an expression),
    so both sides of a comparison go through the same normalization.
    """
    identifiers: set[str] = set()
    errors: list[str] = []
    for entry in raw:
        origin = f"{field}: entry {entry!r}"
        try:
            expression = _parse_expression(entry, origin)
        except ResolutionInputError as exc:
            errors.append(str(exc))
            continue
        if not isinstance(expression, LicenseSymbol):
            errors.append(
                f"{origin}: {entry!r} must be a single SPDX identifier, "
                "not an expression"
            )
            continue
        identifiers.add(str(expression))
    if errors:
        raise ResolutionInputError("; ".join(errors))
    return frozenset(identifiers)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _children(node: Any) -> tuple[Any, ...]:
    """Operands of a compound node; ``WITH`` unfolds to license + exception."""
    if isinstance(node, LicenseWithExceptionSymbol):
        return (node.license_symbol, node.exception_symbol)
    return tuple(node.args)


def _combine(
    kind: str, child_results: list[tuple[str, frozenset[str]]]
) -> tuple[str, frozenset[str]]:
    """Combine operand results for an ``and``/``or`` node.

    The decisive identifiers of the node are the union of the decisive
    identifiers of the operands whose status equals the node's status.
    """
    statuses = [status for status, _ in child_results]
    if kind == "and":
        if VIOLATION in statuses:
            status = VIOLATION
        elif UNKNOWN in statuses:
            status = UNKNOWN
        else:
            status = COMPLIANT
    else:  # "or"
        if COMPLIANT in statuses:
            status = COMPLIANT
        elif UNKNOWN in statuses:
            status = UNKNOWN
        else:
            status = VIOLATION
    decisive = frozenset(
        identifier
        for child_status, child_decisive in child_results
        if child_status == status
        for identifier in child_decisive
    )
    return status, decisive


def evaluate(
    expression: Any, allowed: frozenset[str], denied: frozenset[str]
) -> tuple[str, frozenset[str]]:
    """Evaluate a parsed expression against the policy sets.

    Iterative post-order traversal (explicit stack), so adversarially deep
    nesting cannot exhaust the Python call stack.
    """
    status_of: dict[int, str] = {}
    decisive_of: dict[int, frozenset[str]] = {}
    stack: list[tuple[Any, bool]] = [(expression, False)]
    while stack:
        node, processed = stack.pop()
        if isinstance(node, LicenseSymbol):
            identifier = str(node)
            if identifier in denied:
                status = VIOLATION
            elif identifier in allowed:
                status = COMPLIANT
            else:
                status = UNKNOWN
            status_of[id(node)] = status
            decisive_of[id(node)] = frozenset((identifier,))
            continue
        if not processed:
            stack.append((node, True))
            for child in _children(node):
                stack.append((child, False))
            continue
        children = _children(node)
        child_results = [(status_of[id(c)], decisive_of[id(c)]) for c in children]
        kind = "or" if isinstance(node, OR) else "and"
        status, decisive = _combine(kind, child_results)
        status_of[id(node)] = status
        decisive_of[id(node)] = decisive
    return status_of[id(expression)], decisive_of[id(expression)]


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def run_license_audit(
    resolved_raw: dict[str, str],
    licenses_raw: dict[str, str],
    allowed_raw: list[str],
    denied_raw: list[str],
) -> dict[str, Any]:
    """Apply the license policy to every resolved package.

    Everything is validated before the first package is evaluated, so an
    invalid expression fails the whole request (400) with no partial output.
    Entries in ``licenses`` for packages that are not resolved are ignored:
    the mapping may be a superset of the resolved set (e.g. a license
    knowledge base).
    """
    resolved = parse_resolved(resolved_raw)
    expressions = parse_license_mapping(licenses_raw)
    allowed = parse_identifier_set(allowed_raw, "allowed")
    denied = parse_identifier_set(denied_raw, "denied")

    results: list[dict[str, Any]] = []
    buckets: dict[str, list[str]] = {status: [] for status in STATUS_ORDER}
    for name in sorted(resolved):
        version: Version = resolved[name]
        entry = expressions.get(name)
        if entry is None:
            status = MISSING
            normalized: Optional[str] = None
            decisive: list[str] = []
        else:
            expression, normalized = entry
            status, decisive_set = evaluate(expression, allowed, denied)
            decisive = sorted(decisive_set)
        buckets[status].append(name)
        results.append(
            {
                "name": name,
                "version": str(version),
                "status": status,
                "expression": normalized,
                "decisive": decisive,
            }
        )

    body: dict[str, Any] = {
        "status": "ok",
        "summary": {
            "packages": len(results),
            **{status: len(buckets[status]) for status in STATUS_ORDER},
        },
        "results": results,
    }
    for status in STATUS_ORDER:
        body[status] = buckets[status]
    return body
