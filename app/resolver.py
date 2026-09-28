"""Local, deterministic PEP 440 dependency resolver.

The resolver is intentionally self-contained: it works on an in-memory
package index supplied with the request, so no network access or external
package repository is required.

Resolution strategy
-------------------
* Constraints are intersected per package.
* A locked version that still satisfies every active constraint is always
  tried first ("lock first").
* All other candidate versions are tried from highest to lowest.
* Pre-releases are excluded by default.
* Search is depth-first with fully deterministic ordering.  Failures bubble
  up as structured conflicts carrying the involved packages and the exact
  dependency path that produced each mutually-exclusive constraint.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

# ---------------------------------------------------------------------------
# Parsed data model
# ---------------------------------------------------------------------------


class ResolutionInputError(ValueError):
    """Semantically invalid request payload (mapped to HTTP 400)."""


class ResolutionCancelled(BaseException):
    """Raised at a candidate-evaluation boundary when the job is cancelled.

    BaseException on purpose: cooperative cancellation must not be swallowed
    by ``except Exception`` while unwinding the solver.  Carries the number
    of candidate evaluations already made.
    """

    def __init__(self, attempts: int = 0) -> None:
        super().__init__("resolution cancelled")
        self.attempts = attempts


@dataclass(frozen=True)
class ParsedDependency:
    """A requirement after PEP 508 parsing."""

    name: str  # canonical target
    specifier: SpecifierSet
    specifier_text: str
    prerelease_pin: bool  # explicit pre-release pin such as ==2.0rc1
    marker_text: Optional[str]
    applies: Any  # callable(marker_env) -> bool


@dataclass(frozen=True)
class Constraint:
    """One requirement imposed on a package along one dependency path."""

    package: str
    specifier: SpecifierSet
    specifier_text: str
    prerelease_pin: bool
    source: str  # canonical requiring package, or ROOT
    source_version: Optional[str]
    # Hop list leading to the requiring package (excluding the requirer
    # itself and the target); empty for root requirements.
    path_nodes: tuple[tuple[str, str], ...]  # (package, version) hop list

    def satisfied_by(self, version: Version) -> bool:
        # Pre-release filtering is performed by the caller, so ask the
        # specifier set to include pre-releases here unconditionally.
        return self.specifier.contains(version, prereleases=True)


@dataclass(frozen=True)
class VersionRecord:
    dependencies: tuple[ParsedDependency, ...]


ROOT = "<root>"

# Fixed environment used for PEP 508 marker evaluation, so identical input
# always produces identical output.  Overridable per request.
DEFAULT_MARKER_ENV: dict[str, str] = {
    "implementation_name": "cpython",
    "os_name": "posix",
    "platform_machine": "x86_64",
    "platform_python_implementation": "CPython",
    "platform_release": "0",
    "platform_system": "Linux",
    "platform_version": "0",
    "python_full_version": "3.11.0",
    "python_version": "3.11",
    "sys_platform": "linux",
}


def _make_applies(req: Requirement) -> Any:
    if req.marker is None:
        return lambda _env: True
    marker = req.marker

    def applies(env: dict[str, str]) -> bool:
        # Unknown marker variable -> keep the requirement pessimistically.
        try:
            return bool(marker.evaluate(env))
        except Exception:
            return True

    return applies


def _parse_requirement(raw: str, *, name_override: Optional[str], origin: str) -> ParsedDependency:
    text = raw if name_override is None else f"{name_override} {raw}".strip()
    try:
        req = Requirement(text)
    except (InvalidRequirement, ValueError) as exc:
        raise ResolutionInputError(f"{origin}: invalid requirement {raw!r}: {exc}")
    prerelease_pin = False
    for part in req.specifier:
        if part.operator in ("==", "!=") and part.version is not None:
            try:
                if Version(part.version).is_prerelease:
                    prerelease_pin = True
            except InvalidVersion:
                pass
    return ParsedDependency(
        name=canonicalize_name(req.name),
        specifier=req.specifier,
        specifier_text=str(req.specifier),
        prerelease_pin=prerelease_pin,
        marker_text=str(req.marker) if req.marker is not None else None,
        applies=_make_applies(req),
    )


def _iter_dependencies(raw: Any, origin: str):
    """Yield ``(position, original_text, ParsedDependency)`` tuples.

    Works for both a mapping and a list of PEP 508 strings.  ``position`` is
    the zero-based position in the input (list index or mapping insertion
    order) and ``original_text`` is the requirement exactly as supplied, so
    callers can distinguish duplicate requirements.
    """
    if raw is None:
        return
    if isinstance(raw, dict):
        for position, (package, spec) in enumerate(raw.items()):
            if spec is None:
                spec = ""
            if not isinstance(spec, str):
                raise ResolutionInputError(
                    f"{origin}: dependency spec for {package!r} must be a string"
                )
            yield (
                position,
                f"{package} {spec}".strip(),
                _parse_requirement(spec, name_override=package, origin=origin),
            )
        return
    if isinstance(raw, list):
        for position, item in enumerate(raw):
            if not isinstance(item, str):
                raise ResolutionInputError(f"{origin}: dependency list items must be strings")
            yield position, item, _parse_requirement(
                item, name_override=None, origin=origin
            )
        return
    raise ResolutionInputError(f"{origin}: dependencies must be an object or a list of strings")


@dataclass
class PackageIndex:
    # canonical name -> list of (parsed version, record)
    versions: dict[str, list[tuple[Version, VersionRecord]]] = field(default_factory=dict)


def parse_index(packages: dict[str, Any]) -> tuple[PackageIndex, list[str]]:
    errors: list[str] = []
    index = PackageIndex()

    for package_name, versions in packages.items():
        if not isinstance(versions, dict):
            errors.append(f"package {package_name!r}: versions must be an object")
            continue
        canonical = canonicalize_name(package_name)
        if canonical in index.versions:
            errors.append(
                f"package {package_name!r}: duplicates {canonical!r} after name normalization"
            )
            continue
        records: list[tuple[Version, VersionRecord]] = []
        seen: set[str] = set()
        for raw_version, body in versions.items():
            origin = f"package {package_name!r} version {raw_version!r}"
            try:
                parsed_version = Version(raw_version)
            except InvalidVersion as exc:
                errors.append(f"{origin}: not a valid PEP 440 version: {exc}")
                continue
            if str(parsed_version) in seen:
                errors.append(f"{origin}: duplicate version after PEP 440 normalization")
                continue
            seen.add(str(parsed_version))
            if body is None:
                body = {}
            if not isinstance(body, dict):
                errors.append(f"{origin}: version entry must be an object")
                continue
            deps: list[ParsedDependency] = []
            if "dependencies" in body:
                try:
                    deps = [
                        dep
                        for _position, _text, dep in _iter_dependencies(
                            body["dependencies"], origin
                        )
                    ]
                except ResolutionInputError as exc:
                    errors.append(str(exc))
                    continue
            records.append(
                (parsed_version, VersionRecord(dependencies=tuple(deps)))
            )
        index.versions[canonical] = records

    return index, errors


@dataclass(frozen=True)
class RootEntry:
    """A root requirement with its position and original text.

    Duplicate requirements (identical text appearing more than once, or
    different spellings normalizing to the same canonical package) stay
    distinguishable through ``index``.
    """

    index: int  # 0-based position in the root list / mapping
    requirement: str  # requirement text exactly as supplied
    dep: ParsedDependency


def parse_root_entries(raw: Any, origin: str) -> list[RootEntry]:
    """Parse root requirements while preserving input position and text.

    Uses the exact same PEP 440/508 rules as :func:`parse_requirements`; the
    positions refer to the original input, not a marker-filtered list.
    """
    return [
        RootEntry(index=position, requirement=text, dep=dep)
        for position, text, dep in _iter_dependencies(raw, origin)
    ]


def parse_requirements(raw: Any, origin: str) -> list[ParsedDependency]:
    return [dep for _position, _text, dep in _iter_dependencies(raw, origin)]


def parse_locks(raw: dict[str, str]) -> tuple[dict[str, Version], list[str]]:
    locks: dict[str, Version] = {}
    errors: list[str] = []
    for package, version in raw.items():
        if not isinstance(version, str):
            errors.append(f"lock for {package!r}: version must be a string")
            continue
        try:
            parsed = Version(version)
        except InvalidVersion as exc:
            errors.append(f"lock for {package!r}: {version!r} is not PEP 440: {exc}")
            continue
        canonical = canonicalize_name(package)
        if canonical in locks:
            errors.append(f"lock for {package!r}: duplicate normalized name {canonical!r}")
            continue
        locks[canonical] = parsed
    return locks, errors


# ---------------------------------------------------------------------------
# Conflicts
# ---------------------------------------------------------------------------


@dataclass
class LeafConflict:
    """Terminal impossibility: no candidate of one package survives."""

    package: str
    reason: str  # not-found | no-versions | unsatisfiable
    constraints: list[Constraint]  # all active constraints on the package
    rejected: list[Constraint]  # optional: constraint that clashed with choice
    attempted: list[str]
    available: list[str]
    detail: str

    @property
    def involved(self) -> set[str]:
        names = {self.package}
        for c in self.constraints + self.rejected:
            names.add(c.source)
        return names


@dataclass
class CompositeConflict:
    """Every candidate of a package failed in a deeper branch."""

    package: str
    reason: str  # exhausted | search-limit
    constraints: list[Constraint]
    attempted: list[str]
    available: list[str]
    children: list[Any]
    involved: set[str]


Conflict = LeafConflict | CompositeConflict


# ---------------------------------------------------------------------------
# Candidate ordering
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    version: Version
    locked: bool


def _eligible_versions(
    index: PackageIndex,
    package: str,
    constraints: list[Constraint],
    allow_prereleases: bool,
    lock: Optional[Version] = None,
) -> list[Version]:
    allow_prerelease = allow_prereleases or any(c.prerelease_pin for c in constraints)
    out: list[Version] = []
    for version, _record in index.versions.get(package, []):
        if (
            version.is_prerelease
            and not allow_prerelease
            and (lock is None or version != lock)
        ):
            continue
        if all(c.satisfied_by(version) for c in constraints):
            out.append(version)
    out.sort(reverse=True)
    return out


def build_candidates(
    index: PackageIndex,
    package: str,
    constraints: list[Constraint],
    lock: Optional[Version],
    allow_prereleases: bool,
) -> tuple[list[Candidate], list[Version]]:
    eligible = _eligible_versions(index, package, constraints, allow_prereleases, lock)
    candidates: list[Candidate] = []
    if lock is not None and lock in eligible:
        candidates.append(Candidate(lock, locked=True))
    for version in eligible:
        if lock is not None and version == lock:
            continue
        candidates.append(Candidate(version, locked=False))
    return candidates, eligible


def available_versions(index: PackageIndex, package: str) -> list[str]:
    return [str(v) for v, _ in sorted(index.versions.get(package, []), reverse=True)]


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Solver
# ---------------------------------------------------------------------------
#
# A classic recursive depth-first backtracking solver.
#
#   * ``constraints[package]`` is the intersected list of all requirements
#     currently imposed on a package by selected versions (plus the root).
#   * ``choose(package)`` tries that package's candidates highest-first
#     (locked compatible version first), applies the winning candidate's
#     dependencies, and recurses into the next not-yet-chosen demanded
#     package.
#   * Each call owns ONLY the effects of its currently tried candidate;
#     when a deeper branch fails, effects are unwound in exact reverse
#     order.  This makes backtracking exhaustive and obviously correct.
#   * Backtracking is chronological: a failure simply unwinds to the
#     calling frame.  The ``involved`` package sets are used solely to
#     render actionable conflict reports, never for control flow.
# ---------------------------------------------------------------------------


@dataclass
class SolveResult:
    status: str  # ok | conflict | limit
    chosen: dict[str, str]
    attempts: int
    edges: list[dict[str, str]]
    conflict: Optional[Any]
    lock_notes: dict[str, str]


def resolve(
    index: PackageIndex,
    roots: list[ParsedDependency],
    locks: dict[str, Version],
    *,
    allow_prereleases: bool = False,
    marker_env: Optional[dict[str, str]] = None,
    max_attempts: int = 100_000,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> SolveResult:
    import sys

    sys.setrecursionlimit(max(10_000, sys.getrecursionlimit()))

    env = dict(DEFAULT_MARKER_ENV)
    if marker_env:
        env.update({str(k): str(v) for k, v in marker_env.items()})

    chosen: dict[str, Version] = {}
    constraints: dict[str, list[Constraint]] = {}
    edges: list[tuple[str, Optional[str], str, str]] = []
    attempts = 0
    lock_notes: dict[str, str] = {}

    def note_lock(pkg: str, note: str) -> None:
        lock_notes[pkg] = note

    def representative_hops(cs: list[Constraint]) -> tuple[tuple[str, str], ...]:
        """Hops leading to the constrained package, excluding its own node."""
        rep = min(
            cs,
            key=lambda c: tuple((n, v) for n, v in c.path_nodes),
            default=None,
        )
        if rep is None or rep.source == ROOT:
            return rep.path_nodes if rep is not None else ()
        return rep.path_nodes + ((rep.source, rep.source_version or ""),)

    def empty_leaf(pkg: str, cs: list[Constraint]) -> LeafConflict:
        if pkg not in index.versions:
            return LeafConflict(
                package=pkg,
                reason="not-found",
                constraints=list(cs),
                rejected=[],
                attempted=[],
                available=[],
                detail=f"package {pkg!r} is required but not present in the supplied index",
            )
        if not index.versions[pkg]:
            return LeafConflict(
                package=pkg,
                reason="no-versions",
                constraints=list(cs),
                rejected=[],
                attempted=[],
                available=[],
                detail=f"package {pkg!r} has no versions in the supplied index",
            )
        allow_prerelease = allow_prereleases or any(c.prerelease_pin for c in cs)
        lock = locks.get(pkg)
        unfiltered = [
            v for v, _ in sorted(index.versions[pkg], reverse=True)
            if all(c.satisfied_by(v) for c in cs)
        ]
        if (
            unfiltered
            and all(v.is_prerelease for v in unfiltered)
            and not allow_prerelease
            and not (lock is not None and lock in unfiltered)
        ):
            detail = (
                f"only pre-release versions of {pkg!r} satisfy the constraints; "
                f"set allow_prereleases=true to accept them"
            )
        else:
            detail = f"no version of {pkg!r} satisfies all active constraints"
        return LeafConflict(
            package=pkg,
            reason="unsatisfiable",
            constraints=list(cs),
            rejected=[],
            attempted=[],
            available=available_versions(index, pkg),
            detail=detail,
        )

    # Ordered list of every package demanded so far (discovery order =
    # sorted roots, then dependencies appended by selected candidates).
    demanded: list[str] = []

    def add_edge(
        sink: list,
        source: str,
        source_version: Optional[str],
        target: str,
        target_version: str,
    ) -> None:
        edge = (source, source_version, target, target_version)
        if edge not in edges:
            edges.append(edge)
            sink.append(edge)

    def choose(package: str) -> tuple[str, Any]:
        """Try candidates for ``package``; return ("ok", None) or a conflict."""
        nonlocal attempts

        cs = list(constraints.get(package, []))
        lock = locks.get(package)
        candidates, eligible = build_candidates(
            index, package, cs, lock, allow_prereleases
        )

        if lock is not None:
            if package not in index.versions:
                note_lock(package, "not-found")
            else:
                raw_versions = [v for v, _ in index.versions[package]]
                if lock not in raw_versions:
                    note_lock(package, "missing-version")
                elif not any(c.locked for c in candidates):
                    note_lock(package, "unsatisfiable")

        if not candidates:
            return ("conflict", empty_leaf(package, cs))

        hops = representative_hops(cs)
        lock_version = lock if any(c.locked for c in candidates) else None
        attempted: list[str] = []
        branch_failures: list[Any] = []

        for candidate in candidates:
            # Cooperative cancellation point: exactly one candidate
            # evaluation boundary, so a running job stops between candidates
            # rather than mid-branch.
            if should_cancel is not None and should_cancel():
                raise ResolutionCancelled(attempts)
            attempts += 1
            if attempts > max_attempts:
                limit = CompositeConflict(
                    package=package,
                    reason="search-limit",
                    constraints=list(cs),
                    attempted=list(attempted),
                    available=[str(v) for v in eligible],
                    children=list(branch_failures),
                    involved={package},
                )
                return ("limit", limit)

            version = candidate.version
            attempted.append(str(version))
            if candidate.locked:
                note_lock(package, "applied")
            elif lock_version is not None and lock_notes.get(package) == "applied":
                note_lock(package, "backtracked")

            # --- apply this candidate ---
            chosen[package] = version
            added_edges: list[tuple[str, Optional[str], str, str]] = []
            for c in cs:
                add_edge(
                    added_edges,
                    c.source,
                    c.source_version,
                    package,
                    str(version),
                )

            added: list[Constraint] = []
            new_demands: list[str] = []
            immediate: Any = None

            record = dict(index.versions.get(package, [])).get(version)
            if record is not None:
                for dep in sorted(
                    record.dependencies, key=lambda d: (d.name, d.specifier_text)
                ):
                    if not dep.applies(env):
                        continue
                    target = dep.name
                    new_constraint = Constraint(
                        package=target,
                        specifier=dep.specifier,
                        specifier_text=dep.specifier_text,
                        prerelease_pin=dep.prerelease_pin,
                        source=package,
                        source_version=str(version),
                        # hops leads to this package (the constraint source);
                        # the renderer appends the source node itself.
                        path_nodes=hops,
                    )
                    if target in chosen and not new_constraint.satisfied_by(chosen[target]):
                        immediate = LeafConflict(
                            package=target,
                            reason="unsatisfiable",
                            constraints=list(constraints.get(target, []))
                            + [new_constraint],
                            rejected=[new_constraint],
                            attempted=[str(chosen[target])],
                            available=available_versions(index, target),
                            detail=(
                                f"{package}=={version} requires "
                                f"{target}{dep.specifier_text or ''}, but "
                                f"{target}=={chosen[target]} was already selected"
                            ),
                        )
                        break
                    added.append(new_constraint)
                    constraints.setdefault(target, []).append(new_constraint)
                    if target not in chosen and target not in demanded:
                        demanded.append(target)
                        new_demands.append(target)

            if immediate is None:
                # Recurse into the oldest not-yet-chosen demanded package.
                status, conflict = solve_next()
            else:
                status, conflict = "conflict", immediate

            if status == "ok":
                return ("ok", None)

            # --- rollback this candidate exactly ---
            for new_constraint in reversed(added):
                bucket = constraints.get(new_constraint.package)
                if bucket is not None and new_constraint in bucket:
                    bucket.remove(new_constraint)
                    if not bucket:
                        del constraints[new_constraint.package]
            for pkg_ in new_demands:
                # The recursive calls already removed any constraints they
                # added; drop this candidate's discovery markers.
                if pkg_ in demanded and pkg_ not in constraints and pkg_ not in chosen:
                    demanded.remove(pkg_)
            for edge in added_edges:
                edges.remove(edge)
            del chosen[package]

            if status == "limit":
                return ("limit", conflict)
            branch_failures.append(conflict)

        involved = {package}
        for child in branch_failures:
            involved |= child.involved
        return (
            "conflict",
            CompositeConflict(
                package=package,
                reason="exhausted",
                constraints=list(cs),
                attempted=list(attempted),
                available=[str(v) for v in eligible],
                children=list(branch_failures),
                involved=involved,
            ),
        )

    def solve_next() -> tuple[str, Any]:
        """Choose the oldest demanded package without an assignment."""
        for pkg in demanded:
            if pkg not in chosen:
                return choose(pkg)
        return ("ok", None)

    # -- Seed root requirements --------------------------------------------
    root_constraints: list[Constraint] = []
    for dep in sorted(roots, key=lambda d: (d.name, d.specifier_text)):
        if not dep.applies(env):
            continue
        constraint = Constraint(
            package=dep.name,
            specifier=dep.specifier,
            specifier_text=dep.specifier_text,
            prerelease_pin=dep.prerelease_pin,
            source=ROOT,
            source_version=None,
            path_nodes=(),
        )
        if dep.name in chosen and not constraint.satisfied_by(chosen[dep.name]):
            leaf = LeafConflict(
                package=dep.name,
                reason="unsatisfiable",
                constraints=[constraint],
                rejected=[constraint],
                attempted=[str(chosen[dep.name])],
                available=available_versions(index, dep.name),
                detail="root requirements contradict each other",
            )
            return SolveResult("conflict", {}, 0, [], leaf, {})
        root_constraints.append(constraint)
        constraints.setdefault(dep.name, []).append(constraint)
        if dep.name not in demanded:
            demanded.append(dep.name)

    status, conflict = solve_next()

    # Root constraints are only used to seed; clean up on failure.
    if status != "ok":
        for constraint in reversed(root_constraints):
            bucket = constraints.get(constraint.package)
            if bucket is not None and constraint in bucket:
                bucket.remove(constraint)
                if not bucket:
                    del constraints[constraint.package]
        return SolveResult(
            status, {}, attempts, [], conflict, dict(sorted(lock_notes.items()))
        )

    for pkg, lock in locks.items():
        if pkg in chosen:
            lock_notes.setdefault(pkg, "applied" if chosen[pkg] == lock else "unused")
        elif pkg in index.versions:
            lock_notes.setdefault(pkg, "unused")
        else:
            lock_notes.setdefault(pkg, "not-found")

    success_edges = [
        {
            "source": src,
            "source_version": src_ver or "",
            "target": tgt,
            "target_version": tgt_ver,
        }
        for src, src_ver, tgt, tgt_ver in sorted(
            edges, key=lambda e: (e[0], e[2], e[1] or "", e[3])
        )
    ]
    return SolveResult(
        status="ok",
        chosen={pkg: str(chosen[pkg]) for pkg in sorted(chosen)},
        attempts=attempts,
        edges=success_edges,
        conflict=None,
        lock_notes=dict(sorted(lock_notes.items())),
    )
