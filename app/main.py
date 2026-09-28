"""FastAPI application exposing the local dependency resolver."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, Callable, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .audit import run_audit
from .avoid_vulnerabilities import run_avoid_vulnerabilities
from .chokepoint_audit import run_dependency_chokepoints
from .diagnose import run_root_conflict_diagnosis
from .environment_matrix import parse_environments, run_environment_matrix
from .graph_fingerprints import run_graph_fingerprints
from .license_audit import run_license_audit
from .jobs import (
    CANCELLED,
    FAILED,
    RUNNING,
    SUCCEEDED,
    JobStore,
    JobWorker,
)
from .rebuild import run_rebuild_plan
from .resolver import (
    ResolutionInputError,
    parse_index,
    parse_locks,
    parse_root_entries,
    resolve,
)
from .serialize import conflict_summary
from .upgrade_feasibility import run_upgrade_feasibility
from .version_withdrawal import run_version_withdrawal

DEFAULT_DB_PATH = os.path.join("data", "jobs.db")


class ResolveBaseRequest(BaseModel):
    """Request fields shared by every endpoint that runs the solver."""

    model_config = ConfigDict(extra="forbid")

    packages: dict[str, dict[str, Any]] = Field(
        ...,
        description=(
            "Package index: package name -> version -> entry. "
            "Each entry may contain 'dependencies' as either "
            "{package: specifier} or a list of PEP 508 strings."
        ),
    )
    root: Any = Field(
        ...,
        description="Root requirements: {package: specifier} or a list of PEP 508 strings.",
    )
    locks: Optional[dict[str, str]] = Field(
        default=None,
        description="Optional pinned versions. Pins are kept while they satisfy all constraints.",
    )
    allow_prereleases: bool = Field(
        default=False,
        description="Include a/b/rc pre-releases for every package when true.",
    )
    max_attempts: int = Field(
        default=100_000, ge=1, le=10_000_000,
        description="Bound on candidate evaluations to keep resolution finite.",
    )


class ResolveRequest(ResolveBaseRequest):
    marker_env: Optional[dict[str, str]] = Field(
        default=None,
        description="Override values for PEP 508 environment marker evaluation.",
    )


class EnvironmentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        ..., min_length=1,
        description="Environment label; must be unique within the request.",
    )
    marker_env: Optional[dict[str, str]] = Field(
        default=None,
        description="Override values for PEP 508 marker evaluation in this environment.",
    )


class EnvironmentMatrixRequest(ResolveBaseRequest):
    environments: list[EnvironmentInput] = Field(
        ..., min_length=2, max_length=8,
        description=(
            "Named marker environments to resolve under, in comparison "
            "order. Each environment is solved independently."
        ),
    )


class UpgradeFeasibilityRequest(ResolveRequest):
    package: str = Field(
        ..., min_length=1,
        description="Target package to upgrade; normalized like index package names.",
    )
    candidates: list[str] = Field(
        ..., min_length=1, max_length=8,
        description=(
            "Candidate exact versions of the target, 1-8 items in input "
            "order. Each must exist in the package index and no two may "
            "normalize to the same PEP 440 version."
        ),
    )


class WithdrawInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package: str = Field(
        ..., min_length=1,
        description="Package to withdraw; normalized like index package names.",
    )
    version: str = Field(
        ..., min_length=1,
        description="PEP 440 version to withdraw from this request's index.",
    )


class VersionWithdrawalRequest(ResolveRequest):
    withdraw: WithdrawInput = Field(
        ...,
        description=(
            "The single package version removed from this request's index "
            "before the second solve."
        ),
    )


class AdvisoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Local advisory identifier.")
    package: str = Field(..., description="Affected package name.")
    affected: str = Field(
        ..., description="PEP 440 specifier of the affected version range."
    )


class AvoidVulnerabilitiesRequest(ResolveRequest):
    advisories: list[AdvisoryInput] = Field(
        ...,
        description=(
            "Local advisories to avoid. Every index version of an advisory's "
            "canonical package inside its PEP 440 'affected' range is excluded "
            "from this request's index before solving; multiple advisories "
            "union."
        ),
    )


class GraphEdgeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., description="Requiring package, or '<root>'.")
    source_version: str = Field(
        ..., description="Resolved version of the source ('' for '<root>')."
    )
    target: str = Field(..., description="Required package.")
    target_version: str = Field(..., description="Resolved version of the target.")


class AuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolved: dict[str, str] = Field(
        ..., description="Package -> resolved version, as returned by /resolve."
    )
    dependency_graph: list[GraphEdgeInput] = Field(
        default_factory=list,
        description="Edges as returned by /resolve.",
    )
    advisories: list[AdvisoryInput] = Field(
        default_factory=list,
        description="Local advisories to match against the resolved versions.",
    )


class DependencyChokepointsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolved: dict[str, str] = Field(
        ..., description="Package -> resolved version, as returned by /resolve."
    )
    dependency_graph: list[GraphEdgeInput] = Field(
        default_factory=list,
        description="Edges as returned by /resolve.",
    )


class GraphFingerprintsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolved: dict[str, str] = Field(
        ..., description="Package -> resolved version, as returned by /resolve."
    )
    dependency_graph: list[GraphEdgeInput] = Field(
        default_factory=list,
        description="Edges as returned by /resolve.",
    )


class RebuildPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolved: dict[str, str] = Field(
        ..., description="Package -> resolved version, as returned by /resolve."
    )
    dependency_graph: list[GraphEdgeInput] = Field(
        default_factory=list,
        description="Edges as returned by /resolve.",
    )
    changed: list[str] = Field(
        default_factory=list,
        description=(
            "Locally changed package names. Names absent from 'resolved' are "
            "reported as 'uninstalled'; the rest seed reverse-dependency "
            "propagation."
        ),
    )


class LicenseAuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resolved: dict[str, str] = Field(
        ..., description="Package -> resolved version, as returned by /resolve."
    )
    licenses: dict[str, str] = Field(
        ...,
        description=(
            "Package -> SPDX license expression. Resolved packages without an "
            "entry are reported as 'missing'; entries for packages that are "
            "not resolved are ignored."
        ),
    )
    allowed: list[str] = Field(
        default_factory=list,
        description="SPDX identifiers considered compliant.",
    )
    denied: list[str] = Field(
        default_factory=list,
        description=(
            "SPDX identifiers considered violations. Denied takes precedence "
            "when an identifier appears in both sets."
        ),
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Open the SQLite job store and start the background worker.

    Jobs left ``running`` by an earlier process are returned to ``queued``
    before the worker starts, so a crash/kill never strands work.
    """
    db_path = os.environ.get("RESOLVER_DB", DEFAULT_DB_PATH)
    store = JobStore(db_path)
    store.requeue_stale_running()
    worker = JobWorker(store, run_resolution_job)
    worker.start()
    _app.state.job_store = store
    _app.state.job_worker = worker
    try:
        yield
    finally:
        worker.stop()
        store.close()


app = FastAPI(
    title="Local PEP 440 Dependency Resolver",
    version="1.10.0",
    description=(
        "Resolves transitive dependencies from a self-contained package index. "
        "No external package index or account is used."
    ),
    lifespan=lifespan,
)


@app.exception_handler(ResolutionInputError)
async def _input_error_handler(_request: Request, exc: ResolutionInputError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": {"code": "invalid_request", "message": str(exc)}})


def _parse_input(payload: ResolveBaseRequest):
    """Parse and semantically validate a request.

    Cheap (no solving), so it can run synchronously on both ``/resolve`` and
    ``POST /jobs`` to reject malformed input with 400 before queueing.
    Returns the root requirements as position-annotated entries; callers
    that only need parsed requirements take ``[entry.dep for entry in ...]``.
    """
    index, index_errors = parse_index(payload.packages)
    if index_errors:
        raise ResolutionInputError("; ".join(index_errors))

    entries = parse_root_entries(payload.root, "root requirements")

    locks, lock_errors = parse_locks(payload.locks or {})
    if lock_errors:
        raise ResolutionInputError("; ".join(lock_errors))

    return index, entries, locks


def _resolve_body(
    payload: ResolveRequest,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> tuple[dict[str, Any], int, Optional[dict[str, Any]], Optional[int]]:
    """Validate and resolve. Returns ``(body, http_status, error, attempts)``.

    ``ResolutionCancelled`` is allowed to propagate so the job worker can
    finalise the job as cancelled at a candidate boundary.
    """
    index, entries, locks = _parse_input(payload)

    result = resolve(
        index,
        [entry.dep for entry in entries],
        locks,
        allow_prereleases=payload.allow_prereleases,
        marker_env=payload.marker_env,
        max_attempts=payload.max_attempts,
        should_cancel=should_cancel,
    )

    body: dict[str, Any] = {
        "status": result.status,
        "attempts": result.attempts,
        "allow_prereleases": payload.allow_prereleases,
    }
    if result.status == "ok":
        body["resolved"] = result.chosen
        body["dependency_graph"] = result.edges
        body["locks"] = result.lock_notes
        return body, 200, None, result.attempts
    if result.status == "conflict":
        body["locks"] = result.lock_notes
        body["conflict"] = conflict_summary(result)
        return body, 409, None, result.attempts
    # limit
    body["locks"] = result.lock_notes
    body["conflict"] = conflict_summary(result)
    body["error"] = {
        "code": "search_limit_exceeded",
        "message": f"resolution exceeded {payload.max_attempts} candidate evaluations",
    }
    return body, 409, None, result.attempts


def run_resolution_job(
    raw_payload: dict[str, Any],
    should_cancel: Callable[[], bool],
) -> tuple[Optional[dict[str, Any]], Optional[int], Optional[dict[str, Any]], Optional[int]]:
    """Runner used by the worker thread."""
    payload = ResolveRequest.model_validate(raw_payload)
    try:
        body, status_code, _error, attempts = _resolve_body(payload, should_cancel)
    except ResolutionInputError as exc:
        # Defensive: POST /jobs validates before queueing, so this only
        # happens for jobs persisted by older/newer code paths.
        return (
            {"error": {"code": "invalid_request", "message": str(exc)}},
            400,
            {"code": "invalid_request", "message": str(exc)},
            None,
        )
    return body, status_code, None, attempts


@app.post("/resolve")
async def resolve_endpoint(payload: ResolveRequest) -> JSONResponse:
    body, status_code, _error, _attempts = _resolve_body(payload)
    return JSONResponse(status_code=status_code, content=body)


@app.post("/resolve/avoid-vulnerabilities")
async def avoid_vulnerabilities_endpoint(
    payload: AvoidVulnerabilitiesRequest,
) -> JSONResponse:
    """Resolve while never selecting an advisory-affected version.

    Accepts the exact same body as ``/resolve`` plus ``advisories`` (a list
    of local ``id`` / ``package`` / ``affected`` entries).  Before solving,
    every index version of each advisory's canonical package that falls
    inside its PEP 440 ``affected`` range is removed from a request-local
    copy of the index; exclusions from multiple advisories take the union.
    The remaining candidates are solved with the ordinary exhaustive
    backtracking, so a locked version an advisory excludes is never selected
    again (reported as ``missing-version``).

    On success the body carries a safe ``resolved`` / ``dependency_graph`` /
    ``locks`` plus the versions each advisory actually excluded and their
    union.  No solution returns 409 ``conflict``; hitting ``max_attempts``
    returns 409 ``undetermined`` and is never treated as unsatisfiable.
    Malformed advisories (e.g. invalid PEP 440 ranges) return 400.
    """
    index, entries, locks = _parse_input(payload)
    body, status_code = run_avoid_vulnerabilities(
        index,
        entries,
        locks,
        payload.advisories,
        allow_prereleases=payload.allow_prereleases,
        marker_env=payload.marker_env,
        max_attempts=payload.max_attempts,
    )
    return JSONResponse(status_code=status_code, content=body)


@app.post("/diagnose/root-conflict")
async def diagnose_root_conflict_endpoint(payload: ResolveRequest) -> JSONResponse:
    """Find a minimal conflicting subset of the root requirements.

    Accepts the exact same request body as ``/resolve`` and reuses its
    PEP 440/508 parsing rules.  When the full input is unsatisfiable, root
    requirements are temporarily deleted one at a time in input order and
    the remainder is re-solved, yielding a *minimal* conflicting root set:
    the set itself has no solution, but deleting any single entry from it
    becomes solvable.  Entries carry the original requirement text and its
    position in the input, so duplicate requirements stay distinguishable.

    All outcomes return 200; the ``status`` field discriminates:

    * ``ok`` — the full input is solvable; ``conflicting_roots`` is empty.
    * ``conflict`` — ``conflicting_roots`` holds the minimal set.
    * ``undetermined`` — the initial solve or a re-solve hit
      ``max_attempts``; hitting the search limit is not treated as a
      contradiction, so no set is reported (``conflicting_roots`` is null).
    """
    index, entries, locks = _parse_input(payload)
    body = run_root_conflict_diagnosis(
        index,
        entries,
        locks,
        allow_prereleases=payload.allow_prereleases,
        marker_env=payload.marker_env,
        max_attempts=payload.max_attempts,
    )
    return JSONResponse(status_code=200, content=body)


@app.post("/audit/vulnerabilities")
async def audit_vulnerabilities_endpoint(payload: AuditRequest) -> JSONResponse:
    """Match local advisories against a resolved dependency graph.

    Takes the ``resolved`` mapping and ``dependency_graph`` edges from a
    successful ``/resolve`` response plus a list of local advisories.  Every
    hit reports the advisory, the resolved package version, and all shortest
    ``<root>`` -> package paths; unreachable hits are listed as ``orphaned``.
    """
    body = run_audit(payload.resolved, payload.dependency_graph, payload.advisories)
    return JSONResponse(status_code=200, content=body)


@app.post("/audit/dependency-chokepoints")
async def dependency_chokepoints_endpoint(
    payload: DependencyChokepointsRequest,
) -> JSONResponse:
    """Find mandatory (unavoidable) dependencies in a resolved graph.

    Takes the ``resolved`` mapping and ``dependency_graph`` edges from a
    successful ``/resolve`` response.  Starting at ``<root>``, a package is a
    mandatory dependency of another when every root-to-package path passes
    through it (no path can bypass it); diamonds therefore do not gate their
    shared target, and cycles are supported.  Each chokepoint also reports the
    packages it exclusively dominates (its dominator-tree descendants) and
    their count.  Results are stably sorted; packages that are resolved but
    unreachable from ``<root>`` are listed separately.
    """
    body = run_dependency_chokepoints(
        payload.resolved, payload.dependency_graph
    )
    return JSONResponse(status_code=200, content=body)


@app.post("/audit/graph-fingerprints")
async def graph_fingerprints_endpoint(
    payload: GraphFingerprintsRequest,
) -> JSONResponse:
    """Fingerprint the dependency closure of ``<root>`` and every package.

    Takes the ``resolved`` mapping and ``dependency_graph`` edges from a
    successful ``/resolve`` response.  For ``<root>`` and every resolved
    package, the full reachable dependency closure — canonical package
    names, PEP 440 normalized versions and deduplicated directed edges — is
    serialized deterministically and hashed with SHA-256.  Nodes in cycles
    or diamonds are counted exactly once, the insertion order of
    ``resolved`` and the order/duplication of input edges cannot affect the
    result, and any version or edge change inside a closure changes the
    fingerprints of exactly the nodes that can reach it.  Packages that are
    resolved but unreachable from ``<root>`` are still fingerprinted over
    their own closure and are additionally listed under ``unreachable``.
    """
    body = run_graph_fingerprints(payload.resolved, payload.dependency_graph)
    return JSONResponse(status_code=200, content=body)


@app.post("/audit/licenses")
async def audit_licenses_endpoint(payload: LicenseAuditRequest) -> JSONResponse:
    """Check resolved packages against a local license policy.

    Takes the ``resolved`` mapping from a successful ``/resolve`` response, a
    package -> SPDX expression mapping, and ``allowed``/``denied`` identifier
    sets.  Every resolved package is classified as ``violation``,
    ``compliant``, ``unknown`` or ``missing`` (no expression provided), with
    the normalized expression and the identifiers that decided the status.
    Any invalid SPDX expression fails the whole request with 400.
    """
    body = run_license_audit(
        payload.resolved, payload.licenses, payload.allowed, payload.denied
    )
    return JSONResponse(status_code=200, content=body)


@app.post("/plan/rebuild")
async def rebuild_plan_endpoint(payload: RebuildPlanRequest) -> JSONResponse:
    """Plan deterministic rebuilds for locally changed packages.

    Takes the ``resolved`` mapping and ``dependency_graph`` edges from a
    successful ``/resolve`` response plus a list of changed package names.
    Reverse-dependency propagation collects every affected package, cycles
    are compressed into groups rebuilt as one batch, and stages are emitted
    dependency-first so groups in one stage may build in parallel.  Each
    affected package also reports its shortest reverse path to the nearest
    changed package; changed names absent from ``resolved`` are listed as
    ``uninstalled``.
    """
    body = run_rebuild_plan(
        payload.resolved, payload.dependency_graph, payload.changed
    )
    return JSONResponse(status_code=200, content=body)


@app.post("/analyze/environment-matrix")
async def environment_matrix_endpoint(payload: EnvironmentMatrixRequest) -> JSONResponse:
    """Resolve the same input under several marker environments and compare.

    Accepts the ``/resolve`` request fields (except the top-level
    ``marker_env``, which moves into each environment) plus 2-8 uniquely
    named environments, each carrying its own optional ``marker_env``.
    Every environment is solved independently with the full ``max_attempts``
    budget — one environment conflicting or hitting the search limit never
    affects the others — and keeps its own ``ok`` / ``conflict`` / ``limit``
    result and ``attempts``.  The version matrix is aggregated over
    successful environments only: each package row maps environment names
    to the resolved version or ``null`` (absent in that environment), and
    ``differences`` lists the packages whose version or presence differs
    (empty when fewer than two environments succeed).  Environments are
    reported in input order, packages sorted by canonical name.  Valid
    requests always return 200; input validation mirrors ``/resolve``.
    """
    index, entries, locks = _parse_input(payload)
    environments = parse_environments(payload.environments)
    body = run_environment_matrix(
        index,
        entries,
        locks,
        allow_prereleases=payload.allow_prereleases,
        max_attempts=payload.max_attempts,
        environments=environments,
    )
    return JSONResponse(status_code=200, content=body)


@app.post("/analyze/version-withdrawal")
async def version_withdrawal_endpoint(payload: VersionWithdrawalRequest) -> JSONResponse:
    """Compare the resolution before and after withdrawing one package version.

    Accepts the exact same request body as ``/resolve`` plus a ``withdraw``
    target (one package and one of its versions).  The baseline solve runs on
    the unmodified index; the withdrawal solve re-resolves the same roots,
    locks, marker environment and attempt budget against a copy of this
    request's index with exactly that version removed — a full re-resolution
    against the complete dependency constraints, never an inference along the
    old dependency graph.  When both succeed, the response lists the packages
    that were added, removed or changed version, plus the post-withdrawal
    dependency graph and lock disposition.

    All outcomes return 200; the ``status`` field discriminates:

    * ``ok`` — both solves succeeded; ``changes`` and the post-withdrawal
      ``resolved`` / ``dependency_graph`` / ``locks`` are reported.
    * ``baseline_conflict`` — the unmodified input already has no solution.
    * ``withdrawn_conflict`` — the baseline solves, the withdrawn input does
      not.
    * ``undetermined`` — either solve hit ``max_attempts``; hitting the
      search limit is not treated as a contradiction.

    A ``withdraw`` package or version absent from the index is a 400 input
    error.  Result ordering is deterministic.
    """
    index, entries, locks = _parse_input(payload)
    body = run_version_withdrawal(
        index,
        entries,
        locks,
        allow_prereleases=payload.allow_prereleases,
        marker_env=payload.marker_env,
        max_attempts=payload.max_attempts,
        withdraw_package=payload.withdraw.package,
        withdraw_version=payload.withdraw.version,
    )
    return JSONResponse(status_code=200, content=body)


@app.post("/analyze/upgrade-feasibility")
async def upgrade_feasibility_endpoint(payload: UpgradeFeasibilityRequest) -> JSONResponse:
    """Check 1-8 candidate upgrade versions of one package, independently.

    Accepts the exact same request body as ``/resolve`` plus a target
    ``package`` and 1-8 ``candidates`` versions.  For every candidate, in
    input order, an exact-version root constraint (``==<candidate>``) is
    *temporarily added* to the original root requirements — never replacing
    them — and the whole project is re-solved with the ordinary exhaustive
    backtracking.  The original roots, all other locks, the marker
    environment and a full ``max_attempts`` budget participate in every
    independent solve, so feasibility reflects the complete transitive
    constraints rather than the target package's own version range.  A lock
    on the target that contradicts the pin is falsified as usual.

    Each candidate is reported in input order as one of:

    * ``ok`` — complete ``resolved`` / ``dependency_graph`` / ``locks`` plus
      ``changes`` relative to the original locks (added / removed / changed).
    * ``conflict`` — structured ``conflict`` summary (same shape as
      ``/resolve``) proving this candidate cannot be installed.
    * ``undetermined`` — the solve hit ``max_attempts``; the search limit is
      not treated as a proof of conflict, so the candidate is never reported
      as uninstallable.

    Every candidate keeps its own ``attempts``.  Valid requests always
    return 200; an unknown target package, a candidate absent from the
    index, a non-PEP-440 candidate, or PEP-440-duplicate candidates return
    400; shape violations return 422.
    """
    index, entries, locks = _parse_input(payload)
    body = run_upgrade_feasibility(
        index,
        entries,
        locks,
        allow_prereleases=payload.allow_prereleases,
        marker_env=payload.marker_env,
        max_attempts=payload.max_attempts,
        target_package=payload.package,
        candidate_versions=payload.candidates,
    )
    return JSONResponse(status_code=200, content=body)


# ---------------------------------------------------------------------------
# Asynchronous jobs
# ---------------------------------------------------------------------------


def _store(request: Request) -> JobStore:
    return request.app.state.job_store


def _job_view(job: dict[str, Any]) -> dict[str, Any]:
    view: dict[str, Any] = {
        "id": job["id"],
        "status": job["status"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
    }
    if job["status"] == RUNNING or job["cancel_requested"]:
        view["cancel_requested"] = job["cancel_requested"]
    if job["attempts"] is not None:
        view["attempts"] = job["attempts"]
    if job["status"] in (SUCCEEDED, FAILED) and job["response"] is not None:
        # The synchronous response body, including 400/409-style shapes.
        view["response"] = job["response"]
        view["response_status"] = job["response_status"]
    if job["error"] is not None:
        view["error"] = job["error"]
    return view


@app.post("/jobs", status_code=202)
async def create_job(payload: ResolveRequest, request: Request) -> JSONResponse:
    """Persist the same payload accepted by ``/resolve`` and queue it.

    Input is parsed and validated (but not solved) before queueing, so bad
    requests get the same 400/422 as ``/resolve`` instead of a dead job.
    """
    _parse_input(payload)
    store = _store(request)
    job = store.enqueue(payload.model_dump(mode="json"))
    request.app.state.job_worker.wake()
    return JSONResponse(
        status_code=202,
        content=_job_view(job),
        headers={"Location": f"/jobs/{job['id']}"},
    )


@app.get("/jobs/{job_id}")
async def get_job(job_id: str, request: Request) -> JSONResponse:
    job = _store(request).get(job_id)
    if job is None:
        return JSONResponse(
            status_code=404, content={"error": {"code": "not_found", "message": f"job {job_id!r} not found"}}
        )
    return JSONResponse(status_code=200, content=_job_view(job))


@app.delete("/jobs/{job_id}")
async def cancel_job(job_id: str, request: Request) -> JSONResponse:
    """Cancel a job.

    * queued    -> cancelled immediately (200)
    * running   -> cancel requested; stops at the next candidate-evaluation
                   boundary and becomes cancelled (202)
    * cancelled -> idempotent no-op (200)
    * succeeded/failed -> 409, terminal state is preserved
    """
    store = _store(request)
    status = store.request_cancel(job_id)
    if status is None:
        return JSONResponse(
            status_code=404, content={"error": {"code": "not_found", "message": f"job {job_id!r} not found"}}
        )
    job = store.get(job_id)
    if job is None:  # pragma: no cover - cannot happen within one request
        return JSONResponse(
            status_code=404, content={"error": {"code": "not_found", "message": f"job {job_id!r} not found"}}
        )
    if status == CANCELLED:
        return JSONResponse(status_code=200, content=_job_view(job))
    if status in (SUCCEEDED, FAILED):
        return JSONResponse(
            status_code=409,
            content={
                "error": {
                    "code": "job_terminal",
                    "message": f"job already finished with status {status!r}; terminal state cannot be cancelled",
                }
            },
        )
    # running: cancellation will be honoured cooperatively
    return JSONResponse(status_code=202, content=_job_view(job))


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
