"""Persistent asynchronous resolution jobs backed by SQLite.

Job lifecycle::

    queued --(worker claim, BEGIN IMMEDIATE)--> running
    queued --(DELETE while queued)-----------> cancelled
    running --(worker finishes)--------------> succeeded | failed
    running --(DELETE while running)--[worker stops at the next
                candidate-evaluation boundary]--> cancelled

``succeeded``, ``failed`` and ``cancelled`` are terminal states and every
state transition is a conditional UPDATE, so a terminal row can never be
overwritten.

Linearised cancellation
-----------------------

``DELETE`` while a job is ``running`` and the worker's completion are
linearised by **commit order** of two ``BEGIN IMMEDIATE`` transactions:

* if the cancel request is committed first, the worker's finalising
  transaction observes ``cancel_requested = 1`` and atomically writes
  ``cancelled`` -- with ``response``, ``response_status`` and ``error``
  forced to NULL -- even if the resolver had already passed its last
  cooperative cancel check and hands a successful or failed result to the
  store;
* if the worker's terminal state is committed first, ``DELETE`` observes
  ``succeeded``/``failed`` and leaves the row untouched (HTTP 409).

The decision and the write happen in the same transaction; nothing is read
before opening it.

On startup, jobs left in ``running`` by a process that died (or was killed)
are returned to ``queued``; stale ``cancel_requested`` rows are finalised as
``cancelled`` immediately instead.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .resolver import ResolutionCancelled

QUEUED = "queued"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"

TERMINAL_STATES = (SUCCEEDED, FAILED, CANCELLED)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id               TEXT PRIMARY KEY,
    status           TEXT NOT NULL,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    payload          TEXT NOT NULL,
    response         TEXT,
    response_status  INTEGER,
    error            TEXT,
    attempts         INTEGER,
    created_at       TEXT NOT NULL,
    started_at       TEXT,
    finished_at      TEXT
)
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobStore:
    """SQLite-backed job table guarded by one connection and one lock.

    All operations are blocking but very short; the worker and the API
    access the store from different threads, hence ``check_same_thread`` is
    disabled and every call is serialized with ``self._lock``.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            directory = os.path.dirname(os.path.abspath(path))
            os.makedirs(directory, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # WAL lets API reads and worker writes coexist; a long busy timeout
        # makes lock contention wait rather than fail.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._conn:
            self._conn.executescript(_SCHEMA)
        self._cancel_events: dict[str, threading.Event] = {}

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # Lifecycle transitions
    # ------------------------------------------------------------------

    def enqueue(self, payload: dict[str, Any]) -> dict[str, Any]:
        job_id = uuid.uuid4().hex
        created_at = _utcnow()
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO jobs (id, status, payload, created_at)"
                " VALUES (?, ?, ?, ?)",
                (job_id, QUEUED, json.dumps(payload, ensure_ascii=False), created_at),
            )
        return self.get(job_id)  # type: ignore[return-value]

    def get(self, job_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return self._row_to_dict(row) if row is not None else None

    def claim_next(self) -> Optional[dict[str, Any]]:
        """Atomically claim the oldest queued job.

        ``BEGIN IMMEDIATE`` acquires the database write lock before the
        SELECT, so two workers can never claim the same row even if more
        workers are added later.
        """
        started_at = _utcnow()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM jobs WHERE status = ? ORDER BY rowid LIMIT 1",
                    (QUEUED,),
                ).fetchone()
                if row is None:
                    self._conn.execute("COMMIT")
                    return None
                self._conn.execute(
                    "UPDATE jobs SET status = ?, started_at = ? WHERE id = ?",
                    (RUNNING, started_at, row["id"]),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            claimed = dict(row)
            claimed["status"] = RUNNING
            claimed["started_at"] = started_at
            return self._row_to_dict(claimed)

    def request_cancel(self, job_id: str) -> Optional[str]:
        """Request cancellation. Returns the resulting state, or None if
        the job does not exist.

        * queued -> cancelled immediately (DELETE semantics)
        * running -> stays running with cancel_requested=1; the worker
          stops at the next candidate-evaluation boundary, or its finalising
          transaction sees the flag and writes cancelled atomically
        * cancelled -> cancelled (idempotent)
        * succeeded/failed -> unchanged terminal state

        The read of the current state and every write happen in one
        ``BEGIN IMMEDIATE`` transaction, so this call is one of the two
        linearisation points racing with :meth:`finalize`: whichever
        transaction commits first fixes the outcome.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT status, cancel_requested FROM jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                if row is None:
                    self._conn.execute("COMMIT")
                    return None
                status = row["status"]
                if status in (SUCCEEDED, FAILED):
                    # Terminal state committed first: preserve it so the
                    # API answers 409.
                    self._conn.execute("COMMIT")
                    return status
                if status == CANCELLED:
                    self._conn.execute("COMMIT")
                    return CANCELLED
                finished_at = _utcnow()
                if status == QUEUED:
                    self._conn.execute(
                        "UPDATE jobs SET status = ?, cancel_requested = 1,"
                        " finished_at = ? WHERE id = ? AND status = ?",
                        (CANCELLED, finished_at, job_id, QUEUED),
                    )
                    became_terminal = True
                else:  # running: persist the flag; the finalise txn decides
                    self._conn.execute(
                        "UPDATE jobs SET cancel_requested = 1"
                        " WHERE id = ? AND status = ?",
                        (job_id, RUNNING),
                    )
                    became_terminal = False
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        # Wake the in-process worker after the durable commit.
        self._fire_cancel_event(job_id)
        if became_terminal:
            self._cancel_events.pop(job_id, None)
            return CANCELLED
        return self.get_status(job_id)

    def _fire_cancel_event(self, job_id: str) -> None:
        event = self._cancel_events.get(job_id)
        if event is not None:
            event.set()

    def get_status(self, job_id: str) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT status FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return row["status"] if row is not None else None

    def is_cancel_requested(self, job_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT cancel_requested FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return bool(row and row["cancel_requested"])

    def finalize(
        self,
        job_id: str,
        *,
        response: Optional[dict[str, Any]] = None,
        response_status: Optional[int] = None,
        error: Optional[dict[str, Any]] = None,
        attempts: Optional[int] = None,
    ) -> Optional[str]:
        """Finish a running job in one ``BEGIN IMMEDIATE`` transaction.

        Cancellation priority is decided *inside* the transaction: if a
        cancel request committed first while the row was still ``running``,
        ``cancel_requested`` is 1 here and the terminal state is written as
        ``cancelled`` with ``response``, ``response_status`` and ``error``
        all forced to NULL -- even when the runner returned a result after
        its last cooperative cancel check.  Otherwise the supplied result is
        written as ``succeeded`` or ``failed``.

        Returns the terminal status written by this call
        (``cancelled``/``succeeded``/``failed``), or ``None`` if the row was
        already terminal.  Terminal rows are never overwritten.
        """
        finished_at = _utcnow()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT cancel_requested FROM jobs"
                    " WHERE id = ? AND status = ?",
                    (job_id, RUNNING),
                ).fetchone()
                if row is None:
                    # Already terminal (or gone): never overwrite.
                    self._conn.execute("COMMIT")
                    written: Optional[str] = None
                elif row["cancel_requested"]:
                    # The cancel txn committed first. Write the terminal
                    # state and clear every result column in this same txn,
                    # so no response/error can ever be observed on a
                    # cancelled job, regardless of what the runner returned.
                    self._conn.execute(
                        "UPDATE jobs"
                        " SET status = ?, response = NULL,"
                        "     response_status = NULL, error = NULL,"
                        "     attempts = COALESCE(?, attempts),"
                        "     finished_at = ?"
                        " WHERE id = ? AND status = ?",
                        (CANCELLED, attempts, finished_at, job_id, RUNNING),
                    )
                    self._conn.execute("COMMIT")
                    written = CANCELLED
                else:
                    new_status = FAILED if error is not None else SUCCEEDED
                    self._conn.execute(
                        "UPDATE jobs"
                        " SET status = ?, response = COALESCE(?, response),"
                        "     response_status = COALESCE(?, response_status),"
                        "     error = ?, attempts = COALESCE(?, attempts),"
                        "     finished_at = ?"
                        " WHERE id = ? AND status = ?",
                        (
                            new_status,
                            None
                            if response is None
                            else json.dumps(response, ensure_ascii=False),
                            response_status,
                            None
                            if error is None
                            else json.dumps(error, ensure_ascii=False),
                            attempts,
                            finished_at,
                            job_id,
                            RUNNING,
                        ),
                    )
                    self._conn.execute("COMMIT")
                    written = new_status
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        if written is not None:
            self._cancel_events.pop(job_id, None)
        return written

    def requeue_stale_running(self) -> int:
        """At startup, hand interrupted work back to the queue.

        running+cancel_requested becomes cancelled (the owner is gone and
        will never stop the job cooperatively); plain running becomes queued
        again so it is picked up in FIFO order.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET status = ?, finished_at = ?"
                " WHERE status = ? AND cancel_requested = 1",
                (CANCELLED, _utcnow(), RUNNING),
            )
            cancelled_count = cur.rowcount
            cur = self._conn.execute(
                "UPDATE jobs SET status = ?, started_at = NULL"
                " WHERE status = ? AND cancel_requested = 0",
                (QUEUED, RUNNING),
            )
            requeued = cur.rowcount
        return requeued + cancelled_count

    # ------------------------------------------------------------------
    # Cancel event registry used by the in-process worker
    # ------------------------------------------------------------------

    def bind_cancel_event(self, job_id: str) -> threading.Event:
        event = threading.Event()
        with self._lock:
            existing = self._cancel_events.get(job_id)
            if existing is not None:
                return existing
            # Close the bind/flag race: a DELETE that landed before this
            # registration could not fire the event, so consult the persisted
            # flag while holding the same lock that serializes request_cancel.
            if self.is_cancel_requested(job_id):
                event.set()
            self._cancel_events[job_id] = event
        return event

    def drop_cancel_event(self, job_id: str) -> None:
        with self._lock:
            self._cancel_events.pop(job_id, None)

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def _row_to_dict(self, row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        def get(key: str) -> Any:
            return row[key]

        job: dict[str, Any] = {
            "id": get("id"),
            "status": get("status"),
            "cancel_requested": bool(get("cancel_requested")),
            "attempts": get("attempts"),
            "created_at": get("created_at"),
            "started_at": get("started_at"),
            "finished_at": get("finished_at"),
        }
        payload = get("payload")
        job["request"] = json.loads(payload) if payload is not None else None
        response = get("response")
        if response is not None:
            job["response"] = json.loads(response)
            job["response_status"] = get("response_status")
        else:
            job["response"] = None
            job["response_status"] = None
        error = get("error")
        job["error"] = json.loads(error) if error is not None else None
        return job


class JobWorker:
    """Single background thread that claims and executes queued jobs."""

    def __init__(
        self,
        store: JobStore,
        runner: Callable[[dict[str, Any], Callable[[], bool]], tuple[Optional[dict[str, Any]], Optional[int], Optional[dict[str, Any]], Optional[int]]],
        *,
        poll_interval: float = 0.2,
    ) -> None:
        self._store = store
        self._runner = runner
        self._poll_interval = poll_interval
        self._wakeup = threading.Event()
        self._shutdown = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="job-worker", daemon=True
        )
        self._thread.start()

    def wake(self) -> None:
        self._wakeup.set()

    def stop(self) -> None:
        self._shutdown.set()
        self._wakeup.set()
        if self._thread is not None:
            # Don't stall shutdown on a long-running resolution; any job the
            # thread still owns stays "running" in SQLite and is requeued by
            # requeue_stale_running() on the next start.
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._shutdown.is_set():
            try:
                job = self._store.claim_next()
            except sqlite3.Error:
                time.sleep(self._poll_interval)
                continue
            if job is None:
                self._wakeup.wait(self._poll_interval)
                self._wakeup.clear()
                continue
            self._process(job)

    def _process(self, job: dict[str, Any]) -> None:
        job_id = job["id"]
        # A DELETE may have raced the claim transaction; honour it before
        # spending any work. This is only an optimisation: finalize()
        # re-checks the persisted flag inside its own transaction.
        if self._store.is_cancel_requested(job_id):
            self._store.finalize(job_id)
            return
        event = self._store.bind_cancel_event(job_id)
        cancelled_attempts: Optional[int] = None
        try:
            body, status_code, error, attempts = self._runner(
                job["request"], event.is_set
            )
        except ResolutionCancelled as exc:
            cancelled_attempts = exc.attempts
            body, status_code, error, attempts = None, None, None, exc.attempts
        except BaseException as exc:  # pragma: no cover - defensive
            # Whether this becomes failed or cancelled is decided inside the
            # finalize transaction by the persisted cancel_requested flag, so
            # a DELETE racing an unwinding runner still wins atomically.
            self._store.finalize(
                job_id,
                error={"code": "internal_error", "message": repr(exc)},
            )
            return
        # No pre-transaction cancel check here: the whole point of finalize()
        # is that cancel priority is resolved against the committed flag in
        # the same transaction that writes the terminal state. A cancel
        # committed after the resolver's last boundary check therefore still
        # yields cancelled (with no response/error), while a terminal state
        # committed first survives and makes the later DELETE answer 409.
        self._store.finalize(
            job_id,
            response=body,
            response_status=status_code,
            error=error,
            attempts=cancelled_attempts if cancelled_attempts is not None else attempts,
        )
