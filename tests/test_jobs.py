"""Tests for the asynchronous job API, SQLite persistence and the worker."""

from __future__ import annotations

import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from app.jobs import QUEUED, RUNNING, JobStore
from app.main import app


# An unsatisfiable dependency chain forces heavy backtracking
# (~6.4k candidate evaluations, roughly a second on a normal machine),
# long enough to observe a running job and cancel it.
SLOW_N, SLOW_M = 7, 8


def slow_payload() -> dict:
    packages = {}
    for i in range(SLOW_N):
        packages[f"p{i}"] = {
            f"{v}.0": {"dependencies": {f"p{i+1}": f">={v}"}}
            for v in range(1, SLOW_M + 1)
        }
    packages[f"p{SLOW_N}"] = {}
    return {"packages": packages, "root": {"p0": ""}}


SIMPLE = {"packages": {"x": {"1.0": {}, "2.0": {}}}, "root": {"x": ""}}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("RESOLVER_DB", str(tmp_path / "jobs.db"))
    with TestClient(app) as c:
        yield c


def wait_for(client, job_id, *, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        body = client.get(f"/jobs/{job_id}").json()
        if body["status"] in ("succeeded", "failed", "cancelled"):
            return body
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} never finished: {body}")


def wait_until_status(client, job_id, status, *, timeout=5.0):
    deadline = time.monotonic() + timeout
    body = {}
    while time.monotonic() < deadline:
        body = client.get(f"/jobs/{job_id}").json()
        if body["status"] == status:
            return body
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} never reached {status!r}: {body}")


def test_post_job_returns_202_with_location_and_eventually_succeeds(client):
    r = client.post("/jobs", json=SIMPLE)
    assert r.status_code == 202
    assert r.headers["location"] == f"/jobs/{r.json()['id']}"
    job = wait_for(client, r.json()["id"])
    assert job["status"] == "succeeded"
    assert job["response_status"] == 200
    assert job["response"]["resolved"] == {"x": "2.0"}
    assert job["attempts"] == 1
    assert job["finished_at"] is not None


def test_job_preserves_conflict_response_status_and_body(client):
    payload = {
        "packages": {
            "a": {"1.0": {"dependencies": {"x": ">=2.0"}}},
            "b": {"1.0": {"dependencies": {"x": "<2.0"}}},
            "x": {"1.0": {}, "2.0": {}},
        },
        "root": ["a", "b"],
    }
    jid = client.post("/jobs", json=payload).json()["id"]
    job = wait_for(client, jid)
    assert job["status"] == "succeeded"
    assert job["response_status"] == 409
    assert job["response"]["status"] == "conflict"


def test_invalid_input_rejected_before_queueing(client):
    r = client.post("/jobs", json={"packages": {"x": {"bad-version": {}}}, "root": {"x": ""}})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_request"

    # Extra fields are rejected by pydantic the same way as on /resolve.
    r = client.post("/jobs", json={**SIMPLE, "unexpected": 1})
    assert r.status_code == 422


def test_get_missing_job_and_delete_missing_job_are_404(client):
    assert client.get("/jobs/does-not-exist").status_code == 404
    assert client.delete("/jobs/does-not-exist").status_code == 404


def test_cancel_running_job_stops_at_candidate_boundary(client):
    jid = client.post("/jobs", json=slow_payload()).json()["id"]

    # Wait until the worker has claimed it.
    assert wait_until_status(client, jid, RUNNING)["status"] == RUNNING

    r = client.delete(f"/jobs/{jid}")
    assert r.status_code == 202
    assert r.json()["status"] == RUNNING
    assert r.json()["cancel_requested"] is True

    job = wait_for(client, jid, timeout=10)
    assert job["status"] == "cancelled"
    # Cancellation lands between candidate evaluations, never overwrites
    # with a result, and records how far the search got.
    assert "response" not in job
    assert job["attempts"] is not None
    assert job["attempts"] >= 0
    assert job["finished_at"] is not None


def test_cancelled_job_is_terminal_and_idempotent(client):
    jid = client.post("/jobs", json=slow_payload()).json()["id"]
    wait_until_status(client, jid, RUNNING)
    client.delete(f"/jobs/{jid}")
    job = wait_for(client, jid)
    assert job["status"] == "cancelled"

    # Repeated DELETE is a 200 no-op and cannot change the terminal state.
    assert client.delete(f"/jobs/{jid}").status_code == 200
    time.sleep(0.3)
    assert client.get(f"/jobs/{jid}").json()["status"] == "cancelled"


def test_cancel_queued_job_is_immediate(client):
    # Occupy the single worker with the slow job.
    running_id = client.post("/jobs", json=slow_payload()).json()["id"]
    wait_until_status(client, running_id, RUNNING)

    queued_id = client.post("/jobs", json=SIMPLE).json()["id"]
    time.sleep(0.1)
    assert client.get(f"/jobs/{queued_id}").json()["status"] == QUEUED

    r = client.delete(f"/jobs/{queued_id}")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"
    time.sleep(0.2)
    assert client.get(f"/jobs/{queued_id}").json()["status"] == "cancelled"

    # The running job must be unaffected.
    assert client.get(f"/jobs/{running_id}").json()["status"] == RUNNING
    client.delete(f"/jobs/{running_id}")
    wait_for(client, running_id)


def test_cancel_finished_job_is_409_and_preserves_state(client):
    jid = client.post("/jobs", json=SIMPLE).json()["id"]
    job = wait_for(client, jid)
    assert job["status"] == "succeeded"

    r = client.delete(f"/jobs/{jid}")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "job_terminal"
    assert client.get(f"/jobs/{jid}").json()["status"] == "succeeded"


def test_jobs_claimed_in_fifo_order(tmp_path):
    store = JobStore(str(tmp_path / "fifo.db"))
    ids = [store.enqueue(SIMPLE)["id"] for _ in range(3)]
    claimed = []
    while True:
        job = store.claim_next()
        if job is None:
            break
        claimed.append(job["id"])
    assert claimed == ids
    store.close()


def test_claim_is_atomic_with_begin_immediate(tmp_path):
    # Many threads claiming concurrently: exactly one wins the job.  This is
    # the guarantee the BEGIN IMMEDIATE transaction provides.
    import threading

    path = str(tmp_path / "a.db")
    s1 = JobStore(path)
    jid = s1.enqueue(SIMPLE)["id"]
    winners: list[str] = []
    barrier = threading.Barrier(8)

    def attempt(store):
        barrier.wait()
        job = store.claim_next()
        if job is not None:
            winners.append(job["id"])

    stores = [JobStore(path) for _ in range(8)]
    threads = [threading.Thread(target=attempt, args=(s,)) for s in stores]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert winners == [jid]
    # After the win, the queue is empty for everyone.
    assert all(s.claim_next() is None for s in stores)
    for s in stores:
        s.close()
    s1.close()


def test_terminal_state_cannot_be_overwritten_by_worker_finalize(tmp_path):
    store = JobStore(str(tmp_path / "t.db"))
    jid = store.enqueue(SIMPLE)["id"]
    assert store.request_cancel(jid) == "cancelled"
    # finalize only transitions running rows; a cancelled queued row is a
    # terminal state the worker cannot overwrite with a result.
    written = store.finalize(jid, response={"ok": 1}, response_status=200)
    assert written is None
    job = store.get(jid)
    assert job["status"] == "cancelled"
    assert job["response"] is None
    assert job["response_status"] is None
    assert job["error"] is None
    assert job["finished_at"] is not None
    store.close()


def test_request_cancel_running_race_after_claim_returns_running(tmp_path):
    store = JobStore(str(tmp_path / "r.db"))
    jid = store.enqueue(SIMPLE)["id"]
    claimed = store.claim_next()
    assert claimed["status"] == RUNNING
    assert store.request_cancel(jid) == RUNNING
    job = store.get(jid)
    assert job["status"] == RUNNING
    assert job["cancel_requested"] is True
    # The store, not the caller, decides cancellation inside the finalize
    # transaction from the persisted flag.
    assert store.finalize(jid, attempts=42) == "cancelled"
    assert store.get(jid)["status"] == "cancelled"
    assert store.get(jid)["attempts"] == 42
    store.close()


# ---------------------------------------------------------------------------
# Deterministic cancel/finish interleaving tests.
#
# Both racy orders are pinned with threading.Event instead of sleeps: the two
# sides run on real threads against two JobStore instances (two SQLite
# connections, as the API and the worker are), and one side blocks on an
# event until the other side has *committed*, fixing the linearisation point.
# ---------------------------------------------------------------------------


def _claimed_store(path):
    store = JobStore(path)
    jid = store.enqueue(SIMPLE)["id"]
    assert store.claim_next()["status"] == RUNNING
    return store, jid


def test_cancel_committed_first_forces_cancelled_with_no_result(tmp_path):
    """DELETE commits cancel_requested=1 while running; the worker then
    submits a successful result anyway. The finalize transaction must
    observe the flag and atomically write cancelled with all result
    columns NULL."""
    import threading

    path = str(tmp_path / "cancel_first.db")
    worker, jid = _claimed_store(path)
    api = JobStore(path)
    outcome: dict = {}
    cancel_committed = threading.Event()

    def cancel_side():
        outcome["cancel"] = api.request_cancel(jid)
        cancel_committed.set()

    def finish_side():
        assert cancel_committed.wait(timeout=5)
        outcome["finish"] = worker.finalize(
            jid,
            response={"status": "ok", "resolved": {"x": "2.0"}},
            response_status=200,
            attempts=7,
        )

    t1 = threading.Thread(target=cancel_side)
    t2 = threading.Thread(target=finish_side)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)
    assert not t1.is_alive() and not t2.is_alive()

    assert outcome["cancel"] == RUNNING  # DELETE answered 202
    assert outcome["finish"] == "cancelled"
    job = api.get(jid)
    assert job["status"] == "cancelled"
    assert job["cancel_requested"] is True
    assert job["response"] is None
    assert job["response_status"] is None
    assert job["error"] is None
    # Cancellation may still record how far the search got.
    assert job["attempts"] == 7
    assert job["finished_at"] is not None
    # A later DELETE is the idempotent 200 path, not a resurrection.
    assert api.request_cancel(jid) == "cancelled"
    worker.close()
    api.close()


def test_cancel_committed_first_forces_cancelled_with_no_error(tmp_path):
    """Same interleaving, but the worker submits a *failed* result. The
    error must be discarded together with any response columns."""
    import threading

    path = str(tmp_path / "cancel_first_fail.db")
    worker, jid = _claimed_store(path)
    api = JobStore(path)
    outcome: dict = {}
    cancel_committed = threading.Event()

    def cancel_side():
        outcome["cancel"] = api.request_cancel(jid)
        cancel_committed.set()

    def finish_side():
        assert cancel_committed.wait(timeout=5)
        outcome["finish"] = worker.finalize(
            jid,
            response={"status": "ok"},
            response_status=200,
            error={"code": "internal_error", "message": "boom"},
            attempts=3,
        )

    t1 = threading.Thread(target=cancel_side)
    t2 = threading.Thread(target=finish_side)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert outcome["cancel"] == RUNNING
    assert outcome["finish"] == "cancelled"
    job = api.get(jid)
    assert job["status"] == "cancelled"
    assert job["response"] is None
    assert job["response_status"] is None
    assert job["error"] is None
    assert job["attempts"] == 3
    worker.close()
    api.close()


def test_finish_committed_first_later_delete_is_terminal_409(tmp_path):
    """The worker's terminal state commits first; the later DELETE must
    observe the terminal status (the API maps that to 409) and the result
    must be preserved verbatim."""
    import threading

    path = str(tmp_path / "finish_first.db")
    worker, jid = _claimed_store(path)
    api = JobStore(path)
    outcome: dict = {}
    finish_committed = threading.Event()

    def finish_side():
        outcome["finish"] = worker.finalize(
            jid,
            response={"status": "ok", "resolved": {"x": "2.0"}},
            response_status=200,
            attempts=1,
        )
        finish_committed.set()

    def cancel_side():
        assert finish_committed.wait(timeout=5)
        outcome["cancel"] = api.request_cancel(jid)

    t1 = threading.Thread(target=finish_side)
    t2 = threading.Thread(target=cancel_side)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert outcome["finish"] == "succeeded"
    # This is exactly the predicate the DELETE endpoint maps to HTTP 409.
    assert outcome["cancel"] == "succeeded"
    job = api.get(jid)
    assert job["status"] == "succeeded"
    assert job["response"] == {"status": "ok", "resolved": {"x": "2.0"}}
    assert job["response_status"] == 200
    assert job["error"] is None
    worker.close()
    api.close()


@pytest.mark.parametrize(
    "result",
    [
        # worker submits a success after its last cancel boundary check
        ({"status": "ok", "resolved": {"x": "2.0"}}, 200, None, 1),
        # worker submits a failure after its last cancel boundary check
        ({"error": {"code": "internal_error", "message": "boom"}}, 500,
         {"code": "internal_error", "message": "boom"}, 2),
    ],
)
def test_worker_cancel_after_last_boundary_check_wins_over_submitted_result(
    tmp_path, result
):
    """End-to-end through the real JobWorker: the resolver passes its final
    ``should_cancel()`` boundary check, DELETE then commits
    cancel_requested=1 while the job is running, and the runner returns
    success/failure regardless. The persisted terminal state must be
    cancelled with no response/response_status/error."""
    import threading

    from app.jobs import JobWorker

    store = JobStore(str(tmp_path / "worker_race.db"))
    at_last_check = threading.Event()
    proceed = threading.Event()
    observed: dict = {}

    def runner(_payload, should_cancel):
        # The very last cooperative check before returning: not cancelled.
        observed["checked"] = should_cancel()
        at_last_check.set()
        # Block until DELETE has committed its flag, then submit the result.
        assert proceed.wait(timeout=5)
        return result

    worker = JobWorker(store, runner)
    jid = store.enqueue(SIMPLE)["id"]
    worker.start()
    try:
        assert at_last_check.wait(timeout=5)
        assert observed["checked"] is False
        # DELETE lands strictly after the last check and before finalize.
        assert store.request_cancel(jid) == RUNNING
        assert store.get(jid)["cancel_requested"] is True
        proceed.set()
    finally:
        proceed.set()
        worker.stop()
        store.close()

    # Reopen to also prove the terminal state is what got persisted.
    checker = JobStore(str(tmp_path / "worker_race.db"))
    try:
        job = checker.get(jid)
        assert job["status"] == "cancelled"
        assert job["response"] is None
        assert job["response_status"] is None
        assert job["error"] is None
        assert job["attempts"] == result[3]
        assert job["finished_at"] is not None
    finally:
        checker.close()


def test_worker_finish_first_then_delete_preserves_result(tmp_path):
    """End-to-end through the real JobWorker._process for the opposite
    order: the runner returns, finalize commits succeeded, and the later
    cancel request reports the terminal status (API => 409) with the result
    preserved.  ``_process`` is synchronous, so the order is pinned without
    any thread or sleep."""
    from app.jobs import JobWorker

    store = JobStore(str(tmp_path / "worker_finish_first.db"))

    def runner(_payload, should_cancel):
        assert should_cancel() is False
        return {"status": "ok", "resolved": {"x": "2.0"}}, 200, None, 1

    worker = JobWorker(store, runner)
    jid = store.enqueue(SIMPLE)["id"]
    claimed = store.claim_next()
    assert claimed["status"] == RUNNING
    # No DELETE before/during the run: the terminal state commits first.
    worker._process(claimed)
    assert store.get_status(jid) == "succeeded"
    assert store.request_cancel(jid) == "succeeded"
    job = store.get(jid)
    assert job["status"] == "succeeded"
    assert job["response"]["resolved"] == {"x": "2.0"}
    assert job["response_status"] == 200
    assert job["error"] is None
    store.close()


def test_stale_running_jobs_requeued_on_startup(tmp_path, monkeypatch):
    path = str(tmp_path / "jobs.db")
    seed = JobStore(path)
    stale = seed.enqueue(SIMPLE)["id"]
    flagged = seed.enqueue(SIMPLE)["id"]
    queued = seed.enqueue(SIMPLE)["id"]
    done = seed.enqueue(SIMPLE)["id"]
    con = sqlite3.connect(path)
    con.execute("UPDATE jobs SET status='running' WHERE id=?", (stale,))
    con.execute(
        "UPDATE jobs SET status='running', cancel_requested=1 WHERE id=?", (flagged,)
    )
    con.execute(
        "UPDATE jobs SET status='succeeded', response=?, response_status=200 WHERE id=?",
        ('{"status":"ok"}', done),
    )
    con.commit()
    con.close()
    seed.close()

    monkeypatch.setenv("RESOLVER_DB", path)
    with TestClient(app) as client:
        assert wait_for(client, stale)["status"] == "succeeded"
        assert wait_for(client, queued)["status"] == "succeeded"
        assert client.get(f"/jobs/{flagged}").json()["status"] == "cancelled"
        assert client.get(f"/jobs/{done}").json()["status"] == "succeeded"


def test_jobs_persist_across_worker_store_restarts(tmp_path, monkeypatch):
    path = str(tmp_path / "persist.db")
    store = JobStore(path)
    jid = store.enqueue(SIMPLE)["id"]
    store.close()

    # A fresh store (new process) sees the queued row and processes it.
    monkeypatch.setenv("RESOLVER_DB", path)
    with TestClient(app) as client:
        job = wait_for(client, jid)
    assert job["response"]["resolved"] == {"x": "2.0"}

    # And the terminal result survives another restart.
    with TestClient(app) as client:
        again = client.get(f"/jobs/{jid}").json()
    assert again["status"] == "succeeded"
    assert again["response"]["resolved"] == {"x": "2.0"}


def test_db_file_is_created_on_disk(tmp_path, monkeypatch):
    path = tmp_path / "nested" / "dir" / "jobs.db"
    monkeypatch.setenv("RESOLVER_DB", str(path))
    with TestClient(app):
        assert path.exists()


def test_sync_resolve_still_available_alongside_jobs(client):
    r = client.post("/resolve", json=SIMPLE)
    assert r.status_code == 200
    assert r.json()["resolved"] == {"x": "2.0"}


def test_worker_runner_marks_cancelled_when_flag_set_mid_run(tmp_path):
    # Direct worker/runner integration with a controllable cancel flag.
    from app.main import run_resolution_job

    calls = {"n": 0}

    def should_cancel():
        calls["n"] += 1
        return calls["n"] == 3

    with pytest.raises(BaseException) as excinfo:
        run_resolution_job(slow_payload(), should_cancel)
    assert excinfo.value.attempts is not None
