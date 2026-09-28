"""End-to-end tests for POST /audit/licenses."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _audit(**payload):
    response = client.post("/audit/licenses", json=payload)
    return response.status_code, response.json()


def _by_name(body):
    return {entry["name"]: entry for entry in body["results"]}


RESOLVED = {"app": "1.0", "web": "2.0", "db": "1.5", "util": "0.9"}


def test_basic_status_buckets_sorted_by_name():
    status, body = _audit(
        resolved=RESOLVED,
        licenses={
            "web": "MIT",
            "db": "GPL-3.0-only",
            "util": "Some-Custom-License",
            # "app" has no entry -> missing
        },
        allowed=["MIT"],
        denied=["GPL-3.0-only"],
    )
    assert status == 200
    assert body["status"] == "ok"
    assert body["summary"] == {
        "packages": 4,
        "violation": 1,
        "compliant": 1,
        "unknown": 1,
        "missing": 1,
    }
    # Stable ordering by normalized package name everywhere.
    assert [entry["name"] for entry in body["results"]] == ["app", "db", "util", "web"]
    assert body["violation"] == ["db"]
    assert body["compliant"] == ["web"]
    assert body["unknown"] == ["util"]
    assert body["missing"] == ["app"]

    entries = _by_name(body)
    assert entries["app"] == {
        "name": "app",
        "version": "1.0",
        "status": "missing",
        "expression": None,
        "decisive": [],
    }
    assert entries["web"]["status"] == "compliant"
    assert entries["web"]["expression"] == "MIT"
    assert entries["web"]["decisive"] == ["MIT"]
    assert entries["db"]["status"] == "violation"
    assert entries["db"]["decisive"] == ["GPL-3.0-only"]
    assert entries["util"]["status"] == "unknown"
    assert entries["util"]["decisive"] == ["Some-Custom-License"]


def test_and_semantics_and_decisive_identifiers():
    # Any denied operand -> violation; decisive lists only the denied ones.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "MIT AND GPL-3.0-only AND Some-Custom"},
        allowed=["MIT"],
        denied=["GPL-3.0-only"],
    )
    assert status == 200
    (entry,) = body["results"]
    assert entry["status"] == "violation"
    assert entry["decisive"] == ["GPL-3.0-only"]

    # No denied, at least one unknown -> unknown.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "MIT AND Some-Custom"},
        allowed=["MIT"],
    )
    (entry,) = body["results"]
    assert entry["status"] == "unknown"
    assert entry["decisive"] == ["Some-Custom"]

    # All allowed -> compliant, every identifier is decisive.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "MIT AND Apache-2.0"},
        allowed=["MIT", "Apache-2.0"],
    )
    (entry,) = body["results"]
    assert entry["status"] == "compliant"
    assert entry["decisive"] == ["Apache-2.0", "MIT"]


def test_or_semantics_and_decisive_identifiers():
    # Any compliant operand -> compliant; decisive lists only the allowed ones.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "GPL-3.0-only OR MIT OR Some-Custom"},
        allowed=["MIT"],
        denied=["GPL-3.0-only"],
    )
    (entry,) = body["results"]
    assert entry["status"] == "compliant"
    assert entry["decisive"] == ["MIT"]

    # No compliant, at least one unknown -> unknown.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "GPL-3.0-only OR Some-Custom"},
        denied=["GPL-3.0-only"],
    )
    (entry,) = body["results"]
    assert entry["status"] == "unknown"
    assert entry["decisive"] == ["Some-Custom"]

    # All denied -> violation, every denied identifier is decisive.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "GPL-3.0-only OR AGPL-3.0-only"},
        denied=["GPL-3.0-only", "AGPL-3.0-only"],
    )
    (entry,) = body["results"]
    assert entry["status"] == "violation"
    assert entry["decisive"] == ["AGPL-3.0-only", "GPL-3.0-only"]


def test_parentheses_and_precedence():
    # OR binds looser than AND: MIT OR (GPL AND Apache).
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "(MIT OR GPL-3.0-only) AND Apache-2.0"},
        allowed=["MIT", "Apache-2.0"],
        denied=["GPL-3.0-only"],
    )
    (entry,) = body["results"]
    # (MIT OR GPL) is compliant via MIT; AND Apache-2.0 keeps it compliant.
    assert entry["status"] == "compliant"
    assert entry["decisive"] == ["Apache-2.0", "MIT"]
    assert entry["expression"] == "(MIT OR GPL-3.0-only) AND Apache-2.0"


def test_with_is_judged_like_and():
    # Exception denied -> the whole WITH is a violation.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "GPL-2.0-only WITH Classpath-exception-2.0"},
        allowed=["GPL-2.0-only"],
        denied=["Classpath-exception-2.0"],
    )
    (entry,) = body["results"]
    assert entry["status"] == "violation"
    assert entry["decisive"] == ["Classpath-exception-2.0"]
    assert entry["expression"] == "GPL-2.0-only WITH Classpath-exception-2.0"

    # License and exception both allowed -> compliant.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "GPL-2.0-only WITH Classpath-exception-2.0"},
        allowed=["GPL-2.0-only", "Classpath-exception-2.0"],
    )
    (entry,) = body["results"]
    assert entry["status"] == "compliant"
    assert entry["decisive"] == ["Classpath-exception-2.0", "GPL-2.0-only"]

    # License denied, exception allowed -> violation decided by the license.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "GPL-2.0-only WITH Classpath-exception-2.0"},
        allowed=["Classpath-exception-2.0"],
        denied=["GPL-2.0-only"],
    )
    (entry,) = body["results"]
    assert entry["status"] == "violation"
    assert entry["decisive"] == ["GPL-2.0-only"]


def test_identifier_and_package_name_normalization():
    status, body = _audit(
        resolved={"My_Pkg": "1.0"},
        licenses={"my-pkg": "mit"},  # canonicalized name + SPDX key case
        allowed=["MIT"],
    )
    assert status == 200
    (entry,) = body["results"]
    assert entry["name"] == "my-pkg"
    assert entry["status"] == "compliant"
    assert entry["expression"] == "MIT"
    assert entry["decisive"] == ["MIT"]

    # allowed/denied entries are normalized through the same parser.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "Apache-2.0"},
        allowed=["apache-2.0"],
    )
    assert body["results"][0]["status"] == "compliant"


def test_denied_wins_over_allowed():
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "MIT"},
        allowed=["MIT"],
        denied=["MIT"],
    )
    assert body["results"][0]["status"] == "violation"


def test_license_entries_for_unresolved_packages_are_ignored():
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "MIT", "not-installed": "GPL-3.0-only"},
        allowed=["MIT"],
    )
    assert status == 200
    assert body["summary"]["packages"] == 1
    assert [entry["name"] for entry in body["results"]] == ["x"]


def test_invalid_expression_returns_400_without_partial_results():
    status, body = _audit(
        resolved={"good": "1.0", "bad": "1.0"},
        licenses={"good": "MIT", "bad": "MIT AND"},
        allowed=["MIT"],
    )
    assert status == 400
    assert body["error"]["code"] == "invalid_request"
    assert "bad" in body["error"]["message"]
    # No partial audit output.
    assert "results" not in body
    assert "compliant" not in body


def test_multiple_invalid_expressions_reported_together():
    status, body = _audit(
        resolved={"a": "1.0", "b": "1.0"},
        licenses={"a": "(MIT OR", "b": ""},
    )
    assert status == 400
    message = body["error"]["message"]
    assert "'a'" in message and "'b'" in message


def test_invalid_policy_entries_return_400():
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "MIT"},
        allowed=["MIT AND Apache-2.0"],  # expression, not a single identifier
    )
    assert status == 400
    assert "allowed" in body["error"]["message"]

    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": "MIT"},
        denied=["MIT OR"],
    )
    assert status == 400
    assert "denied" in body["error"]["message"]


def test_resolved_validation_is_reused():
    status, body = _audit(
        resolved={"x": "not-a-version"},
        licenses={"x": "MIT"},
    )
    assert status == 400
    assert "PEP 440" in body["error"]["message"]

    status, body = _audit(
        resolved={"<root>": "1.0"},
        licenses={},
    )
    assert status == 400


def test_licenses_mapping_validation():
    # Duplicate package after name normalization.
    status, body = _audit(
        resolved={"my-pkg": "1.0"},
        licenses={"My_Pkg": "MIT", "my-pkg": "Apache-2.0"},
    )
    assert status == 400
    assert "duplicates" in body["error"]["message"]

    # <root> is reserved.
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"<root>": "MIT"},
    )
    assert status == 400
    assert "reserved" in body["error"]["message"]


def test_extra_fields_rejected():
    response = client.post(
        "/audit/licenses",
        json={"resolved": {}, "licenses": {}, "unexpected": 1},
    )
    assert response.status_code == 422


def test_empty_policy_marks_everything_unknown_or_missing():
    status, body = _audit(
        resolved={"x": "1.0", "y": "2.0"},
        licenses={"x": "MIT OR Apache-2.0"},
    )
    assert status == 200
    entries = _by_name(body)
    assert entries["x"]["status"] == "unknown"
    assert entries["x"]["decisive"] == ["Apache-2.0", "MIT"]
    assert entries["y"]["status"] == "missing"


def test_deeply_nested_expression_evaluates():
    depth = 300
    expression = "MIT"
    for i in range(depth):
        operator = "AND" if i % 2 == 0 else "OR"
        expression = f"Apache-2.0 {operator} ({expression})"
    status, body = _audit(
        resolved={"x": "1.0"},
        licenses={"x": expression},
        allowed=["MIT", "Apache-2.0"],
    )
    assert status == 200
    assert body["results"][0]["status"] == "compliant"
