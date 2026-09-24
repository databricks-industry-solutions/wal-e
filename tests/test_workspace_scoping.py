"""Tests for deep-scan workspace scoping.

System tables are account-global, so every system-table query must be filtered to
the assessed workspace's id. These tests cover id resolution (Azure host parse and
system.access.workspaces_latest lookup) and that the filter is injected into the
queries.
"""

from wal_e.collectors import system_tables as st
from wal_e.collectors.system_tables import SystemTablesCollector


def _collector(host="", cloud="azure"):
    return SystemTablesCollector(
        "DEFAULT", "wh123", cloud_provider=cloud, workspace_host=host
    )


class _FakeResp:
    """Minimal urlopen context-manager stand-in with a headers mapping."""

    def __init__(self, headers):
        self.headers = headers

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _capture(collector):
    """Monkeypatch _run_sql to record every SQL statement it is handed."""
    seen: list[str] = []

    def fake_run_sql(sql, label=""):
        seen.append(sql)
        return [], True

    collector._run_sql = fake_run_sql  # type: ignore[assignment]
    return seen


def test_resolve_workspace_id_from_azure_host():
    c = _collector(host="https://adb-2548836972759138.18.azuredatabricks.net")
    assert c._resolve_workspace_id() == "2548836972759138"


def test_resolve_workspace_id_azure_host_no_scheme():
    c = _collector(host="adb-1653573648247579.11.azuredatabricks.net/")
    assert c._resolve_workspace_id() == "1653573648247579"


def test_resolve_workspace_id_falls_back_to_workspaces_latest():
    c = _collector(host="https://dbc-abc123.cloud.databricks.com", cloud="aws")
    c._resolve_via_org_id_header = lambda: ""  # type: ignore[assignment]

    def fake_run_sql(sql, label=""):
        assert "system.access.workspaces_latest" in sql
        assert "dbc-abc123.cloud.databricks.com" in sql
        return [{"workspace_id": "987654321"}], True

    c._run_sql = fake_run_sql  # type: ignore[assignment]
    assert c._resolve_workspace_id() == "987654321"


def test_resolve_workspace_id_empty_when_lookup_misses():
    c = _collector(host="https://dbc-abc123.cloud.databricks.com", cloud="aws")
    c._resolve_via_org_id_header = lambda: ""  # type: ignore[assignment]
    c._run_sql = lambda sql, label="": ([], True)  # type: ignore[assignment]
    assert c._resolve_workspace_id() == ""


def test_resolve_workspace_id_rejects_non_numeric_lookup():
    c = _collector(host="https://dbc-abc123.cloud.databricks.com", cloud="aws")
    c._resolve_via_org_id_header = lambda: ""  # type: ignore[assignment]
    c._run_sql = lambda sql, label="": ([{"workspace_id": "not-a-number"}], True)  # type: ignore[assignment]
    assert c._resolve_workspace_id() == ""


def test_resolve_via_org_id_header_success(monkeypatch):
    c = _collector(host="https://vanity.example.com", cloud="aws")
    c._mint_token = lambda: "sekret-token"  # type: ignore[assignment]
    monkeypatch.setattr(
        st.urllib.request, "urlopen",
        lambda req, timeout=30: _FakeResp({"X-Databricks-Org-Id": "1444828305810485"}),
    )
    assert c._resolve_via_org_id_header() == "1444828305810485"


def test_resolve_via_org_id_header_no_token_skips_call(monkeypatch):
    c = _collector(host="https://vanity.example.com", cloud="aws")
    c._mint_token = lambda: ""  # type: ignore[assignment]

    def _boom(*a, **k):
        raise AssertionError("urlopen must not run without a token")

    monkeypatch.setattr(st.urllib.request, "urlopen", _boom)
    assert c._resolve_via_org_id_header() == ""


def test_org_id_header_used_for_vanity_url(monkeypatch):
    c = _collector(host="https://vanity.example.com", cloud="aws")
    c._mint_token = lambda: "tok"  # type: ignore[assignment]
    monkeypatch.setattr(
        st.urllib.request, "urlopen",
        lambda req, timeout=30: _FakeResp({"X-Databricks-Org-Id": "42"}),
    )

    def _no_sql(sql, label=""):
        raise AssertionError("SQL fallback should not run when the header resolves")

    c._run_sql = _no_sql  # type: ignore[assignment]
    assert c._resolve_workspace_id() == "42"


def test_org_id_resolution_never_logs_token(monkeypatch):
    c = _collector(host="https://vanity.example.com", cloud="aws")
    c._mint_token = lambda: "super-secret-token-value"  # type: ignore[assignment]
    monkeypatch.setattr(
        st.urllib.request, "urlopen",
        lambda req, timeout=30: _FakeResp({"X-Databricks-Org-Id": "42"}),
    )
    c._resolve_via_org_id_header()
    blob = " ".join(
        " ".join(e.command) + " " + (e.raw_output or "") + " " + (e.error or "")
        for e in c.audit_entries
    )
    assert "super-secret-token-value" not in blob
    assert "Bearer" not in blob
    assert any("X-Databricks-Org-Id" in " ".join(e.command) for e in c.audit_entries)


def test_ws_filter_empty_when_unresolved():
    c = _collector()
    assert c.workspace_id == ""
    assert c._ws_filter() == ""


def test_ws_filter_predicate_when_resolved():
    c = _collector()
    c.workspace_id = "12345"
    assert c._ws_filter() == " AND CAST(workspace_id AS STRING) = '12345'"
    assert c._ws_filter("nt.workspace_id") == " AND CAST(nt.workspace_id AS STRING) = '12345'"


def test_billing_queries_scoped_when_resolved():
    c = _collector()
    c.workspace_id = "55555"
    seen = _capture(c)
    c._collect_billing()
    assert seen, "expected billing queries to run"
    assert all("workspace_id AS STRING) = '55555'" in sql for sql in seen)


def test_audit_queries_scoped_when_resolved():
    c = _collector()
    c.workspace_id = "55555"
    seen = _capture(c)
    c._collect_audit_events()
    assert seen
    assert all("55555" in sql for sql in seen)


def test_queries_unscoped_when_unresolved():
    c = _collector()
    seen = _capture(c)
    c._collect_billing()
    assert seen
    assert all("CAST(workspace_id AS STRING)" not in sql for sql in seen)


def test_autoterm_query_scoped_on_clusters_and_node_timeline():
    c = _collector(cloud="aws")
    c.workspace_id = "42"
    seen = _capture(c)
    c._collect_autoterm_savings()
    sql = seen[0]
    assert "CAST(workspace_id AS STRING) = '42'" in sql  # clusters + billing CTEs
    assert "CAST(nt.workspace_id AS STRING) = '42'" in sql  # node_timeline CTEs


def test_collect_records_scoping_flag():
    c = _collector(host="https://adb-2548836972759138.18.azuredatabricks.net")
    # Every query (connectivity, resolve, and collectors) returns empty rows OK.
    c._run_sql = lambda sql, label="": ([{"workspace_id": "2548836972759138"}] if label == "resolve-workspace-id" else [], True)  # type: ignore[assignment]
    findings = c.collect()
    assert findings["workspace_id"] == "2548836972759138"
    assert findings["workspace_scoped"] is True
