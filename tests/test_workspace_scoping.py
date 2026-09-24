"""Tests for deep-scan workspace scoping.

System tables are account-global, so every system-table query must be filtered to
the assessed workspace's id. These tests cover id resolution (Azure host parse and
system.access.workspaces_latest lookup) and that the filter is injected into the
queries.
"""

from wal_e.collectors.system_tables import SystemTablesCollector


def _collector(host="", cloud="azure"):
    return SystemTablesCollector(
        "DEFAULT", "wh123", cloud_provider=cloud, workspace_host=host
    )


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

    def fake_run_sql(sql, label=""):
        assert "system.access.workspaces_latest" in sql
        assert "dbc-abc123.cloud.databricks.com" in sql
        return [{"workspace_id": "987654321"}], True

    c._run_sql = fake_run_sql  # type: ignore[assignment]
    assert c._resolve_workspace_id() == "987654321"


def test_resolve_workspace_id_empty_when_lookup_misses():
    c = _collector(host="https://dbc-abc123.cloud.databricks.com", cloud="aws")
    c._run_sql = lambda sql, label="": ([], True)  # type: ignore[assignment]
    assert c._resolve_workspace_id() == ""


def test_resolve_workspace_id_rejects_non_numeric_lookup():
    c = _collector(host="https://dbc-abc123.cloud.databricks.com", cloud="aws")
    c._run_sql = lambda sql, label="": ([{"workspace_id": "not-a-number"}], True)  # type: ignore[assignment]
    assert c._resolve_workspace_id() == ""


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
