"""Tests for ops-024 (cluster utilization efficiency) streaming exemption.

Continuous-trigger jobs and Lakeflow Declarative Pipelines keep their clusters up
24/7 by design, so they must not be flagged as always-on waste.
"""

from wal_e.collectors.system_tables import SystemTablesCollector
from wal_e.framework.scoring import _score_ops_024


def _data(uptime, continuous=None):
    ch = {
        "available": True,
        "cluster_uptime": uptime,
        "total_running_hours_30d": sum(c["running_hours"] for c in uptime),
    }
    if continuous is not None:
        ch["continuous_job_clusters"] = continuous
    return {"SystemTablesCollector": {"available": True, "compute_history": ch}}


def test_interactive_always_on_still_flagged():
    data = _data([{"cluster_id": "a", "cluster_name": "shared", "cluster_source": "UI", "running_hours": 700}])
    score, note = _score_ops_024(data)
    assert score == 0
    assert "shared" in note


def test_continuous_job_cluster_not_flagged():
    data = _data(
        [
            {"cluster_id": "j1", "cluster_name": "job-1-run-9", "cluster_source": "JOB", "running_hours": 720},
            {"cluster_id": "b", "cluster_name": "adhoc", "cluster_source": "UI", "running_hours": 40},
        ],
        continuous=[{"cluster_id": "j1", "job_id": "1"}],
    )
    score, note = _score_ops_024(data)
    assert score == 2
    assert "1 cluster(s) run 24/7 by design" in note


def test_pipeline_cluster_not_flagged():
    data = _data([{"cluster_id": "p1", "cluster_name": "dlt-execution-x", "cluster_source": "PIPELINE", "running_hours": 720}])
    score, note = _score_ops_024(data)
    assert score == 2
    assert "by design" in note


def test_non_continuous_job_cluster_still_flagged():
    data = _data(
        [{"cluster_id": "j2", "cluster_name": "job-2-run-1", "cluster_source": "JOB", "running_hours": 720}],
        continuous=[],
    )
    score, _ = _score_ops_024(data)
    assert score == 0


def test_continuous_job_on_all_purpose_cluster_still_flagged():
    data = _data(
        [{"cluster_id": "u1", "cluster_name": "stream-ui", "cluster_source": "UI", "running_hours": 720}],
        continuous=[{"cluster_id": "u1", "job_id": "3"}],
    )
    score, _ = _score_ops_024(data)
    assert score == 0


def test_streaming_excluded_from_average():
    uptime = [
        {"cluster_id": f"j{i}", "cluster_name": f"job-{i}", "cluster_source": "JOB", "running_hours": 480}
        for i in range(3)
    ] + [{"cluster_id": "b", "cluster_name": "adhoc", "cluster_source": "UI", "running_hours": 20}]
    data = _data(uptime, continuous=[{"cluster_id": f"j{i}", "job_id": str(i)} for i in range(3)])
    score, note = _score_ops_024(data)
    assert score == 2
    assert "avg 20h" in note


def test_continuous_query_scoped_and_uses_trigger_type():
    c = SystemTablesCollector("DEFAULT", "wh123", cloud_provider="aws")
    c.workspace_id = "42"
    seen: list[tuple[str, str]] = []

    def fake_run_sql(sql, label=""):
        seen.append((label, sql))
        return [], True

    c._run_sql = fake_run_sql  # type: ignore[assignment]
    c._collect_compute_history()
    by_label = dict(seen)
    sql = by_label["compute-continuous-job-clusters-30d"]
    assert "trigger_type = 'CONTINUOUS'" in sql
    assert sql.count("CAST(workspace_id AS STRING) = '42'") == 2
    assert "cluster_source" in by_label["compute-cluster-uptime-30d"]
