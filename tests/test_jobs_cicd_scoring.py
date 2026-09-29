"""Tests for CI/CD and automated-rollback detection on jobs (OPS_003, OPS_021).

Regression coverage for the false negative where every customer was flagged
"No Git-backed jobs -> no automated rollbacks". Root cause: /api/2.1/jobs/list
returns a truncated settings object that never contains git_source, and the
scoring ignored Databricks Asset Bundle deployments entirely.
"""

from wal_e.collectors.operations import OperationsCollector
from wal_e.framework.scoring import _score_ops_003, _score_ops_021


def _ops(jobs: list[dict]) -> dict:
    return {"OperationsCollector": {"job_count": len(jobs), "jobs": jobs}}


def test_ops021_bundle_job_is_full_rollback():
    data = _ops([{"deployment_kind": "BUNDLE", "is_cicd_managed": True}])
    score, notes = _score_ops_021(data)
    assert score == 2
    assert "Asset Bundles" in notes


def test_ops021_git_source_job_is_partial():
    data = _ops([{"has_git_source": True, "is_cicd_managed": True, "deployment_kind": None}])
    score, notes = _score_ops_021(data)
    assert score == 1
    assert "Git/CI-CD managed" in notes


def test_ops021_no_signal_is_zero():
    data = _ops([{"is_cicd_managed": False, "deployment_kind": None}])
    score, notes = _score_ops_021(data)
    assert score == 0
    assert "No CI/CD-managed jobs" in notes


def test_ops003_bundle_job_is_full_cicd():
    data = _ops([{"deployment_kind": "BUNDLE", "is_cicd_managed": True}])
    score, notes = _score_ops_003(data)
    assert score == 2
    assert "Asset Bundles" in notes


def test_ops003_no_jobs_is_zero():
    score, _ = _score_ops_003(_ops([]))
    assert score == 0


def test_scoring_backward_compatible_with_old_cached_jobs():
    # Old cached data has neither is_cicd_managed nor deployment_kind, only the
    # (always-false) has_git_source. Both checks must still return sane values.
    jobs = [{"has_git_source": False}]
    assert _score_ops_021(_ops(jobs))[0] == 0
    assert _score_ops_003(_ops(jobs))[0] == 1


# --- Collector-level behavior (pure summary + pagination/enrichment) ---


def test_summarize_job_detects_bundle_from_list_settings():
    job = {"job_id": 1, "creator_user_name": "a@b.com",
           "settings": {"name": "x", "deployment": {"kind": "BUNDLE"}, "edit_mode": "UI_LOCKED"}}
    summary = OperationsCollector._summarize_job(job, job["settings"])
    assert summary["deployment_kind"] == "BUNDLE"
    assert summary["is_cicd_managed"] is True
    assert summary["has_git_source"] is False


def test_summarize_job_task_level_retries_and_clusters():
    settings = {
        "name": "y",
        "tasks": [{"max_retries": 3, "existing_cluster_id": "c-1"}, {"max_retries": 1}],
        "job_clusters": [{"job_cluster_key": "main"}],
    }
    summary = OperationsCollector._summarize_job({"job_id": 2}, settings)
    assert summary["max_retries"] == 3
    assert summary["has_existing_cluster_id"] is True
    assert summary["has_job_clusters"] is True


def test_collect_jobs_paginates_and_enriches_git_source(monkeypatch):
    """Two list pages; a plain job (no list-side CI/CD signal) is enriched via
    jobs/get, which reveals git_source. Bundle jobs must NOT trigger a get."""
    page1 = {
        "jobs": [
            {"job_id": 10, "settings": {"name": "bundle", "deployment": {"kind": "BUNDLE"}}},
            {"job_id": 11, "settings": {"name": "plain"}},
        ],
        "has_more": True,
        "next_page_token": "TOK",
    }
    page2 = {"jobs": [{"job_id": 12, "settings": {"name": "plain2"}}], "has_more": False}
    get_calls: list[int] = []

    def fake_api(self, endpoint: str):
        if endpoint.startswith("/api/2.1/jobs/list"):
            return (page2 if "page_token=TOK" in endpoint else page1, True)
        if endpoint.startswith("/api/2.1/jobs/get"):
            jid = int(endpoint.split("job_id=")[1])
            get_calls.append(jid)
            # job 11 is actually Git-backed; job 12 is not
            gs = {"provider": "gitHub"} if jid == 11 else None
            return ({"settings": {"name": "detail", "git_source": gs}}, True)
        return ({}, True)

    monkeypatch.setattr(OperationsCollector, "run_api_call", fake_api)
    findings = OperationsCollector(profile_name="TEST").collect()

    assert findings["job_count"] == 3
    # Bundle job never needed a detail call; only the two plain jobs did.
    assert sorted(get_calls) == [11, 12]
    by_id = {j["job_id"]: j for j in findings["jobs"]}
    assert by_id[10]["is_cicd_managed"] is True and by_id[10]["deployment_kind"] == "BUNDLE"
    assert by_id[11]["has_git_source"] is True and by_id[11]["is_cicd_managed"] is True
    assert by_id[12]["is_cicd_managed"] is False
