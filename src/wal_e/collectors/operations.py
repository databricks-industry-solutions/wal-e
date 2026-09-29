"""Operations (jobs, pipelines, repos, etc.) data collector."""

from __future__ import annotations

from typing import Any

from wal_e.collectors.base import BaseCollector

# Page size for the paginated jobs/list call.
_JOBS_PAGE_LIMIT = 100
# Safety cap on total list pages, to avoid runaway loops on huge workspaces.
_JOBS_MAX_PAGES = 50
# `git_source` is never returned by jobs/list (even with expand_tasks); it is
# only available via jobs/get. We enrich per-job only when the cheap list
# signals leave CI/CD status ambiguous, bounded by this cap to keep API volume
# reasonable. Bundle- and UI_LOCKED-managed jobs are detected from the list and
# never consume a detail call.
_JOBS_MAX_DETAIL_CALLS = 200


class OperationsCollector(BaseCollector):
    """Collects operational assets: jobs, pipelines, endpoints, repos, scripts, groups, secrets."""

    def collect(self) -> dict[str, Any]:
        """Collect jobs, pipelines, serving endpoints, repos, init scripts, groups, secret scopes."""
        findings: dict[str, Any] = {
            "job_count": 0,
            "jobs": [],
            "pipeline_count": 0,
            "pipelines": [],
            "endpoint_count": 0,
            "endpoints": [],
            "repo_count": 0,
            "init_script_count": 0,
            "init_scripts": [],
            "group_count": 0,
            "scope_count": 0,
        }

        # Jobs (paginated list + bounded per-job detail enrichment)
        jobs_raw = self._list_all_jobs()
        detail_calls = 0
        for j in jobs_raw:
            if not isinstance(j, dict):
                continue
            settings = j.get("settings", {}) or {}
            job = self._summarize_job(j, settings)
            # jobs/list omits git_source, so a job that shows no CI/CD signal yet
            # may still be Git-backed. Confirm via jobs/get, bounded by a cap.
            if not job["is_cicd_managed"] and detail_calls < _JOBS_MAX_DETAIL_CALLS:
                detail = self._get_job_settings(j.get("job_id"))
                detail_calls += 1
                if detail:
                    job = self._summarize_job(j, detail)
            findings["jobs"].append(job)
        findings["job_count"] = len(findings["jobs"])
        findings["jobs_detail_calls"] = detail_calls

        # Pipelines
        data, ok = self.run_api_call("/api/2.0/pipelines")
        if ok and data:
            pipelines = data.get("statuses", []) or data.get("pipelines", []) or []
            findings["pipeline_count"] = len(pipelines)
            for p in pipelines:
                if isinstance(p, dict):
                    findings["pipelines"].append({
                        "pipeline_id": p.get("pipeline_id"),
                        "name": p.get("name"),
                        "state": p.get("state"),
                        "creator_user_name": p.get("creator_user_name"),
                    })

        # Serving endpoints
        data, ok = self.run_api_call("/api/2.0/serving-endpoints")
        if ok and data:
            endpoints = data.get("endpoints", []) or []
            findings["endpoint_count"] = len(endpoints)
            for e in endpoints:
                if isinstance(e, dict):
                    findings["endpoints"].append({
                        "name": e.get("name"),
                        "state": e.get("state"),
                    })

        # Repos
        data, ok = self.run_api_call("/api/2.0/repos")
        if ok and data:
            repos = data.get("repos", []) or []
            findings["repo_count"] = len(repos)

        # Global init scripts - endpoint is /api/2.0/global-init-scripts (no /list)
        data, ok = self.run_api_call("/api/2.0/global-init-scripts")
        if ok and data:
            scripts = data.get("scripts", []) or []
            findings["init_script_count"] = len(scripts)
            for s in scripts:
                if isinstance(s, dict):
                    findings["init_scripts"].append({
                        "name": s.get("name"),
                        "enabled": s.get("enabled"),
                        "script_id": s.get("script_id"),
                    })

        # Groups
        data, ok = self.run_api_call("/api/2.0/groups/list")
        if ok and data:
            groups = data.get("group_names", []) or data.get("groups", []) or []
            findings["group_count"] = len(groups) if isinstance(groups, list) else 0

        # Secret scopes
        data, ok = self.run_api_call("/api/2.0/secrets/list-scopes")
        if ok and data:
            scopes = data.get("scopes", []) or []
            findings["scope_count"] = len(scopes)

        return findings

    def _list_all_jobs(self) -> list[dict[str, Any]]:
        """Return all jobs across pages. jobs/list truncates settings, so we also
        request expand_tasks to surface tasks/job_clusters."""
        jobs: list[dict[str, Any]] = []
        base = f"/api/2.1/jobs/list?limit={_JOBS_PAGE_LIMIT}&expand_tasks=true"
        endpoint = base
        for _ in range(_JOBS_MAX_PAGES):
            data, ok = self.run_api_call(endpoint)
            if not ok or not data:
                break
            jobs.extend(data.get("jobs", []) or [])
            token = data.get("next_page_token")
            if not data.get("has_more") or not token:
                break
            endpoint = f"{base}&page_token={token}"
        return jobs

    def _get_job_settings(self, job_id: Any) -> dict[str, Any] | None:
        """Fetch full settings (incl. git_source) for one job via jobs/get."""
        if not job_id:
            return None
        data, ok = self.run_api_call(f"/api/2.1/jobs/get?job_id={job_id}")
        if ok and data:
            return data.get("settings", {}) or {}
        return None

    @staticmethod
    def _summarize_job(job: dict[str, Any], settings: dict[str, Any]) -> dict[str, Any]:
        """Build the per-job summary WAL-E scores against.

        A job counts as CI/CD-managed if it declares a Git source, is deployed
        via a Databricks Asset Bundle (`deployment.kind == BUNDLE`), or is
        UI-locked (the marker bundle/IaC deployment applies).
        """
        tasks = settings.get("tasks") or []
        job_clusters = settings.get("job_clusters") or []
        deployment_kind = (settings.get("deployment") or {}).get("kind")
        edit_mode = settings.get("edit_mode")
        has_git_source = bool(settings.get("git_source") or job.get("git_source"))
        is_bundle = deployment_kind == "BUNDLE"
        is_cicd_managed = bool(has_git_source or is_bundle or edit_mode == "UI_LOCKED")

        task_retries = [
            t.get("max_retries") for t in tasks
            if isinstance(t, dict) and isinstance(t.get("max_retries"), int)
        ]
        max_retries = settings.get("max_retries")
        if max_retries is None and task_retries:
            max_retries = max(task_retries)
        existing_cluster = bool(
            settings.get("existing_cluster_id")
            or any(isinstance(t, dict) and t.get("existing_cluster_id") for t in tasks)
        )

        return {
            "job_id": job.get("job_id"),
            "name": settings.get("name", job.get("job_name", job.get("name", ""))),
            "job_type": settings.get("format") or settings.get("job_type") or job.get("job_type"),
            "has_git_source": has_git_source,
            "deployment_kind": deployment_kind,
            "edit_mode": edit_mode,
            "is_cicd_managed": is_cicd_managed,
            "max_retries": max_retries,
            "has_existing_cluster_id": existing_cluster,
            "has_job_clusters": bool(job_clusters),
            # creator for service principal ownership check
            "creator_user_name": job.get("creator_user_name", ""),
        }
