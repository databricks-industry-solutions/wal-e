"""Tests for the account-level collector and account-confirmed network scoring.

Confirms that when an account profile is provided, network isolation controls
that the workspace API cannot see are read from the Databricks account API and
scored as *confirmed* rather than *unverifiable*.
"""

from wal_e.collectors.account import AccountCollector, _workspace_matches_host
from wal_e.framework.scoring import _is_verified, _score_sec_003, _score_sec_011


# ---------------------------------------------------------------------------
# Workspace <-> account record matching
# ---------------------------------------------------------------------------


def test_workspace_matches_by_id():
    ws = {"workspace_id": 7800748942590523, "deployment_name": "adb-7800748942590523.3"}
    host = "https://adb-7800748942590523.3.azuredatabricks.net"
    assert _workspace_matches_host(ws, host)


def test_workspace_matches_by_deployment_name():
    ws = {"workspace_id": 42, "deployment_name": "dbc-abc123"}
    assert _workspace_matches_host(ws, "https://dbc-abc123.cloud.databricks.com")


def test_workspace_no_match():
    ws = {"workspace_id": 999, "deployment_name": "dbc-other"}
    assert not _workspace_matches_host(ws, "https://adb-7800748942590523.3.azuredatabricks.net")


def test_collect_without_account_id_is_unavailable():
    findings = AccountCollector("acct", account_id="").collect()
    assert findings["available"] is False
    assert "account_id" in findings["error"].lower()


# ---------------------------------------------------------------------------
# sec-011 customer-managed VPC — confirmed via account API
# ---------------------------------------------------------------------------


def test_sec_011_vpc_injection_confirmed():
    data = {"_cloud_provider": "aws", "AccountCollector": {
        "available": True, "workspace_matched": True, "workspace_vpc_injection": True,
    }}
    score, notes = _score_sec_011(data)
    assert score == 2
    assert "confirmed" in notes.lower()


def test_sec_011_private_link_confirmed():
    data = {"_cloud_provider": "azure", "AccountCollector": {
        "available": True, "workspace_matched": True, "workspace_private_link": True,
        "private_access_count": 1, "ncc_count": 2,
    }}
    assert _score_sec_011(data)[0] == 2


def test_sec_011_azure_no_databricks_isolation_defers_to_arm():
    data = {"_cloud_provider": "azure", "AccountCollector": {
        "available": True, "workspace_matched": True,
    }}
    score, notes = _score_sec_011(data)
    assert score == 1
    assert "arm" in notes.lower() or "resource manager" in notes.lower()
    assert not _is_verified(score, notes)


def test_sec_011_aws_no_isolation_is_real_gap():
    data = {"_cloud_provider": "aws", "AccountCollector": {
        "available": True, "workspace_matched": True,
    }}
    score, notes = _score_sec_011(data)
    assert score == 1
    assert "private link" in notes.lower()


def test_sec_011_without_account_profile_stays_unverifiable():
    # No AccountCollector -> existing account-level-unverifiable behavior.
    data = {"_cloud_provider": "azure", "SecurityCollector": {"security_settings": {}}}
    score, notes = _score_sec_011(data)
    assert score == 1
    assert not _is_verified(score, notes)


# ---------------------------------------------------------------------------
# sec-003 network security — confirmed via account API
# ---------------------------------------------------------------------------


def test_sec_003_confirmed_by_private_access_settings():
    data = {"_cloud_provider": "azure", "SecurityCollector": {"ip_access_list_count": 0},
            "AccountCollector": {"available": True, "private_access_count": 1, "ncc_count": 1}}
    score, notes = _score_sec_003(data)
    assert score == 2
    assert _is_verified(score, notes)


def test_sec_003_unavailable_account_falls_back_to_unverifiable():
    data = {"_cloud_provider": "azure", "SecurityCollector": {"ip_access_list_count": 0},
            "AccountCollector": {"available": False}}
    score, notes = _score_sec_003(data)
    assert score == 1
    assert not _is_verified(score, notes)
