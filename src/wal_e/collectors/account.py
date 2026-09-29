"""Account-level collector: confirms controls the workspace API cannot see.

Network isolation (customer-managed VPC / VNet, Private Link / Private Service
Connect, Network Connectivity Configs), account-level SCIM, and audit log
delivery are configured at the Databricks *account* level, not the workspace.
They are invisible to the workspace REST API, so a workspace-only run can only
report them as "unverifiable". This collector uses the Databricks *account* API
(the accounts-console host, via a separate CLI profile) to confirm them.

All access is read-only (GET only).

Cloud caveat: on Azure, VNet injection is a property of the workspace's Azure
Resource Manager (ARM) resource, not the Databricks account API. This collector
confirms what the account API exposes (Private Link / NCC / private-access
settings, account SCIM, log delivery); Azure VNet injection still requires an
ARM check and is reported as such.
"""

from __future__ import annotations

from typing import Any

from wal_e.collectors.base import BaseCollector


def _workspace_matches_host(ws: dict, workspace_host: str) -> bool:
    """True when an account workspace record corresponds to the assessed host."""
    host = (workspace_host or "").lower()
    if not host:
        return False
    ws_id = str(ws.get("workspace_id", "") or "")
    deployment = str(ws.get("deployment_name", "") or "").lower()
    if ws_id and ws_id in host:
        return True
    if deployment and deployment in host:
        return True
    return False


class AccountCollector(BaseCollector):
    """Collects account-level controls via the Databricks account API."""

    def __init__(self, profile_name: str, account_id: str, workspace_host: str = "") -> None:
        super().__init__(profile_name)
        self.account_id = account_id
        self.workspace_host = workspace_host

    def _acct(self, path: str) -> tuple[dict[str, Any] | None, bool]:
        return self.run_api_call(f"/api/2.0/accounts/{self.account_id}/{path}")

    def collect(self) -> dict[str, Any]:
        findings: dict[str, Any] = {
            "available": False,
            "account_id": self.account_id,
            "network_count": 0,
            "private_access_count": 0,
            "ncc_count": 0,
            "workspace_matched": False,
            "workspace_vpc_injection": False,
            "workspace_private_link": False,
            "account_scim_configured": False,
            "account_scim_group_count": 0,
            "log_delivery_configured": False,
        }
        if not self.account_id:
            findings["error"] = "No account_id resolved; pass --account-id or set it on the account profile."
            return findings

        self._collect_networks(findings)
        self._collect_workspace_isolation(findings)
        self._collect_account_scim(findings)
        self._collect_log_delivery(findings)
        return findings

    def _collect_networks(self, findings: dict[str, Any]) -> None:
        data, ok = self._acct("networks")
        if ok and isinstance(data, dict):
            findings["available"] = True
            nets = data.get("networks", data if isinstance(data, list) else []) or []
            findings["network_count"] = len(nets) if isinstance(nets, list) else 0

        data, ok = self._acct("private-access-settings")
        if ok and isinstance(data, dict):
            findings["available"] = True
            pas = data.get("private_access_settings_list", data.get("items", [])) or []
            findings["private_access_count"] = len(pas) if isinstance(pas, list) else 0

        data, ok = self._acct("network-connectivity-configs")
        if ok and isinstance(data, dict):
            findings["available"] = True
            nccs = data.get("items", data.get("network_connectivity_configs", [])) or []
            findings["ncc_count"] = len(nccs) if isinstance(nccs, list) else 0

    def _collect_workspace_isolation(self, findings: dict[str, Any]) -> None:
        data, ok = self._acct("workspaces")
        if not (ok and isinstance(data, dict)):
            return
        findings["available"] = True
        workspaces = data.get("workspaces", data if isinstance(data, list) else []) or []
        if not isinstance(workspaces, list):
            return
        for ws in workspaces:
            if not isinstance(ws, dict) or not _workspace_matches_host(ws, self.workspace_host):
                continue
            findings["workspace_matched"] = True
            if ws.get("network_id"):
                findings["workspace_vpc_injection"] = True
            if ws.get("private_access_settings_id") or ws.get("private_access_settings"):
                findings["workspace_private_link"] = True
            break

    def _collect_account_scim(self, findings: dict[str, Any]) -> None:
        data, ok = self._acct("scim/v2/Groups?count=1")
        if ok and isinstance(data, dict):
            findings["available"] = True
            total = data.get("totalResults")
            count = total if isinstance(total, int) else len(data.get("Resources", []) or [])
            findings["account_scim_group_count"] = count
            findings["account_scim_configured"] = count > 0

    def _collect_log_delivery(self, findings: dict[str, Any]) -> None:
        data, ok = self._acct("log-delivery")
        if ok and isinstance(data, dict):
            findings["available"] = True
            configs = data.get("log_delivery_configurations", []) or []
            active = [
                c for c in configs
                if isinstance(c, dict) and str(c.get("status", "")).upper() == "ENABLED"
            ]
            findings["log_delivery_configured"] = len(active) > 0
