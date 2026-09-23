"""Tests for the AICollector parsing and GenAI best-practice scoring."""

from wal_e.collectors.ai import (
    AICollector,
    _has_strong_guardrails,
    _is_foundation_system_entity,
    _is_llm_entity,
    _looks_production,
    _scan_for_plaintext_secret,
    _uc_model_name,
)
from wal_e.framework.scoring import (
    _score_gov_006,
    _score_gov_016,
    _score_gov_018,
    _score_int_008,
    _score_ops_004,
    _score_rel_022,
    _score_sec_014,
    _score_sec_015,
    _score_sec_016,
)


# ---------------------------------------------------------------------------
# Collector helpers
# ---------------------------------------------------------------------------


def test_is_llm_entity_detects_external_and_fmapi():
    assert _is_llm_entity({"external_model": {"provider": "openai"}}, "my-ep", "")
    assert _is_llm_entity({}, "databricks-meta-llama-3", "")
    assert _is_llm_entity({}, "my-ep", "llm/v1/chat")
    assert not _is_llm_entity({}, "fraud-classifier", "")


def test_scan_for_plaintext_secret():
    safe = {"openai_config": {"openai_api_key": "{{secrets/scope/key}}"}}
    leaky = {"openai_config": {"openai_api_key_plaintext": "sk-realkey"}}
    empty_plaintext = {"openai_config": {"openai_api_key_plaintext": ""}}
    assert not _scan_for_plaintext_secret(safe)
    assert _scan_for_plaintext_secret(leaky)
    assert not _scan_for_plaintext_secret(empty_plaintext)


def test_is_foundation_system_entity():
    # Databricks-managed foundation-model system endpoints.
    assert _is_foundation_system_entity(
        {"type": "FOUNDATION_MODEL", "foundation_model": {"name": "system.ai.databricks-claude-opus-4-8"}},
        "databricks-claude-opus-4-8",
        "FOUNDATION_MODEL_API",
    )
    assert _is_foundation_system_entity({}, "databricks-gpt-oss-120b", "")
    assert _is_foundation_system_entity({"type": "FOUNDATION_MODEL"}, "x", "")
    # Customer-owned endpoints are NOT system endpoints.
    assert not _is_foundation_system_entity(
        {"type": "UC_MODEL", "entity_name": "ds.claimbot.complete_aggregator"}, "aggregator", ""
    )
    # Customer-configured external models remain the customer's responsibility.
    assert not _is_foundation_system_entity(
        {"external_model": {"provider": "openai"}}, "my-openai", "EXTERNAL_MODEL"
    )


def test_uc_model_name():
    assert _uc_model_name({"type": "UC_MODEL", "entity_name": "ds.s.m"}) == "ds.s.m"
    assert _uc_model_name({"model_name": "cat.sch.model"}) == "cat.sch.model"
    assert _uc_model_name({"foundation_model": {"name": "system.ai.x"}}) is None
    assert _uc_model_name({"external_model": {"provider": "openai"}}) is None
    # An explicit UC_MODEL type is trusted even if the name is not three-level.
    assert _uc_model_name({"type": "UC_MODEL", "entity_name": "bare_name"}) == "bare_name"
    # A non-UC entity with a two-level name is not treated as a UC model.
    assert _uc_model_name({"entity_name": "schema.model"}) is None


def test_parse_endpoint_classifies_fmapi_vs_custom():
    """Trupanion-shaped mix: FMAPI system endpoint vs custom UC-model endpoint."""
    collector = AICollector("test")
    findings = {
        "serving_endpoints": [],
        "llm_endpoint_count": 0,
        "foundation_model_system_endpoint_count": 0,
        "external_model_endpoint_count": 0,
        "endpoints_with_guardrails": 0,
        "endpoints_with_inference_tables": 0,
        "endpoints_with_plaintext_keys": 0,
        "prod_llm_endpoint_count": 0,
        "prod_llm_provisioned_throughput": 0,
        "prod_llm_scale_to_zero": 0,
    }
    uc_models: set[str] = set()

    fmapi = {
        "endpoint_type": "FOUNDATION_MODEL_API",
        "ai_gateway": {"usage_tracking_config": {"enabled": True}},
        "config": {
            "served_entities": [
                {"type": "FOUNDATION_MODEL", "foundation_model": {"name": "system.ai.databricks-claude-opus-4-8"}}
            ]
        },
    }
    custom = {
        "config": {
            "served_entities": [
                {"type": "UC_MODEL", "entity_name": "ds.claimbot_training_jdpoc.complete_aggregator"}
            ]
        },
    }
    collector._parse_endpoint("databricks-claude-opus-4-8", fmapi, findings, uc_models)
    collector._parse_endpoint("aggregator", custom, findings, uc_models)

    # The system endpoint must not be counted as a customer LLM gap.
    assert findings["foundation_model_system_endpoint_count"] == 1
    assert findings["llm_endpoint_count"] == 0
    # The custom UC model must be discovered even if the UC models API is empty.
    assert uc_models == {"ds.claimbot_training_jdpoc.complete_aggregator"}


def test_has_strong_guardrails():
    assert _has_strong_guardrails({"input": {"pii": {"behavior": "BLOCK"}}})
    assert _has_strong_guardrails({"output": {"safety": True}})
    assert not _has_strong_guardrails({"input": {"pii": {"behavior": "NONE"}, "safety": False}})
    assert not _has_strong_guardrails({})


def test_looks_production():
    assert _looks_production("prod-rag-chatbot")
    assert not _looks_production("dev-prod-experiment")  # non-prod marker wins
    assert not _looks_production("rag-chatbot")


# ---------------------------------------------------------------------------
# Scoring: gov-016 (Models in Unity Catalog)
# ---------------------------------------------------------------------------


def test_gov_016_all_in_uc():
    data = {"AICollector": {"uc_model_count": 5, "ws_registry_model_count": 0}}
    score, _ = _score_gov_016(data)
    assert score == 2


def test_gov_016_partial_migration():
    data = {"AICollector": {"uc_model_count": 3, "ws_registry_model_count": 2}}
    score, _ = _score_gov_016(data)
    assert score == 1


def test_gov_016_legacy_only():
    data = {"AICollector": {"uc_model_count": 0, "ws_registry_model_count": 4}}
    score, _ = _score_gov_016(data)
    assert score == 0


def test_gov_016_no_models_unverifiable():
    data = {"AICollector": {"uc_model_count": 0, "ws_registry_model_count": 0}}
    score, notes = _score_gov_016(data)
    assert score == 1
    assert "no registered models" in notes.lower()


# ---------------------------------------------------------------------------
# Scoring: gov-018 (inference tables) and sec-015 (guardrails)
# ---------------------------------------------------------------------------


def test_gov_018_all_logged():
    data = {"AICollector": {"llm_endpoint_count": 2, "endpoints_with_inference_tables": 2}}
    assert _score_gov_018(data)[0] == 2


def test_gov_018_none_logged():
    data = {"AICollector": {"llm_endpoint_count": 2, "endpoints_with_inference_tables": 0}}
    assert _score_gov_018(data)[0] == 0


def test_gov_018_no_llm_is_na_full():
    data = {"AICollector": {"llm_endpoint_count": 0}}
    assert _score_gov_018(data)[0] == 2


def test_gov_018_only_foundation_system_endpoints_not_a_gap():
    # 23 Databricks-managed FMAPI endpoints, no customer LLM endpoints.
    data = {"AICollector": {"llm_endpoint_count": 0, "foundation_model_system_endpoint_count": 23}}
    score, notes = _score_gov_018(data)
    assert score == 2
    assert "databricks-managed" in notes.lower()


def test_sec_015_only_foundation_system_endpoints_not_a_gap():
    data = {"AICollector": {"llm_endpoint_count": 0, "foundation_model_system_endpoint_count": 23}}
    score, notes = _score_sec_015(data)
    assert score == 2
    assert "databricks-managed" in notes.lower()


def test_sec_015_customer_llm_without_guardrails_still_flagged():
    data = {"AICollector": {"llm_endpoint_count": 2, "endpoints_with_guardrails": 0,
                            "foundation_model_system_endpoint_count": 5}}
    assert _score_sec_015(data)[0] == 0


def test_sec_015_partial_guardrails():
    data = {"AICollector": {"llm_endpoint_count": 3, "endpoints_with_guardrails": 1}}
    assert _score_sec_015(data)[0] == 1


# ---------------------------------------------------------------------------
# Scoring: sec-016 (plaintext credentials) — hard fail
# ---------------------------------------------------------------------------


def test_sec_016_plaintext_is_hard_fail():
    data = {"AICollector": {"external_model_endpoint_count": 2, "endpoints_with_plaintext_keys": 1}}
    score, notes = _score_sec_016(data)
    assert score == 0
    assert "secret scope" in notes.lower()


def test_sec_016_secrets_clean():
    data = {"AICollector": {"external_model_endpoint_count": 2, "endpoints_with_plaintext_keys": 0}}
    assert _score_sec_016(data)[0] == 2


# ---------------------------------------------------------------------------
# Scoring: rel-022 (provisioned throughput for prod LLM)
# ---------------------------------------------------------------------------


def test_rel_022_prod_with_provisioned_throughput():
    data = {"AICollector": {
        "llm_endpoint_count": 1, "prod_llm_endpoint_count": 1,
        "prod_llm_provisioned_throughput": 1, "prod_llm_scale_to_zero": 0,
    }}
    assert _score_rel_022(data)[0] == 2


def test_rel_022_prod_scale_to_zero_penalized():
    data = {"AICollector": {
        "llm_endpoint_count": 1, "prod_llm_endpoint_count": 1,
        "prod_llm_provisioned_throughput": 0, "prod_llm_scale_to_zero": 1,
    }}
    assert _score_rel_022(data)[0] == 0


def test_rel_022_no_llm_unverifiable():
    data = {"AICollector": {"llm_endpoint_count": 0}}
    score, notes = _score_rel_022(data)
    assert score == 1


# ---------------------------------------------------------------------------
# Scoring: gov-006 / int-008 upgrades read from AICollector
# ---------------------------------------------------------------------------


def test_gov_006_governed_in_uc():
    data = {"AICollector": {"uc_model_count": 4, "ws_registry_model_count": 0, "vs_endpoint_count": 1}}
    assert _score_gov_006(data)[0] == 2


def test_int_008_uc_models_full():
    data = {"AICollector": {"uc_model_count": 2, "endpoint_count": 3}}
    assert _score_int_008(data)[0] == 2


def test_int_008_endpoints_without_uc_models_partial():
    data = {"AICollector": {"uc_model_count": 0, "endpoint_count": 2}}
    assert _score_int_008(data)[0] == 1


# ---------------------------------------------------------------------------
# UC-served-model fallback (models API empty but endpoints serve UC models)
# ---------------------------------------------------------------------------


def test_gov_016_uc_served_fallback_when_api_empty():
    data = {"AICollector": {"uc_model_count": 0, "ws_registry_model_count": 0, "uc_served_model_count": 2}}
    score, notes = _score_gov_016(data)
    assert score == 2
    assert "served from unity catalog" in notes.lower()


def test_gov_006_uc_served_fallback_when_api_empty():
    data = {"AICollector": {"uc_model_count": 0, "ws_registry_model_count": 0,
                            "uc_served_model_count": 2, "endpoint_count": 5}}
    assert _score_gov_006(data)[0] == 2


def test_int_008_uc_served_fallback_when_api_empty():
    data = {"AICollector": {"uc_model_count": 0, "uc_served_model_count": 3, "endpoint_count": 5}}
    assert _score_int_008(data)[0] == 2


def test_ops_004_uc_models_is_full_not_partial():
    data = {"AICollector": {"uc_model_count": 0, "uc_served_model_count": 2, "endpoint_count": 5}}
    assert _score_ops_004(data)[0] == 2


# ---------------------------------------------------------------------------
# sec-014 permission-change churn is rate-aware (denominator matters)
# ---------------------------------------------------------------------------


def test_sec_014_high_volume_but_tiny_share_is_not_critical():
    # Trupanion: 1,856 changes of 16.6M events = 0.011% — not an incident.
    data = {"SystemTablesCollector": {"available": True, "audit_events": {
        "available": True, "permission_changes_30d": 1856, "total_events_30d": 16_635_173,
    }}}
    assert _score_sec_014(data)[0] == 1


def test_sec_014_high_volume_and_high_share_is_critical():
    data = {"SystemTablesCollector": {"available": True, "audit_events": {
        "available": True, "permission_changes_30d": 600, "total_events_30d": 1000,
    }}}
    assert _score_sec_014(data)[0] == 0
