from __future__ import annotations

from agent_assure.schema.live import (
    LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION,
    LiveComparisonReport,
)


def test_current_live_comparison_schema_has_no_default_and_exact_source_limitation() -> None:
    schema = LiveComparisonReport.model_json_schema(mode="validation")

    assert LiveComparisonReport.model_fields["limitations"].default == (
        "live comparison intervals are descriptive unless the protocol predeclares the "
        "comparison as confirmatory",
    )
    limitations_schema = schema["properties"]["limitations"]
    assert "default" not in limitations_schema

    current_contracts = [
        contract
        for contract in schema["allOf"]
        if contract.get("if", {}).get("properties", {}).get("schema_version", {}).get("const")
        == "0.6.6"
    ]
    assert len(current_contracts) == 1
    current_contract = current_contracts[0]["then"]
    assert "limitations" in current_contract["required"]
    assert current_contract["properties"]["limitations"] == {
        "contains": {"const": LIVE_COMPARISON_SOURCE_LINKAGE_LIMITATION},
        "minContains": 1,
        "maxContains": 1,
    }
