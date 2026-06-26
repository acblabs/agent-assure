from __future__ import annotations

REQUIRED_MODEL_OUTPUT_FIELDS = (
    "recommendation",
    "outcome",
    "provider",
    "model",
)


def missing_model_output_fields(payload: dict[str, object]) -> tuple[str, ...]:
    return tuple(field for field in REQUIRED_MODEL_OUTPUT_FIELDS if field not in payload)
