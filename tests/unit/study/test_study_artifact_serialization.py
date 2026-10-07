from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.study_artifact_serialization import (
    published_model_json_bytes,
    require_published_model_json_bytes,
)


def test_published_model_json_bytes_revalidates_and_is_canonical() -> None:
    model = EnvironmentInfo(platform="test", python_version="3.11.0")

    encoded = published_model_json_bytes(model)

    assert encoded.endswith(b"\n")
    assert json.loads(encoded) == model.model_dump(mode="json", warnings="error")
    assert require_published_model_json_bytes(None, model, label="environment") == encoded
    assert require_published_model_json_bytes(encoded, model, label="environment") == encoded


def test_study_serializers_reject_unsafe_model_copy() -> None:
    model = EnvironmentInfo(platform="test", python_version="3.11.0")
    forged = model.model_copy(update={"artifact_kind": "forged-artifact"})

    with pytest.raises(ValidationError, match="artifact_kind"):
        published_model_json_bytes(forged)

    with pytest.raises(ValidationError, match="artifact_kind"):
        require_published_model_json_bytes(None, forged, label="environment")
