from __future__ import annotations

from typing import Literal

from agent_assure.schema.base import PersistedArtifact


class Provenance(PersistedArtifact):
    artifact_kind: Literal["provenance"] = "provenance"
    prompt_digest: str | None = None
    code_digest: str | None = None
    policy_bundle_digest: str | None = None
    configuration_digest: str | None = None
    tool_schema_digest: str | None = None
    model_identifier: str | None = None
    fixture_manifest_digest: str | None = None
    retrieval_corpus_digest: str | None = None
