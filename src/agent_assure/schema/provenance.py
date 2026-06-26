from __future__ import annotations

from typing import Literal

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import DigestHex


class Provenance(PersistedArtifact):
    artifact_kind: Literal["provenance"] = "provenance"
    prompt_digest: DigestHex | None = None
    code_digest: DigestHex | None = None
    policy_bundle_digest: DigestHex | None = None
    configuration_digest: DigestHex | None = None
    tool_schema_digest: DigestHex | None = None
    model_identifier: str | None = None
    fixture_manifest_digest: DigestHex | None = None
    retrieval_corpus_digest: DigestHex | None = None
