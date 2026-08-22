from __future__ import annotations

from datetime import date
from typing import Literal

SENSITIVITY_EVALUATION_DATE = date(2026, 1, 1)
MAX_SENSITIVITY_CORPUS_BYTES = 1 * 1024 * 1024
MAX_SENSITIVITY_FIXTURE_BYTES = 1 * 1024 * 1024

SensitivitySubjectExecutionScope = Literal["declarative_fixture_harness_not_model_evidence_use"]
SENSITIVITY_SUBJECT_EXECUTION_SCOPE: SensitivitySubjectExecutionScope = (
    "declarative_fixture_harness_not_model_evidence_use"
)

SensitivityProvenanceBinding = Literal["fixture_declared_unverified_digests"]
SENSITIVITY_PROVENANCE_BINDING: SensitivityProvenanceBinding = "fixture_declared_unverified_digests"

SENSITIVITY_HARNESS_NOTICE = (
    "Synthetic declarative fixture harness/oracle only; this result does not show that a "
    "model used contextual evidence instead of parametric memory."
)

# Reviewed immutable identities for the three bundled v1 subjects and two
# committed corpus snapshots. Values are constants rather than values derived
# from mutable package resources at runtime.
BUNDLED_SENSITIVITY_SUITE_IDENTITIES = frozenset(
    {
        (
            "b882eb5ac21179312b40e6e438b9e1aedeecef0ffac2d3d942b88a053c5ee20a",
            "f11528e38cc17afc6e9d726666d324fb8baca4311369c57cd0737caaafc2ba4a",
        ),
        (
            "e4d857b0a750e17fa826f240b05b2880617f41baa0424e1e28310b2b32fcab53",
            "4878cd6f059ce3a2b185ada25e705ebec8165beac0be25bacd6734493a882f79",
        ),
        (
            "f78b7a363b77e227170ac704c5b691a30661828842f7fddfb3cd3f7544f1ee7a",
            "edd4e04d290fec432d8d4f896895e8ce8410f92843c8431040baf0934b85f73f",
        ),
    }
)
BUNDLED_SENSITIVITY_KNOWLEDGE_CONTRACT_DIGEST = (
    "43c6f8258181292c8cb32dd5bcad76f6c7bfd97b95fceb339fbc2ad9bb9d0e57"
)
BUNDLED_SENSITIVITY_CORPUS_SNAPSHOT_IDENTITIES = frozenset(
    {
        (
            "f1d680df273c0189a9c78a1c6246d02e07ab7b52f14285b788ed79f5f601d551",
            "4adf3567d1497aae2c44ce8d6b506cf73b4c59a8aa02e3d3e1d1a5c0bab62905",
        ),
        (
            "d8e26f1502ae20fc4de4bee2d799bfb1f763d8fa7eaea2852cbd193f7350137e",
            "8215d2db9cbc817d8e825528024dffcf2bc9b9ee5ff597d1380d1d16c1a70a7a",
        ),
    }
)

__all__ = [
    "BUNDLED_SENSITIVITY_CORPUS_SNAPSHOT_IDENTITIES",
    "BUNDLED_SENSITIVITY_KNOWLEDGE_CONTRACT_DIGEST",
    "BUNDLED_SENSITIVITY_SUITE_IDENTITIES",
    "MAX_SENSITIVITY_CORPUS_BYTES",
    "MAX_SENSITIVITY_FIXTURE_BYTES",
    "SENSITIVITY_EVALUATION_DATE",
    "SENSITIVITY_HARNESS_NOTICE",
    "SENSITIVITY_PROVENANCE_BINDING",
    "SENSITIVITY_SUBJECT_EXECUTION_SCOPE",
    "SensitivityProvenanceBinding",
    "SensitivitySubjectExecutionScope",
]
