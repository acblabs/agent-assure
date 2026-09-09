from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from types import MappingProxyType
from typing import Final, Literal

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
_V066_BUNDLED_SENSITIVITY_SUITE_IDENTITIES = frozenset(
    {
        (
            "ee4f04ad7ca51e420e0d1b92bfe5a010d2b95b5096137af0f4b1fbb8bad9b5a4",
            "ab359d460343f9171df67154bdd0345741c2d61ad9df961be572f82e31a3ab76",
        ),
        (
            "2ed2260777fc8d5a09764cd2907ef2deaa97668c1e8fcc77d10151679009f173",
            "0977d4d5ebcf57cee26e7ad63924f6b488bd74c7e54d306f1e97dbe4c48485a1",
        ),
        (
            "32893dfd46e7d873747dcc939c9913a9f9ad949f4450d38d8bf21772aae7b894",
            "c5325b70e90b68af8f033e018500705bdcabcef192fad9cc23a2040e7a9751bf",
        ),
    }
)
_V066_BUNDLED_SENSITIVITY_KNOWLEDGE_CONTRACT_DIGEST = (
    "187738466df6185fcad4f93d7cf0ff9c9c85a892396400099d3a374c0841bcd2"
)
_V066_BUNDLED_SENSITIVITY_CORPUS_SNAPSHOT_IDENTITIES = frozenset(
    {
        (
            "26978670fc947d73d73725b0eac700c8faeee0142900c23e4dbf07282466e25a",
            "fd9d082654d02eedc7e0eb1bd04162012430405db567fe1655e9dfb3d58bf124",
        ),
        (
            "dd808d46147a4a2f55e5608f0bab3721ff485752975dfa49b06d17d7660930ce",
            "0b6a2ed94bd99ff670666087bc8f24f31c06a1f96c5d31884947be9051727186",
        ),
    }
)

# Deprecated compatibility aliases. These names were part of the v0.6.x
# public import surface before the identities became writer-version scoped.
# Keep them pinned to the current writer generation; replay of older writers
# must continue to use ``bundled_sensitivity_identity_set(schema_version)``.
BUNDLED_SENSITIVITY_SUITE_IDENTITIES: Final = _V066_BUNDLED_SENSITIVITY_SUITE_IDENTITIES
BUNDLED_SENSITIVITY_KNOWLEDGE_CONTRACT_DIGEST: Final = (
    _V066_BUNDLED_SENSITIVITY_KNOWLEDGE_CONTRACT_DIGEST
)
BUNDLED_SENSITIVITY_CORPUS_SNAPSHOT_IDENTITIES: Final = (
    _V066_BUNDLED_SENSITIVITY_CORPUS_SNAPSHOT_IDENTITIES
)


@dataclass(frozen=True, slots=True)
class BundledSensitivityIdentitySet:
    suite_identities: frozenset[tuple[str, str]]
    knowledge_contract_digest: str
    corpus_snapshot_identities: frozenset[tuple[str, str]]


_V064_BUNDLED_SENSITIVITY_IDENTITIES: Final = BundledSensitivityIdentitySet(
    suite_identities=frozenset(
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
    ),
    knowledge_contract_digest=("43c6f8258181292c8cb32dd5bcad76f6c7bfd97b95fceb339fbc2ad9bb9d0e57"),
    corpus_snapshot_identities=frozenset(
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
    ),
)
_V065_BUNDLED_SENSITIVITY_IDENTITIES: Final = BundledSensitivityIdentitySet(
    suite_identities=frozenset(
        {
            (
                "a96a7e32c50125b30ff768757cce01a121d11a65adb4b0fd5951ccfe6e6038fc",
                "e93ce6d8258c80fd56f004cbb34a3186fe6ca6b02beddad082e17e18a6d6f359",
            ),
            (
                "6d705f5b64ec20ebbec982182305006b2a7e8f6193b9cde6a46dedd47c7ec450",
                "f2350e1740dc7030038594d7ab07b605f2c15b21b55fb3cfe81c800b0b555c67",
            ),
            (
                "174866deee612d4855ec1babb54917bc39b0d05b2ac7e5be516fefbf70992afd",
                "0ee2ca3504df45fd8b7168d8334762fa272e5ddf33b23c9189bff36a499518e3",
            ),
        }
    ),
    # This is the immutable digest shipped by the v0.6.5 writer. Do not
    # alias it through the current public constant: bundled identities may
    # intentionally evolve between writer versions.
    knowledge_contract_digest=("9058dfb027d0b7f5f2dcf37d81420ec729fdc4fe753e921fb2f596e6dba2f816"),
    corpus_snapshot_identities=frozenset(
        {
            (
                "0764f9224779f6f07877f010ecf455773c7840fe498269830eecdb78b13676fc",
                "1f17d6b774171ed8803ea3ff31c68fbb5d5ff6dbcf68012b21e75481e7132b6d",
            ),
            (
                "7b029a4c7b099d04accb8bf9480008d4d8e01961a39aa1bdb3d92cc5e2626f81",
                "89555a56b88293c9e71d9377fe1a582ca4c2080c91c5569c6dc9063c6b45c1ec",
            ),
        }
    ),
)
_V066_BUNDLED_SENSITIVITY_IDENTITIES: Final = BundledSensitivityIdentitySet(
    suite_identities=_V066_BUNDLED_SENSITIVITY_SUITE_IDENTITIES,
    knowledge_contract_digest=_V066_BUNDLED_SENSITIVITY_KNOWLEDGE_CONTRACT_DIGEST,
    corpus_snapshot_identities=_V066_BUNDLED_SENSITIVITY_CORPUS_SNAPSHOT_IDENTITIES,
)
_BUNDLED_SENSITIVITY_IDENTITIES_BY_SCHEMA_VERSION: Final[
    Mapping[str, BundledSensitivityIdentitySet]
] = MappingProxyType(
    {
        "0.6.4": _V064_BUNDLED_SENSITIVITY_IDENTITIES,
        "0.6.5": _V065_BUNDLED_SENSITIVITY_IDENTITIES,
        "0.6.6": _V066_BUNDLED_SENSITIVITY_IDENTITIES,
    }
)


def bundled_sensitivity_identity_set(
    schema_version: str,
) -> BundledSensitivityIdentitySet | None:
    """Return reviewed bundled identities for one exact writer generation."""

    return _BUNDLED_SENSITIVITY_IDENTITIES_BY_SCHEMA_VERSION.get(schema_version)


__all__ = [
    "BUNDLED_SENSITIVITY_CORPUS_SNAPSHOT_IDENTITIES",
    "BUNDLED_SENSITIVITY_KNOWLEDGE_CONTRACT_DIGEST",
    "BUNDLED_SENSITIVITY_SUITE_IDENTITIES",
    "BundledSensitivityIdentitySet",
    "MAX_SENSITIVITY_CORPUS_BYTES",
    "MAX_SENSITIVITY_FIXTURE_BYTES",
    "SENSITIVITY_EVALUATION_DATE",
    "SENSITIVITY_HARNESS_NOTICE",
    "SENSITIVITY_PROVENANCE_BINDING",
    "SENSITIVITY_SUBJECT_EXECUTION_SCOPE",
    "SensitivityProvenanceBinding",
    "SensitivitySubjectExecutionScope",
    "bundled_sensitivity_identity_set",
]
