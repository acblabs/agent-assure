from __future__ import annotations

from agent_assure.sensitivity_contract import (
    BUNDLED_SENSITIVITY_CORPUS_SNAPSHOT_IDENTITIES,
    BUNDLED_SENSITIVITY_KNOWLEDGE_CONTRACT_DIGEST,
    BUNDLED_SENSITIVITY_SUITE_IDENTITIES,
    bundled_sensitivity_identity_set,
)


def test_v065_bundled_knowledge_contract_identity_is_immutable() -> None:
    identity_set = bundled_sensitivity_identity_set("0.6.5")

    assert identity_set is not None
    assert identity_set.knowledge_contract_digest == (
        "9058dfb027d0b7f5f2dcf37d81420ec729fdc4fe753e921fb2f596e6dba2f816"
    )


def test_v066_bundled_knowledge_contract_identity_is_version_scoped() -> None:
    identity_set = bundled_sensitivity_identity_set("0.6.6")

    assert identity_set is not None
    assert identity_set.knowledge_contract_digest == (
        "187738466df6185fcad4f93d7cf0ff9c9c85a892396400099d3a374c0841bcd2"
    )


def test_deprecated_bundled_identity_imports_alias_the_current_writer() -> None:
    identity_set = bundled_sensitivity_identity_set("0.6.6")

    assert identity_set is not None
    assert BUNDLED_SENSITIVITY_SUITE_IDENTITIES is identity_set.suite_identities
    assert BUNDLED_SENSITIVITY_KNOWLEDGE_CONTRACT_DIGEST == identity_set.knowledge_contract_digest
    assert BUNDLED_SENSITIVITY_CORPUS_SNAPSHOT_IDENTITIES is identity_set.corpus_snapshot_identities
