from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_assure.network_authority import (
    CANONICAL_ENDPOINT_HOST_PATTERN,
    MAX_ENDPOINT_HOST_CHARS,
    MAX_HOST_ENV_NAME_CHARS,
    PROVIDER_SECRET_ENV_NAME_PATTERN,
)
from agent_assure.schema.run import LiveNetworkAuthorityReceipt


def test_network_authority_receipt_accepts_canonical_public_authority() -> None:
    receipt = LiveNetworkAuthorityReceipt(
        endpoint_host="api.openai.com",
        api_key_env="OPENAI_TEST_KEY",
    )

    assert receipt.endpoint_host == "api.openai.com"
    assert receipt.api_key_env == "OPENAI_TEST_KEY"


@pytest.mark.parametrize(
    "endpoint_host",
    ("8.8.8.8", "2606:4700:4700::1111"),
)
def test_network_authority_receipt_accepts_canonical_public_addresses(
    endpoint_host: str,
) -> None:
    receipt = LiveNetworkAuthorityReceipt(
        endpoint_host=endpoint_host,
        api_key_env="OPENAI_TEST_KEY",
    )

    assert receipt.endpoint_host == endpoint_host


@pytest.mark.parametrize(
    "endpoint_host",
    (
        "API.OPENAI.COM",
        "api.openai.com.",
        " https://api.openai.com",
        "https://api.openai.com",
        "api.openai.com:443",
        "api.openai.com/v1/chat/completions",
        "operator@api.openai.com",
        "api..openai.com",
        "intranet",
        "localhost",
        "service.internal",
        "api.example.test",
        "service.invalid",
        "service.example",
        "metadata.google.internal",
        "127.0.0.1",
        "0177.0.0.1",
        "0x7f.0.0.1",
        "169.254.169.254",
        "168.63.129.16",
        "192.0.2.1",
        "::1",
        "::169.254.169.254",
        "::ffff:0:127.0.0.1",
        "::ffff:127.0.0.1",
        "4000::1",
        "2606:4700:4700:0:0:0:0:1111",
        "fe80::1%eth0",
    ),
)
def test_network_authority_receipt_rejects_noncanonical_or_nonpublic_hosts(
    endpoint_host: str,
) -> None:
    with pytest.raises(ValidationError):
        LiveNetworkAuthorityReceipt(
            endpoint_host=endpoint_host,
            api_key_env="OPENAI_TEST_KEY",
        )


@pytest.mark.parametrize(
    "api_key_env",
    (
        "9INVALID",
        "NOT-AN-ENV-NAME",
        "A" * (MAX_HOST_ENV_NAME_CHARS + 1),
        "GITHUB_TOKEN",
        "github_token",
        "AWS_SECRET_ACCESS_KEY",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "GH_TOKEN",
        "GITHUB_PAT",
        "NPM_TOKEN",
        "CI_JOB_JWT_V2",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "IDENTITY_HEADER",
        "ORDINARY_TOKEN",
    ),
)
def test_network_authority_receipt_rejects_invalid_or_ambient_credential_names(
    api_key_env: str,
) -> None:
    with pytest.raises(ValidationError):
        LiveNetworkAuthorityReceipt(
            endpoint_host="api.openai.com",
            api_key_env=api_key_env,
        )


def test_network_authority_receipt_revalidates_model_copy_tampering() -> None:
    valid = LiveNetworkAuthorityReceipt(
        endpoint_host="api.openai.com",
        api_key_env="OPENAI_TEST_KEY",
    )
    forged = valid.model_copy(update={"endpoint_host": "127.0.0.1"})

    with pytest.raises(ValidationError, match="special-use addresses"):
        LiveNetworkAuthorityReceipt.model_validate(forged.model_dump(mode="json"))


def test_network_authority_receipt_revalidates_ambient_credential_tampering() -> None:
    valid = LiveNetworkAuthorityReceipt(
        endpoint_host="api.openai.com",
        api_key_env="OPENAI_TEST_KEY",
    )
    forged = valid.model_copy(update={"api_key_env": "GITHUB_TOKEN"})

    with pytest.raises(ValidationError, match="ambient CI or cloud credential"):
        LiveNetworkAuthorityReceipt.model_validate(forged.model_dump(mode="json"))


def test_network_authority_receipt_schema_uses_field_specific_contracts() -> None:
    properties = LiveNetworkAuthorityReceipt.model_json_schema()["properties"]

    assert properties["endpoint_host"]["maxLength"] == MAX_ENDPOINT_HOST_CHARS
    assert properties["endpoint_host"]["pattern"] == CANONICAL_ENDPOINT_HOST_PATTERN
    assert properties["api_key_env"]["maxLength"] == MAX_HOST_ENV_NAME_CHARS
    assert properties["api_key_env"]["pattern"] == PROVIDER_SECRET_ENV_NAME_PATTERN
