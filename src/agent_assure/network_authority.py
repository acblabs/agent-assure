from __future__ import annotations

import ipaddress
import re

MAX_ENDPOINT_HOST_CHARS = 253
MAX_HOST_ENV_NAME_CHARS = 128
ENV_VAR_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"
PROVIDER_SECRET_ENV_NAME_PATTERN = (
    r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:API_KEY|PROVIDER_KEY|TEST_KEY)$"
)
CANONICAL_ENDPOINT_HOST_PATTERN = r"^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|[0-9a-f:]{2,45})$"

DISALLOWED_AMBIENT_CREDENTIAL_ENV_NAMES = frozenset(
    {
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_RUNTIME_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SECURITY_TOKEN",
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_SECRET",
        "BITBUCKET_STEP_OIDC_TOKEN",
        "CI_JOB_JWT_V2",
        "CI_JOB_TOKEN",
        "GH_TOKEN",
        "GITHUB_PAT",
        "GITHUB_TOKEN",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "IDENTITY_HEADER",
        "NPM_TOKEN",
        "SYSTEM_ACCESSTOKEN",
        "VAULT_TOKEN",
    }
)

DISALLOWED_ENDPOINT_HOSTNAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
    }
)
DISALLOWED_ENDPOINT_HOST_SUFFIXES = (
    ".arpa",
    ".internal",
    ".local",
    ".localhost",
    ".onion",
)
NONPUBLIC_RECEIPT_HOST_SUFFIXES = (
    ".example",
    ".invalid",
    ".test",
)
# Keep the endpoint policy independent of Python's evolving ipaddress
# classifications. These explicit ranges are intentionally conservative:
# outbound provider and telemetry endpoints must use ordinary globally routed
# addresses, never special-purpose address space.
DISALLOWED_ENDPOINT_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "168.63.129.16/32",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fec0::/10",
        "fe80::/10",
        "ff00::/8",
    )
)
PUBLIC_IPV6_UNICAST_NETWORK = ipaddress.ip_network("2000::/3")

_DNS_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_ADDRESS_LABEL_PATTERN = re.compile(r"^(?:0x[0-9a-f]+|[0-9]+)$")


def normalize_endpoint_host(host: str) -> str:
    """Return the canonical persisted representation of an endpoint host."""

    normalized = host.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(normalized))
    except ValueError:
        return normalized


def is_disallowed_endpoint_host(host: str) -> bool:
    """Classify statically disallowed endpoint names and special-use addresses."""

    normalized = normalize_endpoint_host(host)
    if normalized in DISALLOWED_ENDPOINT_HOSTNAMES:
        return True
    if normalized == "localhost" or normalized.endswith(DISALLOWED_ENDPOINT_HOST_SUFFIXES):
        return True
    if "%" in normalized:
        # Scoped IPv6 literals are interface-local authority and are never
        # valid public provider destinations.
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address not in PUBLIC_IPV6_UNICAST_NETWORK:
        # Provider endpoints may use ordinary global IPv6 unicast only.
        # Denying everything outside 2000::/3 closes deprecated compatible,
        # translated/embedded IPv4, future-reserved, and other special forms
        # without depending on interpreter-version ipaddress classifications.
        return True
    return any(
        address.version == network.version and address in network
        for network in DISALLOWED_ENDPOINT_NETWORKS
    )


def validate_canonical_public_endpoint_host(
    host: str,
    *,
    field_name: str = "endpoint_host",
) -> str:
    """Validate a canonical bare host without performing attacker-directed DNS."""

    normalized = normalize_endpoint_host(host)
    if host != normalized:
        raise ValueError(f"{field_name} must be a canonical normalized bare public host")
    if not normalized or len(normalized) > MAX_ENDPOINT_HOST_CHARS:
        raise ValueError(f"{field_name} must be a bounded bare public host")
    if any(marker in normalized for marker in ("/", "\\", "@", "?", "#", "*", "[", "]")):
        raise ValueError(f"{field_name} must not contain a scheme, port, path, or userinfo")

    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None
    if address is not None:
        if is_disallowed_endpoint_host(normalized):
            raise ValueError(
                f"{field_name} must not target localhost, private, link-local, "
                "reserved, multicast, or other special-use addresses"
            )
        return normalized

    if ":" in normalized:
        raise ValueError(f"{field_name} must not contain a scheme or port")
    labels = normalized.split(".")
    if all(_NUMERIC_ADDRESS_LABEL_PATTERN.fullmatch(label) is not None for label in labels):
        raise ValueError(f"{field_name} must use canonical IP address syntax")
    if len(labels) < 2 or any(_DNS_LABEL_PATTERN.fullmatch(label) is None for label in labels):
        raise ValueError(f"{field_name} must be a canonical fully qualified public hostname")
    if normalized.endswith(NONPUBLIC_RECEIPT_HOST_SUFFIXES):
        raise ValueError(f"{field_name} must not use a non-public special-use hostname")
    if is_disallowed_endpoint_host(normalized):
        raise ValueError(
            f"{field_name} must not target localhost, metadata, private, or special-use hosts"
        )
    return normalized


def validate_api_key_environment_name(
    name: str,
    *,
    field_name: str = "api_key_env",
) -> str:
    """Validate an explicit, bounded host environment credential reference."""

    if len(name) > MAX_HOST_ENV_NAME_CHARS or re.fullmatch(ENV_VAR_NAME_PATTERN, name) is None:
        raise ValueError(f"{field_name} must name a host environment variable")
    if name.upper() in DISALLOWED_AMBIENT_CREDENTIAL_ENV_NAMES:
        raise ValueError(
            f"{field_name} must not reference a high-privilege ambient CI or cloud credential"
        )
    if re.fullmatch(PROVIDER_SECRET_ENV_NAME_PATTERN, name) is None:
        raise ValueError(
            f"{field_name} must use a dedicated uppercase provider-secret name "
            "ending in _API_KEY, _PROVIDER_KEY, or _TEST_KEY"
        )
    return name
