"""Bounded, source-aware privacy checks for release-distribution members.

The release archives are intentionally text-only except for reviewed PNG assets.
Source is parsed structurally so credential-handling vocabulary is not mistaken
for a persisted credential value. Unknown member types and undecodable text fail
closed instead of becoming an unscanned archive channel.
"""

from __future__ import annotations

import ast
import hashlib
import io
import re
import struct
import tokenize
import zipfile
import zlib
from collections.abc import Callable, Mapping, Sequence
from pathlib import PurePosixPath

from agent_assure.privacy.credential_uri import (
    PERSISTED_CREDENTIAL_NAMES,
    PERSISTED_CREDENTIAL_SUFFIXES,
    contains_credential_literal,
    contains_persisted_credential,
    matches_credential_name,
)
from agent_assure.privacy.detectors import MAX_PRIVACY_SCAN_CHARS

DISTRIBUTION_UTF8_SUFFIXES = frozenset(
    {
        ".cfg",
        ".env",
        ".html",
        ".ini",
        ".json",
        ".jsonl",
        ".keep",
        ".md",
        ".ps1",
        ".py",
        ".pyi",
        ".sh",
        ".svg",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
    }
)
DISTRIBUTION_TEXT_BASENAMES = frozenset(
    {
        "license",
        "makefile",
        "metadata",
        "pkg-info",
        "record",
        "wheel",
        ".gitignore",
        ".keep",
    }
)
_STRUCTURED_TEXT_SUFFIXES = frozenset(
    {".cfg", ".env", ".ini", ".json", ".jsonl", ".toml", ".yaml", ".yml"}
)
_FORBIDDEN_MEMBER_BASENAMES = frozenset(
    {
        ".env",
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ed25519",
        "id_rsa",
        "provider-response.json",
        "provider_response.json",
        "raw-output.json",
        "raw-provider-output.json",
        "raw_output.json",
        "secret.json",
        "secrets.json",
    }
)
_FORBIDDEN_MEMBER_SUFFIXES = (".jks", ".key", ".keystore", ".p12", ".pem", ".pfx")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_ZIP_LOCAL_HEADER_SIGNATURE = b"PK\x03\x04"
_ZIP_LOCAL_HEADER_SIZE = 30
_PNG_ALLOWED_CHUNKS = frozenset(
    {
        b"IHDR",
        b"PLTE",
        b"IDAT",
        b"IEND",
        b"tRNS",
        b"pHYs",
        b"sRGB",
        b"gAMA",
        b"cHRM",
    }
)


def validate_distribution_member_privacy(
    name: str,
    data: bytes,
    *,
    max_structural_scan_lines: int,
    max_python_member_bytes: int,
    max_python_member_lines: int,
    max_python_member_tokens: int,
    strict_python_source: bool,
    reviewed_binary_assets: Mapping[str, str] | None = None,
    allow_sensitive_fixture: bool = False,
    ast_parser: Callable[[str], ast.AST] = ast.parse,
) -> int:
    """Validate one already size-bounded regular archive member.

    ``allow_sensitive_fixture`` is intended only for an external exact-byte
    allowlist. It suppresses literal-value scanning, but never type, encoding,
    syntax, or resource-limit checks.
    """

    normalized_name = name.casefold()
    path = PurePosixPath(normalized_name)
    suffix = path.suffix
    basename = path.name
    if _has_forbidden_sensitive_path(path):
        raise ValueError("distribution contains a credential or raw-output member path")
    _reject_credential_literals(name)
    if suffix == ".png":
        expected_digest = (reviewed_binary_assets or {}).get(name)
        if (
            not normalized_name.startswith("docs/assets/")
            or expected_digest is None
            or hashlib.sha256(data).hexdigest() != expected_digest
        ):
            raise ValueError("distribution contains an unsupported binary member")
        _validate_png_without_metadata(data)
        return 0
    if suffix not in DISTRIBUTION_UTF8_SUFFIXES and basename not in DISTRIBUTION_TEXT_BASENAMES:
        raise ValueError("distribution contains a member outside the closed text inventory")
    if not data:
        return 0
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("distribution text member is not UTF-8") from exc

    line_count = text.count("\n") + 1 if text else 0
    if line_count > max_structural_scan_lines:
        raise ValueError("distribution exceeds the structural privacy-scan line limit")
    python_member = suffix in {".py", ".pyi"}
    if python_member:
        if len(data) > max_python_member_bytes:
            raise ValueError("distribution Python member exceeds the byte limit")
        if line_count > max_python_member_lines:
            raise ValueError("distribution Python member exceeds the line limit")
        _validate_python_source(
            text,
            max_tokens=max_python_member_tokens,
            scan_assignments=strict_python_source and not allow_sensitive_fixture,
            ast_parser=ast_parser,
        )
    if allow_sensitive_fixture:
        return line_count

    _reject_credential_literals(text)
    if suffix in _STRUCTURED_TEXT_SUFFIXES and not normalized_name.endswith(".schema.json"):
        _reject_structural_credentials(text)
    return line_count


def validate_zip_metadata_absent(archive: zipfile.ZipFile) -> None:
    """Reject ZIP metadata channels that are not part of wheel payload identity."""

    if archive.comment:
        raise ValueError("distribution ZIP archive comments are not supported")
    handle = archive.fp
    if handle is None:
        raise ValueError("distribution ZIP archive is closed")
    original_offset = handle.tell()
    try:
        for info in archive.infolist():
            if info.comment or info.extra:
                raise ValueError(
                    "distribution ZIP member extra fields and comments are not supported"
                )
            if info.orig_filename != info.filename:
                raise ValueError(
                    "distribution ZIP member names must not contain embedded null bytes"
                )
            handle.seek(info.header_offset)
            header = handle.read(_ZIP_LOCAL_HEADER_SIZE)
            if len(header) != _ZIP_LOCAL_HEADER_SIZE:
                raise ValueError("distribution ZIP local header is truncated")
            fields = struct.unpack("<4s5H3L2H", header)
            if fields[0] != _ZIP_LOCAL_HEADER_SIGNATURE:
                raise ValueError("distribution ZIP local header is invalid")
            local_name_size = fields[9]
            local_extra_size = fields[10]
            if local_extra_size:
                raise ValueError("distribution ZIP local extra fields are not supported")
            local_name = handle.read(local_name_size)
            if len(local_name) != local_name_size:
                raise ValueError("distribution ZIP local member name is truncated")
            encoding = "utf-8" if info.flag_bits & 0x800 else "cp437"
            if local_name != info.orig_filename.encode(encoding):
                raise ValueError("distribution ZIP local and central member names differ")
    finally:
        handle.seek(original_offset)


def _has_forbidden_sensitive_path(path: PurePosixPath) -> bool:
    folded_parts = tuple(part.casefold() for part in path.parts)
    basename = folded_parts[-1] if folded_parts else ""
    return (
        any(part in {".git", ".hg", ".svn"} for part in folded_parts)
        or basename in _FORBIDDEN_MEMBER_BASENAMES
        or basename.startswith(".env.")
        or basename.endswith(_FORBIDDEN_MEMBER_SUFFIXES)
    )


def _reject_credential_literals(text: str) -> None:
    step = max(1, MAX_PRIVACY_SCAN_CHARS - 512)
    for offset in range(0, len(text) or 1, step):
        if contains_credential_literal(text[offset : offset + MAX_PRIVACY_SCAN_CHARS]):
            raise ValueError("distribution member failed credential-literal privacy review")


def _reject_structural_credentials(text: str) -> None:
    step = max(1, MAX_PRIVACY_SCAN_CHARS - 512)
    for line in text.splitlines() or (text,):
        for offset in range(0, len(line) or 1, step):
            if contains_persisted_credential(
                line[offset : offset + MAX_PRIVACY_SCAN_CHARS],
                exact_names=PERSISTED_CREDENTIAL_NAMES,
                suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
                scan_sensitive_values=False,
            ):
                raise ValueError("distribution member failed structural privacy review")


def _validate_python_source(
    text: str,
    *,
    max_tokens: int,
    scan_assignments: bool,
    ast_parser: Callable[[str], ast.AST],
) -> None:
    try:
        for token_count, _token in enumerate(
            tokenize.generate_tokens(io.StringIO(text).readline),
            start=1,
        ):
            if token_count > max_tokens:
                raise ValueError("distribution Python member exceeds the token limit")
    except (IndentationError, tokenize.TokenError) as exc:
        raise ValueError("distribution Python member is not syntactically valid") from exc
    try:
        tree = ast_parser(text)
    except SyntaxError as exc:
        raise ValueError("distribution Python member is not syntactically valid") from exc
    if not scan_assignments:
        return

    exact_compact_names = {
        re.sub(r"[^a-z0-9]", "", value.casefold()) for value in PERSISTED_CREDENTIAL_NAMES
    }

    def credential_assignment(name: str, value: object) -> bool:
        if not isinstance(value, str | bytes) or not value:
            return False
        text_value = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else value
        compact_name = re.sub(r"[^a-z0-9]", "", name.casefold())
        if compact_name in exact_compact_names:
            return True
        if not matches_credential_name(
            name,
            exact_names=PERSISTED_CREDENTIAL_NAMES,
            suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
        ):
            return False
        if chr(92) in text_value or any(
            marker in text_value for marker in ("(?:", "[", "]", "{", "}")
        ):
            return contains_credential_literal(text_value)
        return len(text_value.strip()) >= 8

    def assignment_target_names(target: ast.expr) -> tuple[str, ...]:
        if isinstance(target, ast.Name):
            return (target.id,)
        if isinstance(target, ast.Attribute):
            return (target.attr,)
        if (
            isinstance(target, ast.Subscript)
            and isinstance(target.slice, ast.Constant)
            and isinstance(target.slice.value, str)
        ):
            return (target.slice.value,)
        if isinstance(target, ast.Tuple | ast.List):
            return tuple(name for item in target.elts for name in assignment_target_names(item))
        return ()

    for node in ast.walk(tree):
        targets: Sequence[ast.expr]
        assigned: ast.expr | None
        if isinstance(node, ast.Assign):
            targets = node.targets
            assigned = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = (node.target,)
            assigned = node.value
        elif isinstance(node, ast.NamedExpr):
            targets = (node.target,)
            assigned = node.value
        else:
            targets = ()
            assigned = None
        if isinstance(assigned, ast.Constant) and isinstance(assigned.value, str | bytes):
            names = tuple(name for target in targets for name in assignment_target_names(target))
            if any(credential_assignment(name, assigned.value) for name in names):
                raise ValueError("distribution Python member failed structural privacy review")
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and isinstance(value, ast.Constant)
                    and credential_assignment(key.value, value.value)
                ):
                    raise ValueError("distribution Python member failed structural privacy review")
        if (
            isinstance(node, ast.keyword)
            and node.arg is not None
            and isinstance(node.value, ast.Constant)
            and credential_assignment(node.arg, node.value.value)
        ):
            raise ValueError("distribution Python member failed structural privacy review")
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            positional = (*node.args.posonlyargs, *node.args.args)
            for argument, positional_default in zip(
                positional[len(positional) - len(node.args.defaults) :],
                node.args.defaults,
                strict=True,
            ):
                if isinstance(positional_default, ast.Constant) and credential_assignment(
                    argument.arg, positional_default.value
                ):
                    raise ValueError("distribution Python member failed structural privacy review")
            for argument, keyword_default in zip(
                node.args.kwonlyargs,
                node.args.kw_defaults,
                strict=True,
            ):
                if isinstance(keyword_default, ast.Constant) and credential_assignment(
                    argument.arg, keyword_default.value
                ):
                    raise ValueError("distribution Python member failed structural privacy review")


def _validate_png_without_metadata(data: bytes) -> None:
    if not data.startswith(_PNG_SIGNATURE):
        raise ValueError("reviewed PNG distribution member is malformed")
    offset = len(_PNG_SIGNATURE)
    chunk_index = 0
    ihdr: tuple[int, int, int, int] | None = None
    idat_payloads: list[bytes] = []
    idat_ended = False
    saw_iend = False
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError("reviewed PNG distribution member is truncated")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError("reviewed PNG distribution member is truncated")
        payload = data[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", data[offset + 8 + length : end])[0]
        if zlib.crc32(chunk_type + payload) & 0xFFFFFFFF != expected_crc:
            raise ValueError("reviewed PNG distribution member has an invalid checksum")
        if chunk_type not in _PNG_ALLOWED_CHUNKS:
            raise ValueError("reviewed PNG distribution member contains unapproved metadata")
        if chunk_index == 0 and chunk_type != b"IHDR":
            raise ValueError("reviewed PNG distribution member has an invalid chunk order")
        if saw_iend:
            raise ValueError("reviewed PNG distribution member contains trailing chunks")
        if chunk_type == b"IHDR":
            if ihdr is not None or length != 13:
                raise ValueError("reviewed PNG distribution member has an invalid header")
            width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            allowed_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                width == 0
                or height == 0
                or width > 8_192
                or height > 8_192
                or width * height > 32_000_000
                or bit_depth not in allowed_depths.get(color_type, set())
                or compression != 0
                or filtering != 0
                or interlace != 0
            ):
                raise ValueError("reviewed PNG distribution member has unsupported image bounds")
            ihdr = (width, height, bit_depth, color_type)
        elif chunk_type == b"IDAT":
            if ihdr is None or idat_ended:
                raise ValueError("reviewed PNG distribution member has an invalid data order")
            idat_payloads.append(payload)
        elif idat_payloads:
            idat_ended = True
        if chunk_type == b"IEND":
            if length != 0:
                raise ValueError("reviewed PNG distribution member has an invalid end chunk")
            saw_iend = True
        offset = end
        chunk_index += 1
    if not saw_iend:
        raise ValueError("reviewed PNG distribution member has no end chunk")
    if ihdr is None or not idat_payloads:
        raise ValueError("reviewed PNG distribution member has no image data")
    width, height, bit_depth, color_type = ihdr
    channel_count = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
    row_bytes = ((width * channel_count * bit_depth) + 7) // 8
    expected_decoded_bytes = height * (row_bytes + 1)
    decompressor = zlib.decompressobj()
    decoded = decompressor.decompress(b"".join(idat_payloads), expected_decoded_bytes + 1)
    if (
        len(decoded) != expected_decoded_bytes
        or not decompressor.eof
        or decompressor.unused_data
        or decompressor.unconsumed_tail
    ):
        raise ValueError("reviewed PNG distribution member has invalid compressed image data")
    stride = row_bytes + 1
    if any(decoded[offset] > 4 for offset in range(0, len(decoded), stride)):
        raise ValueError("reviewed PNG distribution member has an invalid row filter")


__all__ = [
    "DISTRIBUTION_TEXT_BASENAMES",
    "DISTRIBUTION_UTF8_SUFFIXES",
    "validate_distribution_member_privacy",
    "validate_zip_metadata_absent",
]
