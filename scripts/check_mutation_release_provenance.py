from __future__ import annotations

import argparse
import ast
import re
import sys
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agent_assure.artifact_io import git_file_bytes, git_output  # noqa: E402
from agent_assure.mutation.catalog import (  # noqa: E402
    CatalogIntegrityError,
    implementation_component_sha256,
    introduction_components_from_source,
    lf_normalized_sha256,
    registered_operators,
    target_control_component_path,
)
from agent_assure.schema.mutation import OperatorProvenance  # noqa: E402

CreationSourceLoader = Callable[[str, str], bytes]
RevisionAncestryChecker = Callable[[str, str], bool]

_INTRODUCTION_BINDING_PATHS = (
    "agent_assure/mutation/catalog.py",
    "agent_assure/mutation/operators.py",
)
_INTRODUCTION_SNAPSHOT_PATH = "agent_assure/mutation/introduction_snapshots.json"
_TARGET_CONTROL_IMPLEMENTATION_FUNCTIONS = {
    "material_claims_have_evidence": "evaluate_material_claim_evidence",
    "human_review_required": "evaluate_human_review_requirement",
    "tool_allowlist": "evaluate_tool_allowlist",
    "evidence_provenance_identity": "evaluate_evidence_provenance_identity",
    "redaction_required": "evaluate_redaction",
    "valid_record_required": "_runs_by_case",
    "runset_completion_required": "_runset_status_results",
}
_SEMVER_PATTERN = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:rc([1-9]\d*))?$")
_GIT_COMMIT_PATTERN = re.compile(r"^(?:git:)?[a-f0-9]{40}$")


def release_provenance_failures(
    provenances: Iterable[OperatorProvenance],
    *,
    expected_release: str,
    release_commit: str | None = None,
    creation_source_loader: CreationSourceLoader | None = None,
    ancestry_checker: RevisionAncestryChecker | None = None,
) -> tuple[str, ...]:
    """Return deterministic failures that make an operator unsafe to release."""
    try:
        expected_release_precedence = _semver_precedence(expected_release)
    except ValueError:
        raise ValueError(f"invalid expected release version: {expected_release!r}") from None
    failures: list[str] = []
    source_cache: dict[tuple[str, str], bytes] = {}

    def load_source(commit: str, relative_path: str) -> bytes:
        key = (commit, relative_path)
        if key not in source_cache:
            if creation_source_loader is None:
                raise RuntimeError("no revision source loader")
            source_cache[key] = creation_source_loader(commit, relative_path)
        return source_cache[key]

    for provenance in sorted(provenances, key=lambda item: item.operator_id):
        prefix = f"operator {provenance.operator_id!r}"
        introduction_commit = provenance.introduced_at_commit
        immutable_commit = (
            introduction_commit
            if introduction_commit is not None and introduction_commit != "git:uncommitted"
            else None
        )
        if immutable_commit is None:
            failures.append(f"{prefix} has no immutable introduction commit")
        if provenance.introduced_in_release is None:
            failures.append(f"{prefix} has no introduction release")
        else:
            try:
                introduction_precedence = _semver_precedence(provenance.introduced_in_release)
            except ValueError:
                failures.append(f"{prefix} has an invalid introduction release")
            else:
                if introduction_precedence > expected_release_precedence:
                    failures.append(
                        f"{prefix} introduction release "
                        f"{provenance.introduced_in_release!r} is newer than expected "
                        f"release {expected_release!r}"
                    )
        if not provenance.implementation_components:
            failures.append(f"{prefix} has no implementation-component manifest")
        if not provenance.introduction_components:
            failures.append(f"{prefix} has no introduction-component snapshot")
        if not provenance.target_controls:
            failures.append(f"{prefix} has no target-control provenance")
        if immutable_commit is not None:
            ancestry_failure = _revision_ancestry_failure(
                prefix,
                ancestor=immutable_commit,
                descendant=release_commit,
                relationship="introduction commit is not an ancestor of the release commit",
                checker=ancestry_checker,
            )
            if ancestry_failure is not None:
                failures.append(ancestry_failure)
        if immutable_commit is not None and provenance.introduction_components:
            implementation_failure = _introduction_snapshot_failure(
                provenance,
                immutable_commit=immutable_commit,
                source_loader=(load_source if creation_source_loader is not None else None),
            )
            if implementation_failure is not None:
                failures.append(implementation_failure)
        for target in provenance.target_controls:
            target_prefix = f"{prefix} target control {target.control_id!r}"
            if immutable_commit is not None:
                ancestry_failure = _revision_ancestry_failure(
                    target_prefix,
                    ancestor=target.first_seen_commit,
                    descendant=immutable_commit,
                    relationship=(
                        "first-seen commit is not an ancestor of the operator introduction commit"
                    ),
                    checker=ancestry_checker,
                )
                if ancestry_failure is not None:
                    failures.append(ancestry_failure)
            if target.digest_at_operator_creation == "0" * 64:
                failures.append(f"{target_prefix} has no authored creation digest")
            if immutable_commit is None:
                continue
            try:
                source_path = target_control_component_path(target.control_id)
            except CatalogIntegrityError:
                failures.append(f"{target_prefix} has no provenance source mapping")
                continue
            implementation_function = _TARGET_CONTROL_IMPLEMENTATION_FUNCTIONS.get(
                target.control_id
            )
            if implementation_function is None:
                failures.append(
                    f"{target_prefix} has no provenance implementation-function mapping"
                )
            if creation_source_loader is None:
                failures.append(f"{target_prefix} first-seen declaration was not verified")
                if target.digest_at_operator_creation == "0" * 64:
                    continue
                failures.append(f"{target_prefix} creation digest was not verified")
                continue
            if implementation_function is not None:
                try:
                    first_seen_source = load_source(target.first_seen_commit, source_path)
                except Exception:
                    failures.append(
                        f"{target_prefix} source is unavailable at the first-seen commit"
                    )
                else:
                    try:
                        declares_control = _source_declares_control_id(
                            first_seen_source,
                            relative_path=source_path,
                            control_id=target.control_id,
                            implementation_function=implementation_function,
                        )
                    except Exception:
                        failures.append(
                            f"{target_prefix} source is unparseable at the first-seen commit"
                        )
                    else:
                        if not declares_control:
                            failures.append(
                                f"{target_prefix} is not declared by an exact "
                                "ControlResult control_id keyword literal in mapped "
                                f"function {implementation_function!r} at the first-seen commit"
                            )
            if target.digest_at_operator_creation == "0" * 64:
                continue
            try:
                source = load_source(immutable_commit, source_path)
            except Exception:
                failures.append(f"{target_prefix} source is unavailable at the introduction commit")
                continue
            if lf_normalized_sha256(source) != target.digest_at_operator_creation:
                failures.append(
                    f"{target_prefix} creation digest does not match the introduction commit"
                )
    return tuple(failures)


def _source_declares_control_id(
    source: bytes,
    *,
    relative_path: str,
    control_id: str,
    implementation_function: str,
) -> bool:
    """Return whether the mapped function contains a non-false-branch literal."""
    tree = ast.parse(source, filename=relative_path)
    functions = tuple(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == implementation_function
    )
    return len(functions) == 1 and _statements_declare_control_id(
        functions[0].body,
        control_id,
    )


def _statements_declare_control_id(
    statements: Iterable[ast.stmt],
    control_id: str,
) -> bool:
    for statement in statements:
        if _node_declares_control_id(statement, control_id):
            return True
        if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            return False
    return False


def _nodes_declare_control_id(
    nodes: Iterable[ast.AST],
    control_id: str,
) -> bool:
    return any(_node_declares_control_id(node, control_id) for node in nodes)


def _node_declares_control_id(node: ast.AST, control_id: str) -> bool:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return False
    if isinstance(node, ast.Call) and _is_control_result_literal(node, control_id):
        return True
    if isinstance(node, ast.If):
        truth = _static_truth_value(node.test)
        return (
            _node_declares_control_id(node.test, control_id)
            or (truth is not False and _statements_declare_control_id(node.body, control_id))
            or (truth is not True and _statements_declare_control_id(node.orelse, control_id))
        )
    if isinstance(node, ast.IfExp):
        truth = _static_truth_value(node.test)
        return (
            _node_declares_control_id(node.test, control_id)
            or (truth is not False and _node_declares_control_id(node.body, control_id))
            or (truth is not True and _node_declares_control_id(node.orelse, control_id))
        )
    if isinstance(node, ast.While):
        truth = _static_truth_value(node.test)
        return (
            _node_declares_control_id(node.test, control_id)
            or (truth is not False and _statements_declare_control_id(node.body, control_id))
            or _statements_declare_control_id(node.orelse, control_id)
        )
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            if _node_declares_control_id(value, control_id):
                return True
            truth = _static_truth_value(value)
            if isinstance(node.op, ast.And) and truth is False:
                return False
            if isinstance(node.op, ast.Or) and truth is True:
                return False
        return False
    for field_name, value in ast.iter_fields(node):
        if isinstance(value, ast.AST):
            if _node_declares_control_id(value, control_id):
                return True
        elif isinstance(value, list):
            statements = tuple(item for item in value if isinstance(item, ast.stmt))
            if field_name in {"body", "orelse", "finalbody"} and len(statements) == len(value):
                if _statements_declare_control_id(statements, control_id):
                    return True
            elif _nodes_declare_control_id(
                (item for item in value if isinstance(item, ast.AST)),
                control_id,
            ):
                return True
    return False


def _is_control_result_literal(node: ast.Call, control_id: str) -> bool:
    return (
        isinstance(node.func, ast.Name)
        and node.func.id == "ControlResult"
        and any(
            keyword.arg == "control_id"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
            and keyword.value.value == control_id
            for keyword in node.keywords
        )
    )


def _static_truth_value(node: ast.expr) -> bool | None:
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and not node.elts:
        return False
    if isinstance(node, ast.Dict) and not node.keys:
        return False
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        operand = _static_truth_value(node.operand)
        return None if operand is None else not operand
    if isinstance(node, ast.BoolOp):
        values = tuple(_static_truth_value(value) for value in node.values)
        if isinstance(node.op, ast.And):
            if False in values:
                return False
            return True if all(value is True for value in values) else None
        if True in values:
            return True
        return False if all(value is False for value in values) else None
    return None


def _semver_precedence(value: str) -> tuple[int, int, int, int, int]:
    match = _SEMVER_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(value)
    major, minor, patch, release_candidate = match.groups()
    return (
        int(major),
        int(minor),
        int(patch),
        1 if release_candidate is None else 0,
        int(release_candidate or 0),
    )


def _revision_ancestry_failure(
    prefix: str,
    *,
    ancestor: str,
    descendant: str | None,
    relationship: str,
    checker: RevisionAncestryChecker | None,
) -> str | None:
    if descendant is None or checker is None:
        return f"{prefix} revision ancestry was not verified"
    try:
        is_ancestor = checker(ancestor, descendant)
    except Exception:
        return f"{prefix} revision ancestry could not be verified"
    if not is_ancestor:
        return f"{prefix} {relationship}"
    return None


def _introduction_snapshot_failure(
    provenance: OperatorProvenance,
    *,
    immutable_commit: str,
    source_loader: CreationSourceLoader | None,
) -> str | None:
    """Verify the authored introduction snapshot at the claimed commit.

    The current implementation manifest identifies the implementation being
    released. It is intentionally not replayed against an older introduction
    commit: legitimate maintenance changes its bytes. This separate, frozen
    snapshot proves that the catalog and transformation bindings existed when
    the operator claims to have been introduced.
    """
    prefix = f"operator {provenance.operator_id!r}"
    components_by_path = {
        component.relative_path: component for component in provenance.introduction_components
    }
    for relative_path in _INTRODUCTION_BINDING_PATHS:
        if relative_path not in components_by_path:
            return f"{prefix} introduction snapshot does not bind {relative_path!r}"
    if source_loader is None:
        return f"{prefix} introduction snapshot was not verified"
    try:
        snapshot_source = source_loader(immutable_commit, _INTRODUCTION_SNAPSHOT_PATH)
    except Exception:
        return f"{prefix} authored introduction snapshot is unavailable at the introduction commit"
    try:
        authored_components = introduction_components_from_source(
            provenance.operator_id,
            snapshot_source,
        )
    except CatalogIntegrityError:
        return f"{prefix} authored introduction snapshot is invalid at the introduction commit"
    if authored_components != provenance.introduction_components:
        return (
            f"{prefix} introduction components do not match the snapshot authored at introduction"
        )

    binding_order = {path: index for index, path in enumerate(_INTRODUCTION_BINDING_PATHS)}
    components = sorted(
        provenance.introduction_components,
        key=lambda item: (
            binding_order.get(item.relative_path, len(binding_order)),
            item.component_id,
            item.relative_path,
        ),
    )
    for component in components:
        component_prefix = f"{prefix} introduction component {component.relative_path!r}"
        try:
            source = source_loader(immutable_commit, component.relative_path)
        except Exception:
            return f"{component_prefix} source is unavailable at the introduction commit"
        if implementation_component_sha256(component.relative_path, source) != component.sha256:
            return f"{component_prefix} digest does not match the introduction commit"
    return None


def registered_release_provenance_failures(
    *,
    expected_release: str,
    release_commit: str | None = None,
) -> tuple[str, ...]:
    try:
        provenances = tuple(item.descriptor.provenance for item in registered_operators())
    except CatalogIntegrityError:
        return ("built-in mutation catalog integrity could not be established",)
    if release_commit is None:
        current_commit = git_output(ROOT, "rev-parse", "HEAD")
        if current_commit is None:
            return ("release commit could not be resolved for provenance validation",)
        release_commit = f"git:{current_commit}"
    elif _GIT_COMMIT_PATTERN.fullmatch(release_commit) is None:
        return (f"release commit is not an immutable Git commit: {release_commit!r}",)
    return release_provenance_failures(
        provenances,
        expected_release=expected_release,
        release_commit=release_commit,
        creation_source_loader=_git_creation_source,
        ancestry_checker=_git_is_ancestor,
    )


def _git_creation_source(commit: str, relative_path: str) -> bytes:
    revision = commit.removeprefix("git:")
    if _GIT_COMMIT_PATTERN.fullmatch(revision) is None:
        raise ValueError(f"invalid provenance commit: {commit!r}")
    if "\\" in relative_path or ".." in relative_path.split("/"):
        raise ValueError(f"unsafe provenance component path: {relative_path!r}")
    if relative_path.startswith("agent_assure/"):
        repository_path = f"src/{relative_path}"
    elif relative_path.startswith("schemas/"):
        repository_path = relative_path
    else:
        raise ValueError(f"unsupported provenance component path: {relative_path!r}")
    return git_file_bytes(ROOT, revision, repository_path)


def _git_is_ancestor(ancestor: str, descendant: str) -> bool:
    ancestor_revision = ancestor.removeprefix("git:")
    descendant_revision = descendant.removeprefix("git:")
    return (
        git_output(
            ROOT,
            "merge-base",
            "--is-ancestor",
            ancestor_revision,
            descendant_revision,
            allow_empty=True,
        )
        is not None
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate mutation provenance against a concrete release version."
    )
    parser.add_argument("--expected-release", required=True)
    parser.add_argument("--release-commit", default=None)
    args = parser.parse_args(argv)
    failures = registered_release_provenance_failures(
        expected_release=args.expected_release,
        release_commit=args.release_commit,
    )
    if failures:
        print("mutation release provenance is incomplete:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1
    print("mutation release provenance is complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
