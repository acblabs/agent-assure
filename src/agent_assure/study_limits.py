"""Shared hard bounds for real-model study publication and verification."""

from agent_assure.io_limits import MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES
from agent_assure.schema.study import MAX_STUDY_CONDITIONS

# Six replay artifacts plus optional statistical-method and post-execution
# review receipts. Both receipts are required for publication readiness but
# may be omitted from draft or non-executed replay bundles.
STUDY_BUNDLE_BASE_FILE_COUNT = 8
STUDY_BUNDLE_FILES_PER_EXECUTED_CONDITION = 5
MAX_STUDY_BUNDLE_FILES = (
    STUDY_BUNDLE_BASE_FILE_COUNT + STUDY_BUNDLE_FILES_PER_EXECUTED_CONDITION * MAX_STUDY_CONDITIONS
)
# The v0.6.6 empirical checkpoint has 168 paired cases. This cap leaves room
# for bounded repetitions while preventing a release check from retaining the
# theoretical multi-gigabyte product of every per-file maximum.
MAX_STUDY_BUNDLE_TOTAL_BYTES = 256 * 1024 * 1024
# Each executed condition contains two journal-bearing RunSets. Their dedicated
# per-file ceiling accommodates the declared 4,096-cell bound; the aggregate
# bundle ceiling above remains the stricter cross-condition retention bound.
MAX_STUDY_RUNSET_JSON_BYTES = MAX_JOURNAL_BEARING_RUNSET_JSON_BYTES

__all__ = [
    "MAX_STUDY_BUNDLE_FILES",
    "MAX_STUDY_BUNDLE_TOTAL_BYTES",
    "MAX_STUDY_RUNSET_JSON_BYTES",
    "STUDY_BUNDLE_BASE_FILE_COUNT",
    "STUDY_BUNDLE_FILES_PER_EXECUTED_CONDITION",
]
