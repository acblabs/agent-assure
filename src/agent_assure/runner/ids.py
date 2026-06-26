from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid5

AGENT_ASSURE_NAMESPACE = UUID("1c7e0dfb-2d4d-5cb4-9a08-bfd7aa01a5f6")


@dataclass(frozen=True)
class DeterministicIds:
    namespace: UUID = AGENT_ASSURE_NAMESPACE

    def runset_id(self, suite_id: str, variant_id: str) -> str:
        return f"runset-{uuid5(self.namespace, f'{suite_id}:{variant_id}')}"

    def run_id(self, suite_id: str, variant_id: str, case_id: str) -> str:
        return f"run-{uuid5(self.namespace, f'{suite_id}:{variant_id}:{case_id}')}"

    def finding_id(self, run_id: str, reason_code: str) -> str:
        return f"finding-{uuid5(self.namespace, f'{run_id}:{reason_code}')}"
