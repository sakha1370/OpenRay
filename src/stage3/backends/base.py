from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from ..types import CheckResult


class Stage3Backend(ABC):
    @abstractmethod
    def validate_one(self, uri: str, timeout_s: int) -> Optional[bool]:
        ...

    def validate_many(self, uris: List[str], timeout_s: int) -> Dict[str, Optional[bool]]:
        return {u: self.validate_one(u, timeout_s) for u in uris if u}

    def shutdown(self) -> None:
        pass
