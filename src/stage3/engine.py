from __future__ import annotations

import os
from typing import Dict, List, Optional

from ..common import log
from ..constants import STAGE3_POOL_SIZE, STAGE3_WORKERS
from .backends.xray_api import XrayApiBackend
from .backends.base import Stage3Backend
from .backends.pool import PoolBackend
from .backends.subprocess import SubprocessBackend
from .metrics import log_summary_if_debug, reset_summary
from .types import BackendKind

_engine: Optional['Stage3Engine'] = None


def _backend_kind() -> BackendKind:
    raw = os.environ.get('OPENRAY_STAGE3_BACKEND', 'pool').strip().lower()
    if raw in ('api', 'xray_api'):
        return BackendKind.API
    if raw in ('pool', 'worker', 'workers'):
        return BackendKind.POOL
    return BackendKind.SUBPROCESS


def _make_backend(kind: BackendKind) -> Stage3Backend:
    if kind == BackendKind.API:
        return XrayApiBackend()
    if kind == BackendKind.POOL:
        return PoolBackend()
    return SubprocessBackend()


class Stage3Engine:
    def __init__(self, backend: Optional[Stage3Backend] = None, kind: Optional[BackendKind] = None):
        self._kind = kind or _backend_kind()
        self._backend = backend or _make_backend(self._kind)
        reset_summary(self._kind.value)

    @property
    def backend_kind(self) -> BackendKind:
        return self._kind

    def validate_one(self, uri: str, timeout_s: int = 60) -> Optional[bool]:
        return self._backend.validate_one(uri, timeout_s)

    def validate_many(self, uris: List[str], timeout_s: int) -> Dict[str, Optional[bool]]:
        if not uris:
            return {}
        reset_summary(self._kind.value)
        pool_size = int(os.environ.get('OPENRAY_STAGE3_POOL_SIZE', '0') or 0) or int(STAGE3_POOL_SIZE)
        log(
            f"Stage3 validate_many: backend={self._kind.value} n={len(uris)} "
            f"timeout_s={timeout_s} pool_size={pool_size}"
        )
        results = self._backend.validate_many(uris, timeout_s)
        log_summary_if_debug()
        return results

    def shutdown(self) -> None:
        self._backend.shutdown()


def get_engine(force_new: bool = False) -> Stage3Engine:
    global _engine
    kind = _backend_kind()
    if force_new or _engine is None or _engine.backend_kind != kind:
        if _engine is not None:
            _engine.shutdown()
        _engine = Stage3Engine(kind=kind)
    return _engine
