from __future__ import annotations

import concurrent.futures
import os
import queue
import threading
from typing import Dict, List, Optional, Sequence

from ...constants import REPO_ROOT, SITE_ACCESS_POOL_SIZE, V2RAY_CORE_PATH
from ..metrics import log_summary_if_debug, reset_summary
from ..probe import SiteTarget, probe_all_targets
from .base import Stage3Backend
from .pool import ProbeFn, _PoolWorker
from .subprocess import _stage3_env_int


class SiteAccessBackend(Stage3Backend):
    def __init__(
        self,
        targets: Sequence[SiteTarget],
        pool_size: Optional[int] = None,
    ):
        self._targets: List[SiteTarget] = list(targets)
        self._probe_fn: ProbeFn = self._build_probe_fn()
        path = (V2RAY_CORE_PATH or '').strip()
        if not path or not os.path.exists(path):
            self._enabled = False
            self._workers: List[_PoolWorker] = []
            return

        self._enabled = True
        size = pool_size if pool_size is not None else _stage3_env_int(
            'OPENRAY_SITE_ACCESS_POOL_SIZE', int(SITE_ACCESS_POOL_SIZE), 1, 512
        )
        base_port = _stage3_env_int('OPENRAY_STAGE3_BASE_PORT', 31000, 1024, 60000)
        recycle = _stage3_env_int('OPENRAY_STAGE3_RECYCLE_EVERY', 100, 1, 10000)
        state_dir = os.path.join(REPO_ROOT, '.state')

        self._workers = [
            _PoolWorker(
                i,
                base_port + i,
                base_port + 1000 + i,
                path,
                state_dir,
                recycle,
            )
            for i in range(size)
        ]
        self._queue: queue.Queue = queue.Queue()
        for w in self._workers:
            self._queue.put(w)

    def _build_probe_fn(self) -> ProbeFn:
        targets = self._targets

        def probe_fn(http_port: int, deadline: float):
            return probe_all_targets(http_port, deadline, targets)

        return probe_fn

    def validate_one(self, uri: str, timeout_s: int = 60) -> Optional[Dict[str, bool]]:
        if not self._enabled:
            return None
        worker = self._queue.get()
        try:
            result = worker.run_check(uri, timeout_s, probe_fn=self._probe_fn)
            if isinstance(result, dict):
                return result
            return None
        finally:
            self._queue.put(worker)

    def validate_many(
        self, uris: List[str], timeout_s: int
    ) -> Dict[str, Optional[Dict[str, bool]]]:
        if not self._enabled:
            return {u: None for u in uris if u}
        reset_summary('site_access')
        results: Dict[str, Optional[Dict[str, bool]]] = {}
        lock = threading.Lock()

        def _job(u: str) -> None:
            r = self.validate_one(u, timeout_s)
            with lock:
                results[u] = r

        pending = [u for u in uris if u]
        max_workers = max(1, len(self._workers))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_job, u) for u in pending]
            for fut in concurrent.futures.as_completed(futures):
                fut.result()
        log_summary_if_debug()
        return results

    def shutdown(self) -> None:
        for w in self._workers:
            w.stop()
