from __future__ import annotations

import os
import queue
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional

from ...constants import REPO_ROOT, STAGE3_WORKERS, V2RAY_CORE_PATH
from ..config_helpers import prepare_config_for_uri, worker_config_path, write_config
from ..metrics import record_check
from ..probe import probe_http_proxy
from ..types import TimingStats
from .base import Stage3Backend
from .subprocess import _min_attempt_seconds, _stage3_env_int, _terminate_proc


class _PoolWorker:
    def __init__(self, worker_id: int, http_port: int, core_path: str, state_dir: str, recycle_every: int):
        self.worker_id = worker_id
        self.http_port = http_port
        self.core_path = core_path
        self.config_path = worker_config_path(state_dir, worker_id)
        self.recycle_every = recycle_every
        self._proc: Optional[subprocess.Popen] = None
        self._jobs = 0
        self._lock = threading.Lock()

    def _creationflags(self) -> int:
        return (
            subprocess.CREATE_NO_WINDOW
            if os.name == 'nt' and hasattr(subprocess, 'CREATE_NO_WINDOW')
            else 0
        )

    def stop(self) -> None:
        with self._lock:
            _terminate_proc(self._proc)
            self._proc = None

    def _wait_ready(self, proc: subprocess.Popen, fast_fail_s: float) -> bool:
        start = time.time()
        while time.time() - start < 1.5:
            if proc.poll() is not None:
                return (time.time() - start) > fast_fail_s
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    if s.connect_ex(('127.0.0.1', self.http_port)) == 0:
                        return True
            except Exception:
                pass
            time.sleep(0.08)
        return False

    def run_check(self, uri: str, timeout_s: int) -> Optional[bool]:
        timing = TimingStats()
        t0 = time.perf_counter()
        try:
            cfg = prepare_config_for_uri(uri, self.http_port)
            timing.config_ms = (time.perf_counter() - t0) * 1000
            if not cfg:
                record_check(None, timing)
                return None

            with self._lock:
                if self._jobs >= self.recycle_every:
                    _terminate_proc(self._proc)
                    self._proc = None
                    self._jobs = 0

                t_spawn = time.perf_counter()
                write_config(self.config_path, cfg)
                if self._proc is not None:
                    _terminate_proc(self._proc)
                    self._proc = None

                try:
                    self._proc = subprocess.Popen(
                        [self.core_path, '-config', self.config_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=self._creationflags(),
                    )
                except Exception:
                    record_check(None, timing)
                    return None
                timing.spawn_ms = (time.perf_counter() - t_spawn) * 1000

                fast_fail = _stage3_env_int('OPENRAY_STAGE3_FAST_FAIL_MS', 200, 50, 5000) / 1000.0
                t_ready = time.perf_counter()
                ready = self._wait_ready(self._proc, fast_fail)
                timing.ready_ms = (time.perf_counter() - t_ready) * 1000
                if not ready or self._proc.poll() is not None:
                    _terminate_proc(self._proc)
                    self._proc = None
                    record_check(False, timing)
                    return False

                self._jobs += 1

            attempt_timeout = max(_min_attempt_seconds(), float(timeout_s))
            t_fetch = time.perf_counter()
            ok = probe_http_proxy(self.http_port, time.time() + attempt_timeout)
            timing.fetch_ms = (time.perf_counter() - t_fetch) * 1000

            with self._lock:
                _terminate_proc(self._proc)
                self._proc = None

            result = True if ok else False
            record_check(result, timing)
            return result
        except Exception:
            record_check(None, timing)
            return None


class PoolBackend(Stage3Backend):
    def __init__(self, pool_size: Optional[int] = None):
        path = (V2RAY_CORE_PATH or '').strip()
        if not path or not os.path.exists(path):
            self._enabled = False
            self._workers: List[_PoolWorker] = []
            return

        self._enabled = True
        size = pool_size if pool_size is not None else _stage3_env_int(
            'OPENRAY_STAGE3_POOL_SIZE', int(STAGE3_WORKERS), 1, 512
        )
        base_port = _stage3_env_int('OPENRAY_STAGE3_BASE_PORT', 31000, 1024, 60000)
        recycle = _stage3_env_int('OPENRAY_STAGE3_RECYCLE_EVERY', 100, 1, 10000)
        state_dir = os.path.join(REPO_ROOT, '.state')

        self._workers = [
            _PoolWorker(i, base_port + i, path, state_dir, recycle)
            for i in range(size)
        ]
        self._queue: queue.Queue = queue.Queue()
        for w in self._workers:
            self._queue.put(w)

    def validate_one(self, uri: str, timeout_s: int = 60) -> Optional[bool]:
        if not self._enabled:
            return None
        worker = self._queue.get()
        try:
            return worker.run_check(uri, timeout_s)
        finally:
            self._queue.put(worker)

    def validate_many(self, uris: List[str], timeout_s: int) -> Dict[str, Optional[bool]]:
        if not self._enabled:
            return {u: None for u in uris if u}
        results: Dict[str, Optional[bool]] = {}
        lock = threading.Lock()

        def _job(u: str) -> None:
            r = self.validate_one(u, timeout_s)
            with lock:
                results[u] = r

        threads: List[threading.Thread] = []
        pool_size = max(1, len(self._workers))
        pending = [u for u in uris if u]
        idx = 0
        while idx < len(pending):
            batch = pending[idx:idx + pool_size]
            idx += pool_size
            threads = [threading.Thread(target=_job, args=(u,), daemon=True) for u in batch]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        return results

    def shutdown(self) -> None:
        for w in self._workers:
            w.stop()
