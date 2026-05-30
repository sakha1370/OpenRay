from __future__ import annotations

import concurrent.futures
import os
import queue
import socket
import subprocess
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from ...constants import REPO_ROOT, STAGE3_WORKERS, V2RAY_CORE_PATH
from ..config_helpers import (
    build_pool_daemon_config,
    prepare_config_for_uri,
    worker_config_path,
    worker_outbound_config_path,
    write_config,
)
from ..grpc_client import XrayApiSession, swap_candidate_outbound
from ..metrics import record_check
from ..probe import probe_http_proxy
from ..types import TimingStats
from .base import Stage3Backend
from .subprocess import _min_attempt_seconds, _stage3_env_int, _terminate_proc


def _pool_reuse_enabled() -> bool:
    val = os.environ.get('OPENRAY_STAGE3_POOL_REUSE', '1').strip().lower()
    return val not in ('0', 'false', 'no', 'off')


ProbeFn = Callable[[int, float], Any]


def _probe_result_ok(result: Any) -> Optional[bool]:
    if result is None:
        return None
    if isinstance(result, dict):
        return all(bool(v) for v in result.values()) if result else False
    return True if result else False


def _run_probe(http_port: int, attempt_timeout: float, probe_fn: Optional[ProbeFn]) -> Any:
    deadline = time.time() + attempt_timeout
    if probe_fn is not None:
        return probe_fn(http_port, deadline)
    return probe_http_proxy(http_port, deadline)


class _PoolWorker:
    def __init__(self, worker_id: int, http_port: int, api_port: int, core_path: str, state_dir: str, recycle_every: int):
        self.worker_id = worker_id
        self.http_port = http_port
        self.api_port = api_port
        self.api_addr = f'127.0.0.1:{api_port}'
        self.core_path = core_path
        self.config_path = worker_config_path(state_dir, worker_id)
        self.outbound_path = worker_outbound_config_path(state_dir, worker_id)
        self.recycle_every = recycle_every
        self._proc: Optional[subprocess.Popen] = None
        self._jobs = 0
        self._lock = threading.Lock()
        self._reuse = _pool_reuse_enabled()
        self._api_session = XrayApiSession(self.api_addr)

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
            self._jobs = 0
        self._api_session.close()

    def _port_open(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.1)
                return s.connect_ex(('127.0.0.1', port)) == 0
        except Exception:
            return False

    def _wait_ready(self, proc: subprocess.Popen, fast_fail_s: float) -> bool:
        start = time.time()
        while time.time() - start < 1.5:
            if proc.poll() is not None:
                return (time.time() - start) > fast_fail_s
            if self._port_open(self.http_port):
                return True
            time.sleep(0.08)
        return False

    def _spawn_proc(self, config_path: str) -> Optional[subprocess.Popen]:
        try:
            return subprocess.Popen(
                [self.core_path, '-config', config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=self._creationflags(),
            )
        except Exception:
            return None

    def _stop_locked(self) -> None:
        _terminate_proc(self._proc)
        self._proc = None

    def _ensure_daemon(self, timing: TimingStats) -> bool:
        fast_fail = _stage3_env_int('OPENRAY_STAGE3_FAST_FAIL_MS', 200, 50, 5000) / 1000.0
        if self._proc is not None and self._proc.poll() is None and self._port_open(self.http_port):
            return True

        t_spawn = time.perf_counter()
        self._stop_locked()
        cfg = build_pool_daemon_config(self.http_port, self.api_port)
        write_config(self.config_path, cfg)
        self._proc = self._spawn_proc(self.config_path)
        if self._proc is None:
            return False
        timing.spawn_ms += (time.perf_counter() - t_spawn) * 1000

        t_ready = time.perf_counter()
        ready = self._wait_ready(self._proc, fast_fail)
        timing.ready_ms += (time.perf_counter() - t_ready) * 1000
        if not ready or self._proc.poll() is not None:
            self._stop_locked()
            return False
        return True

    def _swap_outbound(self, outbound: Dict, timing: TimingStats) -> bool:
        t_swap = time.perf_counter()
        ok = swap_candidate_outbound(
            self.core_path,
            self.api_addr,
            outbound,
            self.outbound_path,
            session=self._api_session,
        )
        timing.config_ms += (time.perf_counter() - t_swap) * 1000
        return ok

    def _run_check_restart(
        self, uri: str, timeout_s: int, timing: TimingStats, probe_fn: Optional[ProbeFn] = None
    ) -> Optional[Any]:
        """Legacy one-shot Xray process per check (fallback)."""
        try:
            cfg = prepare_config_for_uri(uri, self.http_port)
            if not cfg:
                record_check(None, timing)
                return None

            with self._lock:
                if self._jobs >= self.recycle_every:
                    self._stop_locked()
                    self._jobs = 0

                t_spawn = time.perf_counter()
                write_config(self.config_path, cfg)
                self._stop_locked()
                self._proc = self._spawn_proc(self.config_path)
                if self._proc is None:
                    record_check(None, timing)
                    return None
                timing.spawn_ms += (time.perf_counter() - t_spawn) * 1000

                fast_fail = _stage3_env_int('OPENRAY_STAGE3_FAST_FAIL_MS', 200, 50, 5000) / 1000.0
                t_ready = time.perf_counter()
                ready = self._wait_ready(self._proc, fast_fail)
                timing.ready_ms += (time.perf_counter() - t_ready) * 1000
                if not ready or self._proc.poll() is not None:
                    self._stop_locked()
                    record_check(False, timing)
                    return False

                self._jobs += 1

            attempt_timeout = max(_min_attempt_seconds(), float(timeout_s))
            t_fetch = time.perf_counter()
            ok = _run_probe(self.http_port, attempt_timeout, probe_fn)
            timing.fetch_ms += (time.perf_counter() - t_fetch) * 1000

            with self._lock:
                self._stop_locked()

            record_check(_probe_result_ok(ok), timing)
            return ok
        except Exception:
            with self._lock:
                self._stop_locked()
            record_check(None, timing)
            return None

    def _run_check_reuse(
        self, uri: str, timeout_s: int, timing: TimingStats, probe_fn: Optional[ProbeFn] = None
    ) -> Optional[Any]:
        try:
            from ...v2ray import build_outbound_for_uri
        except Exception:
            return self._run_check_restart(uri, timeout_s, timing, probe_fn)

        t_cfg = time.perf_counter()
        outbound = build_outbound_for_uri(uri)
        timing.config_ms += (time.perf_counter() - t_cfg) * 1000
        if not outbound:
            record_check(None, timing)
            return None

        with self._lock:
            if self._jobs >= self.recycle_every:
                self._stop_locked()
                self._jobs = 0

            if not self._ensure_daemon(timing):
                record_check(False, timing)
                return False

            swap_ok = self._swap_outbound(outbound, timing)
            if not swap_ok:
                self._stop_locked()
            else:
                self._jobs += 1

        if not swap_ok:
            return self._run_check_restart(uri, timeout_s, timing, probe_fn)

        attempt_timeout = max(_min_attempt_seconds(), float(timeout_s))
        t_fetch = time.perf_counter()
        ok = _run_probe(self.http_port, attempt_timeout, probe_fn)
        timing.fetch_ms += (time.perf_counter() - t_fetch) * 1000

        record_check(_probe_result_ok(ok), timing)
        return ok

    def run_check(
        self, uri: str, timeout_s: int, probe_fn: Optional[ProbeFn] = None
    ) -> Optional[Any]:
        timing = TimingStats()
        if self._reuse:
            return self._run_check_reuse(uri, timeout_s, timing, probe_fn)
        return self._run_check_restart(uri, timeout_s, timing, probe_fn)


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

        pending = [u for u in uris if u]
        max_workers = max(1, len(self._workers))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_job, u) for u in pending]
            for fut in concurrent.futures.as_completed(futures):
                fut.result()
        return results

    def shutdown(self) -> None:
        for w in self._workers:
            w.stop()
