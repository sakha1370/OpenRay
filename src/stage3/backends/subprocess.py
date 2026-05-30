from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import tempfile
import threading
import time
from typing import Optional

from ...constants import V2RAY_CORE_PATH
from ..config_helpers import prepare_config_for_uri
from ..metrics import record_check
from ..probe import probe_http_proxy
from ..types import TimingStats
from .base import Stage3Backend

_port_counter = 0
_port_lock = threading.Lock()
_thread_ports: dict = {}


def _stage3_env_int(name: str, default: int, min_v: int = 0, max_v: int = 100000) -> int:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        n = int(val)
    except Exception:
        return default
    return max(min_v, min(max_v, n))


def _jitter_seconds() -> float:
    ms = _stage3_env_int('OPENRAY_STAGE3_JITTER_MS', 500, 0, 5000)
    if ms <= 0:
        return 0.0
    return random.uniform(0, ms / 1000.0)


def _min_attempt_seconds() -> float:
    return float(_stage3_env_int('OPENRAY_STAGE3_MIN_ATTEMPT_S', 15, 2, 120))


def _fast_fail_seconds() -> float:
    return _stage3_env_int('OPENRAY_STAGE3_FAST_FAIL_MS', 200, 50, 5000) / 1000.0


def _pick_http_port() -> int:
    """Prefer per-thread port range to reduce bind races."""
    tid = threading.get_ident()
    base = _stage3_env_int('OPENRAY_STAGE3_BASE_PORT', 31000, 1024, 60000)
    with _port_lock:
        global _port_counter
        if tid not in _thread_ports:
            _thread_ports[tid] = base + (_port_counter % 512)
            _port_counter += 1
        preferred = _thread_ports[tid]
        _thread_ports[tid] = preferred + 1
        if _thread_ports[tid] > base + 512:
            _thread_ports[tid] = base

    for port in (preferred, preferred + 1000):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('127.0.0.1', port))
                return port
        except Exception:
            continue

    for _ in range(5):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('127.0.0.1', 0))
            port = s.getsockname()[1]
            s.close()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check_s:
                check_s.settimeout(0.1)
                if check_s.connect_ex(('127.0.0.1', port)) != 0:
                    return port
        except Exception:
            continue
    return random.randint(20000, 60000)


def _terminate_proc(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        proc.terminate()
    except Exception:
        pass
    try:
        proc.wait(timeout=0.5)
    except Exception:
        try:
            if hasattr(proc, 'kill'):
                proc.kill()
        except Exception:
            pass


class SubprocessBackend(Stage3Backend):
    """One Xray process per validation (legacy behavior, with timing hooks)."""

    def validate_one(self, uri: str, timeout_s: int = 60) -> Optional[bool]:
        timing = TimingStats()
        t0 = time.perf_counter()
        try:
            path = (V2RAY_CORE_PATH or '').strip()
            if not path or not os.path.exists(path):
                record_check(None, timing)
                return None

            http_port = _pick_http_port()
            cfg = prepare_config_for_uri(uri, http_port)
            timing.config_ms = (time.perf_counter() - t0) * 1000
            if not cfg:
                record_check(None, timing)
                return None

            time.sleep(_jitter_seconds())
            max_retries = 1
            ok = False
            proc = None
            tmp_path = None
            fast_fail = _fast_fail_seconds()

            for attempt in range(max_retries):
                if proc is not None:
                    _terminate_proc(proc)
                    proc = None

                t_spawn = time.perf_counter()
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
                tmp_path = tmp.name
                try:
                    tmp.write(json.dumps(cfg).encode('utf-8'))
                    tmp.flush()
                finally:
                    tmp.close()

                creation = (
                    subprocess.CREATE_NO_WINDOW
                    if os.name == 'nt' and hasattr(subprocess, 'CREATE_NO_WINDOW')
                    else 0
                )
                try:
                    proc = subprocess.Popen(
                        [path, '-config', tmp_path],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=creation,
                    )
                except Exception:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
                    tmp_path = None
                    continue
                timing.spawn_ms += (time.perf_counter() - t_spawn) * 1000

                t_ready = time.perf_counter()
                ready = False
                start_wait = time.time()
                while time.time() - start_wait < 2.0:
                    if proc.poll() is not None:
                        if (time.time() - start_wait) <= fast_fail:
                            break
                        break
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_s:
                            test_s.settimeout(0.1)
                            if test_s.connect_ex(('127.0.0.1', http_port)) == 0:
                                ready = True
                                break
                    except Exception:
                        pass
                    time.sleep(0.1)
                timing.ready_ms += (time.perf_counter() - t_ready) * 1000

                if not ready or proc.poll() is not None:
                    _terminate_proc(proc)
                    proc = None
                    if tmp_path:
                        try:
                            os.unlink(tmp_path)
                        except Exception:
                            pass
                        tmp_path = None
                    continue

                attempt_timeout = max(_min_attempt_seconds(), float(timeout_s) / float(max_retries))
                deadline = time.time() + attempt_timeout
                t_fetch = time.perf_counter()
                ok = probe_http_proxy(http_port, deadline)
                timing.fetch_ms += (time.perf_counter() - t_fetch) * 1000
                if ok:
                    break

                if tmp_path:
                    try:
                        os.unlink(tmp_path)
                    except Exception:
                        pass
                    tmp_path = None

            t_teardown = time.perf_counter()
            _terminate_proc(proc)
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
            timing.teardown_ms = (time.perf_counter() - t_teardown) * 1000

            result = True if ok else False
            record_check(result, timing)
            return result
        except Exception:
            record_check(None, timing)
            return None
