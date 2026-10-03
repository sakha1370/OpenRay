import subprocess
import sys
import unittest

from src.stage3.grpc_client import XrayApiSession


class CliTests(unittest.TestCase):
    def test_offline_imports_and_help(self):
        script = """
import socket,subprocess,importlib
def forbidden(*a,**k): raise AssertionError('import attempted IO')
socket.create_connection=socket.getaddrinfo=forbidden
subprocess.Popen.__init__=forbidden
for name in ['openray.cli','src.main','src.main_existing_only','src.main_for_iran','src.main_local','src.site_access_check','src.constants']:
 importlib.import_module(name)
"""
        subprocess.run([sys.executable, "-c", script], check=True, capture_output=True)
        for module in (
            "src.main",
            "src.main_existing_only",
            "src.main_for_iran",
            "src.main_local",
            "src.site_access_check",
        ):
            r = subprocess.run([sys.executable, "-m", module, "--help"], capture_output=True)
            self.assertEqual(r.returncode, 0)

    def test_grpc_failure_never_deadlocks(self):
        import threading

        class BrokenStub:
            def __call__(self, *a, **k):
                raise RuntimeError("failed RPC")

        session = XrayApiSession("127.0.0.1:1")
        session._stub = BrokenStub()
        thread = threading.Thread(target=lambda: session.remove_outbound("candidate"), daemon=True)
        thread.start()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        session.close()
