#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the Lua client against the real control handler with stubbed policy/BPF."""

import os
from pathlib import Path
import select
import shlex
import subprocess
import sys
import tempfile


def main():
    lua = shlex.split(sys.argv[1] if len(sys.argv) > 1 else "lua")
    server = str(Path(sys.argv[2] if len(sys.argv) > 2 else "tests/test_ctl").resolve())
    with tempfile.TemporaryDirectory(prefix="voidgate-lua-") as directory:
        path = os.path.join(directory, "control.sock")
        process = subprocess.Popen([server, path], stdout=subprocess.PIPE, text=True)
        try:
            ready, _, _ = select.select([process.stdout], [], [], 5)
            if not ready or process.stdout.readline().strip() != "ready":
                raise RuntimeError("control test server failed to start")
            subprocess.run(lua + ["tests/test_lua.lua", path], check=True, timeout=20)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdout.close()


if __name__ == "__main__":
    main()
