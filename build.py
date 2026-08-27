#!/usr/bin/env python3
"""build.bat-альтернатива: сборка lab-agent через MSYS2 gcc.

На этой машине gcc требует PATH с C:/msys64/mingw64/bin (DLL: libgmp, libmpfr и др.),
иначе cc1.exe молча падает с 0xC0000135. Скрипт добавляет путь сам.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GCC = "C:/msys64/mingw64/bin/gcc.exe"
env = os.environ.copy()
env["PATH"] = "C:/msys64/mingw64/bin;" + env.get("PATH", "")

r = subprocess.run(
    [GCC, "-O2", "-Wall", "lab-agent.c", "-o", "lab-agent.exe", "-lws2_32"],
    cwd=HERE, capture_output=True, text=True, env=env,
)
print(r.stderr or "(no warnings)")
if r.returncode == 0:
    print("OK -> lab-agent.exe")
sys.exit(r.returncode)
