#!/usr/bin/env python3
"""verify.py — каноническая проверка проекта (build + e2e + py_compile).

Использование:
    python verify.py          # полный прогон
    python verify.py --quick  # без e2e (только сборка+синтаксис)

Финал: [VERIFY] OK — k/3 legs; exit 0/1. ЭТО официальный тест-команд проекта:
CI гоняет её же (.github/workflows/verify.yml).
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "lab-agent.exe")
QUICK = "--quick" in sys.argv

legs = []


def leg(name, ok, detail=""):
    legs.append((name, bool(ok)))
    print(f"[LEG] {name}: {'PASS' if ok else 'FAIL'} {detail}")


def tail(r, n=2000):
    return (r.stdout or "")[-n:] + (r.stderr or "")[-n:]


# LEG1: сборка агента
r = subprocess.run([sys.executable, "build.py"], cwd=HERE,
                   capture_output=True, text=True, timeout=300)
leg("build", r.returncode == 0 and os.path.exists(EXE), f"rc={r.returncode}")
if r.returncode != 0:
    print(tail(r))

# LEG2: e2e (оркестратор реального пути: listener+agent, plain+tls+wrongpin)
if not QUICK:
    r = subprocess.run([sys.executable, "test_e2e.py"], cwd=HERE,
                       capture_output=True, text=True, timeout=600)
    last = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    leg("e2e", r.returncode == 0 and "[RESULT] 19/19" in r.stdout, last)
    if r.returncode != 0:
        print(tail(r))
else:
    print("[LEG] e2e: SKIP (--quick)")

# LEG3: синтаксис python-стороны
cache = os.path.join(tempfile.gettempdir(), "pycache-lab-verify")
r = subprocess.run(
    [sys.executable, "-m", "py_compile", "listener.py", "test_e2e.py", "build.py", "verify.py"],
    cwd=HERE, capture_output=True, text=True, timeout=120,
    env={**os.environ, "PYTHONPYCACHEPREFIX": cache},
)
leg("py_compile", r.returncode == 0, f"rc={r.returncode}")
if r.returncode != 0:
    print(tail(r))

passed = sum(1 for _, ok in legs if ok)
total = len(legs)
for name, ok in legs:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
print(f"[VERIFY] {'OK' if passed == total else 'FAIL'} — {passed}/{total} legs")
sys.exit(0 if passed == total else 1)
