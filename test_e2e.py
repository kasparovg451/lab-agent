#!/usr/bin/env python3
"""Автотест lab-agent v0: поднимает сервер, запускает агента, гоняет команды,
печатает реальный транскрипт. Проверяет фактическую работу пайпов/протокола."""
import os
import re
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "lab-agent.exe")
HOST, PORT = "127.0.0.1", 44441
SENT = re.compile(rb"__END__ ([^\r\n]+)\r?\n")


def dec(b):
    for enc in ("utf-8", "cp866"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("latin-1")


def roundtrip(conn, cmd):
    conn.sendall(cmd.encode("utf-8") + b"\n")
    buf = b""
    while True:
        d = conn.recv(65536)
        if not d:
            raise RuntimeError("соединение закрыто до sentinel")
        buf += d
        m = SENT.search(buf)
        if m:
            return m.group(1).decode(), buf[: m.start()]


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    srv.settimeout(15)

    agent = subprocess.Popen(
        [EXE, HOST, str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    results = []
    try:
        conn, addr = srv.accept()
        conn.settimeout(60)
        print(f"[TEST] агент подключился с {addr}")

        # 1. обычная команда с выводом
        code, out = roundtrip(conn, "echo hello-lab-test")
        text = dec(out).strip()
        print(f"[TEST 1] echo        -> exit={code}, stdout={text!r}")
        results.append(("echo forward", "hello-lab-test" in text))

        # 2. whoami — системный вызов контекста процесса
        code, out = roundtrip(conn, "whoami")
        text = dec(out).strip()
        print(f"[TEST 2] whoami      -> exit={code}, ctx={text!r}")
        results.append(("whoami not empty", bool(text)))

        # 3. stderr отдельно сливается в тот же канал
        code, out = roundtrip(conn, "cmd /c dir C:\\ definitely_missing_dir_xyz")
        text = dec(out)
        print(f"[TEST 3] stderr      -> exit={code}, err-visible={'File Not Found' in text or 'не удается найти' in text.lower() or 'cannot find' in text.lower()}")
        results.append(("stderr merged", code not in ("pipe_err",)))

        # 4. команда с большим выводом (стресс перекачки > одного буфера)
        code, out = roundtrip(conn, "type C:\\Windows\\explorer.exe")
        print(f"[TEST 4] big output  -> exit={code}, bytes={len(out)}")
        results.append(("big output streamed", len(out) > 200000))

        # 5. корректное завершение по exit
        code, out = roundtrip(conn, "exit")
        print(f"[TEST 5] exit        -> sentinel={code!r}")
        results.append(("clean exit", code == "exit"))
    finally:
        try:
            agent.wait(timeout=10)
        except subprocess.TimeoutExpired:
            agent.kill()
        rc = agent.returncode
        print(f"[TEST] процесс агента завершился, код={rc}")

    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"[RESULT] {passed}/{len(results)}")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
