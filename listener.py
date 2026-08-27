#!/usr/bin/env python3
"""listener.py — консоль оператора для lab-agent (терминал 1).

Слушает TCP, ждёт подключения агента, дальше интерактивный ввод команд.
Выход из оператора: Ctrl+C. Выход агента: команда exit.
"""
import re
import socket
import sys

HOST = "127.0.0.1"
PORT = 4444
SENT = re.compile(rb"__END__ ([^\r\n]+)\r?\n")


def dec(b: bytes) -> str:
    """cmd на винде пишет в CP866; пробуем utf-8, потом cp866."""
    for enc in ("utf-8", "cp866"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("latin-1")


def roundtrip(conn: socket.socket, cmd: str):
    conn.sendall(cmd.encode("utf-8") + b"\n")
    buf = b""
    while True:
        d = conn.recv(65536)
        if not d:
            raise ConnectionError("агент закрыл соединение")
        buf += d
        m = SENT.search(buf)
        if m:
            return m.group(1).decode(), buf[: m.start()]


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[operator] жду агента на {HOST}:{PORT} ...")
    conn, addr = srv.accept()
    print(f"[operator] агент подключился: {addr}")
    while True:
        try:
            cmd = input("lab> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[operator] выходим")
            break
        if not cmd:
            continue
        try:
            code, body = roundtrip(conn, cmd)
        except ConnectionError as e:
            print(f"[operator] {e}")
            break
        text = dec(body)
        if text.strip():
            print(text.rstrip("\n"))
        print(f"[exit:{code}]")
        if cmd == "exit":
            break


if __name__ == "__main__":
    main()
