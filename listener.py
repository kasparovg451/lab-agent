#!/usr/bin/env python3
"""listener.py — консоль оператора для lab-agent v1 (терминал 1).

Протокол v1 — length-prefix фреймы (заменил построчный протокол v0):
    заголовок 12 байт = три u32 little-endian: magic, type, length
    дальше ровно length байт payload.

type: 1=CMD  (оператор->агент, payload = UTF-8 команда БЕЗ \\n)
      2=OUT  (агент->оператор, куски вывода, бинарные как есть)
      3=END  (агент->оператор, payload = ASCII exitcode либо b"exit")
      4=PING (heartbeat: агент шлёт каждые 5с, мы отвечаем эхом)

Агент переподключается сам, поэтому оператор в цикле accept'ит новые
соединения и продолжает работу с новым сокетом.
Выход из оператора: Ctrl+C. Выход агента: команда exit.
"""
import socket
import struct
import sys
import time

HOST = "127.0.0.1"
PORT = 4444

MAGIC = 0x31414142  # "BAA1" в little-endian ('BA01' байтами)
T_CMD, T_OUT, T_END, T_PING = 1, 2, 3, 4
HDR = struct.Struct("<III")  # три u32 little-endian = 12 байт
MAX_FRAME = 64 * 1024 * 1024  # защита от битого/гигантского заголовка


def dec(b: bytes) -> str:
    """cmd на винде пишет в CP866; пробуем utf-8, потом cp866."""
    for enc in ("utf-8", "cp866"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("latin-1")


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Читает ровно n байт: recv может вернуть кусок, крутим цикл."""
    buf = b""
    while len(buf) < n:
        d = sock.recv(n - len(buf))
        if not d:
            raise ConnectionError("агент закрыл соединение")
        buf += d
    return buf


def recv_frame(sock: socket.socket):
    """Читает один кадр -> (type, payload). Обрыв/magic -> исключение."""
    magic, ftype, length = HDR.unpack(recv_exact(sock, HDR.size))
    if magic != MAGIC:
        raise ConnectionError(f"битый magic=0x{magic:08x} (ждали 0x{MAGIC:08x})")
    if length > MAX_FRAME:
        raise ConnectionError(f"подозрительная длина кадра: {length}")
    payload = recv_exact(sock, length) if length else b""
    return ftype, payload


def send_frame(sock: socket.socket, ftype: int, payload: bytes = b""):
    """Шлёт кадр: заголовок + payload одним куском."""
    sock.sendall(HDR.pack(MAGIC, ftype, len(payload)) + payload)


def send_cmd(sock: socket.socket, cmd: str):
    """CMD-кадр: UTF-8 без завершающего \\n."""
    send_frame(sock, T_CMD, cmd.encode("utf-8"))


def run_command(sock: socket.socket, cmd: str) -> bool:
    """Шлёт команду и читает кадры до END.

    OUT печатаем по мере прихода, на PING отвечаем эхом и печатаем
    однострочное уведомление. Возвращает True, если это был exit.
    """
    send_cmd(sock, cmd)
    tail = ""  # хвост неполной строки (вывод рвётся между кадрами)
    while True:
        ftype, payload = recv_frame(sock)
        if ftype == T_OUT:
            out = tail + dec(payload)
            tail = ""
            if not out.endswith(("\n", "\r")):
                # строка может продолжиться в следующем кадре — придержим хвост
                cut = out.rstrip("\r\n")
                keep = max(cut.rfind("\n"), cut.rfind("\r"))
                if keep < 0:
                    tail = out
                    continue
                tail = out[keep + 1:]
                out = out[:keep + 1]
            sys.stdout.write(out)
            sys.stdout.flush()
        elif ftype == T_PING:
            # Эхо только на "ping" (heartbeat-запрос агента). "pong" —
            # терминальный ответ агента на наше эхо: эхо-ить его нельзя,
            # иначе бесконечный ping-pong (обе стороны эхо-ят вечно).
            if payload == b"ping":
                t0 = time.time()
                send_frame(sock, T_PING, payload)
                rtt = (time.time() - t0) * 1000
                print(f"[ping {rtt:.1f}ms]")
            # else: b"pong" — просто подтверждение линка, молча
        elif ftype == T_END:
            if tail:  # печатаем незакрытую строку перед итогом
                sys.stdout.write(tail)
                sys.stdout.flush()
            code = payload.decode("ascii", "replace")
            print(f"[exit:{code}]")
            return code == "exit"
        else:
            print(f"[operator] неожиданный тип кадра {ftype} — рвём линк")
            raise ConnectionError(f"неизвестный тип фрейма {ftype}")


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[operator] жду агента на {HOST}:{PORT} ...")

    while True:
        # ── ждём подключения (переподключения агента приходят сюда же) ──
        try:
            conn, addr = srv.accept()
        except KeyboardInterrupt:
            print("\n[operator] выходим")
            break
        conn.settimeout(None)
        print(f"[operator] агент подключился: {addr}")

        # ── сессия с текущим сокетом ──
        while True:
            try:
                cmd = input("lab> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[operator] выходим")
                conn.close()
                srv.close()
                return
            if not cmd:
                continue
            try:
                is_exit = run_command(conn, cmd)
            except (ConnectionError, OSError) as e:
                print(f"[operator] {e}")
                print("[operator] агент отключился, жду переподключения...")
                try:
                    conn.close()
                except OSError:
                    pass
                break
            if is_exit:
                print("[operator] агент остановлен по команде exit")
                conn.close()
                srv.close()
                return

        # сюда попадаем после обрыва — accept'им следующее подключение


if __name__ == "__main__":
    main()
