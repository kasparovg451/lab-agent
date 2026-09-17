#!/usr/bin/env python3
"""listener.py — консоль оператора для lab-agent v2 (терминал 1).

Транспорт: v1 length-prefix кадры; v2 добавляет TLS (--tls CERT KEY).
    python listener.py                      — plaintext (порт 4444)
    python listener.py --tls lab-cert.pem lab-key.pem [PORT]
TLS самоподписанный: системную валидацию отключаем, вместо trust-store
пиним sha256 серверного сертификата (его печатает агент при подключении).

Кадр: заголовок 12 байт = три u32 little-endian: magic, type, length,
дальше ровно length байт payload.
type: 1=CMD  (оператор->агент, payload = UTF-8 команда без \\n)
      2=OUT  (агент->оператор, куски вывода, бинарные как есть)
      3=END  (агент->оператор, payload = ASCII exitcode либо b"exit")
      4=PING (heartbeat: агент шлёт 'ping' каждые 5с, мы эхо-им;
              'pong' — терминальный ответ агента, его НЕ эхо-им — урок v1)

Агент переподключается сам (backoff), оператор в цикле accept'ит заново.
Выход из оператора: Ctrl+C. Выход агента: команда exit.
"""
import socket
import ssl
import struct
import sys
import time

HOST = "127.0.0.1"
PORT = 4444

MAGIC = 0x31414142  # на проводе байты 'BAA1'
T_CMD, T_OUT, T_END, T_PING = 1, 2, 3, 4
HDR = struct.Struct("<III")  # три u32 little-endian = 12 байт
MAX_FRAME = 64 * 1024 * 1024


def dec(b: bytes) -> str:
    """cmd на винде пишет в CP866; пробуем utf-8, потом cp866."""
    for enc in ("utf-8", "cp866"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("latin-1")


def recv_exact(sock, n: int) -> bytes:
    """Читает ровно n байт: recv может вернуть кусок, крутим цикл."""
    buf = b""
    while len(buf) < n:
        d = sock.recv(n - len(buf))
        if not d:
            raise ConnectionError("агент закрыл соединение")
        buf += d
    return buf


def recv_frame(sock):
    """Читает один кадр -> (type, payload). Обрыв/magic -> исключение."""
    magic, ftype, length = HDR.unpack(recv_exact(sock, HDR.size))
    if magic != MAGIC:
        raise ConnectionError(f"битый magic=0x{magic:08x} (ждали 0x{MAGIC:08x})")
    if length > MAX_FRAME:
        raise ConnectionError(f"подозрительная длина кадра: {length}")
    payload = recv_exact(sock, length) if length else b""
    return ftype, payload


def send_frame(sock, ftype: int, payload: bytes = b""):
    sock.sendall(HDR.pack(MAGIC, ftype, len(payload)) + payload)


def send_cmd(sock, cmd: str):
    """CMD-кадр: UTF-8 без завершающего \\n."""
    send_frame(sock, T_CMD, cmd.encode("utf-8"))


def run_command(sock, cmd: str) -> bool:
    """Шлёт команду и читает кадры до END. Возвращает True, если это exit."""
    send_cmd(sock, cmd)
    tail = ""  # хвост неполной строки (вывод рвётся между кадрами)
    while True:
        ftype, payload = recv_frame(sock)
        if ftype == T_OUT:
            out = tail + dec(payload)
            tail = ""
            if not out.endswith(("\n", "\r")):
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
            # Эхо только на "ping". "pong" — терминальный ответ агента:
            # эхо-ить его нельзя, иначе бесконечный ping-pong (урок v1).
            if payload == b"ping":
                t0 = time.time()
                send_frame(sock, T_PING, payload)
                rtt = (time.time() - t0) * 1000
                print(f"[ping {rtt:.1f}ms]")
        elif ftype == T_END:
            if tail:
                sys.stdout.write(tail)
                sys.stdout.flush()
            code = payload.decode("ascii", "replace")
            print(f"[exit:{code}]")
            return code == "exit"
        else:
            print(f"[operator] неожиданный тип кадра {ftype} — рвём линк")
            raise ConnectionError(f"неизвестный тип фрейма {ftype}")


def parse_args(argv):
    tls_cert = tls_key = None
    port = PORT
    args = list(argv)
    i = 0
    while i < len(args):
        if args[i] == "--tls":
            if i + 2 >= len(args):
                sys.exit("использование: --tls CERT KEY [PORT]")
            tls_cert, tls_key = args[i + 1], args[i + 2]
            i += 3
        elif args[i].isdigit():
            port = int(args[i])
            i += 1
        else:
            i += 1
    return tls_cert, tls_key, port


def main():
    tls_cert, tls_key, port = parse_args(sys.argv[1:])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(1)

    tls_ctx = None
    if tls_cert:
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(tls_cert, tls_key)
        # системную валидацию клиента тут и нет; агент пинит НАШ отпечаток
        print(f"[operator] TLS-режим: cert={tls_cert} key={tls_key}")
    print(f"[operator] жду агента на {HOST}:{port} ...")

    while True:
        try:
            conn, addr = srv.accept()
        except KeyboardInterrupt:
            print("\n[operator] выходим")
            break
        try:
            if tls_ctx:
                conn = tls_ctx.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError) as e:
            # в TLS-режиме сюда попадают чужие/битые клиенты — это норма
            print(f"[operator] TLS-рукопожатие с {addr} не удалось: {e}")
            try:
                conn.close()
            except OSError:
                pass
            continue
        print(f"[operator] агент подключился: {addr}"
              + (f" (TLS {conn.version()})" if tls_ctx else ""))

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
            if cmd == "!drop":
                # операторская команда: сбросить линк (агент должен переподключиться)
                print("[operator] линк сброшен — жду переподключения агента")
                try:
                    conn.close()
                except OSError:
                    pass
                break
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
