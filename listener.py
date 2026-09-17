#!/usr/bin/env python3
"""listener.py — консоль оператора для lab-agent v2 (терминал 1).

Архитектура v2.1 — ДВА ПОТОКА (урок: select() не работает на виндовых
консольных сокетах/пайпах, честное решение — конкурентные потоки):
  поток-читатель: accept() в цикле, TLS-wrap, чтение кадров, печать OUT,
                  эхо только на b"ping" (b"pong" терминален — урок v1),
                  живой счёт RTT (разница между отправкой агентом и приёмом);
  главный поток:  input("lab> ") -> шлёт CMD; END ждёт через Event.

Конкурентность: очередь OUT-фрагментов + threading.Lock; reader выдаёт
«команда завершена» через Event, главный поток её ждёт вместо poll-сна.

Транспорт: v1 length-prefix кадры; TLS — --tls CERT KEY (python ssl).
Кадр: 12 байт (3 x u32 LE: magic, type, length) + payload:
  1=CMD (оператор->агент) 2=OUT 3=END 4=PING (эхо на 'ping', 'pong' молча)
Агент переподключается сам; reader просто принимает новых клиентов.
Выход оператора: Ctrl+C или !exit. Выход агента: команда exit.
"""
import queue
import socket
import ssl
import struct
import sys
import threading
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


class Operator:
    """Общее состояние оператора; конкурентный доступ из двух потоков."""

    def __init__(self):
        self.lock = threading.Lock()          # защищает out, tail, rtt
        self.out = []                          # готовые строки вывода
        self.tail = ""                         # незакрытая строка между кадрами
        self.rtt = []                          # живой RTT пингов, мс
        self.done = threading.Event()          # END текущей команды получен
        self.exit_flag = threading.Event()     # агент/оператор завершаются
        self.current_sock = None               # куда шлёт главный поток
        self.cur_tag = ""                      # id соединения для логов

    def feed(self, payload: bytes):
        """OUT-кадр: строка может прийти куском по нескольким кадрам."""
        with self.lock:
            text = self.tail + dec(payload)
            if not text.endswith(("\n", "\r")):
                cut = text.rstrip("\r\n")
                keep = max(cut.rfind("\n"), cut.rfind("\r"))
                if keep < 0:
                    self.tail = text
                    return
                self.tail = text[keep + 1:]
                text = text[:keep + 1]
            self.out.append(text)

    def finish(self, code: str, sock):
        """END-кадр: печать хвоста, разблокировка главного потока."""
        with self.lock:
            if self.tail:
                self.out.append(self.tail)
                self.tail = ""
        if code == "exit":
            self.exit_flag.set()
        if sock is self.current_sock:
            self.done.set()

    def drain(self) -> str:
        with self.lock:
            text = "".join(self.out)
            self.out.clear()
            return text

    def rtt_note(self, ms: float):
        with self.lock:
            self.rtt.append(ms)

    def rtt_stats(self):
        with self.lock:
            if not self.rtt:
                return None
            vals = sorted(self.rtt)
            n = len(vals)
            return n, vals[n // 2], vals[-1]  # count, median, max


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        d = sock.recv(n - len(buf))
        if not d:
            raise ConnectionError("агент закрыл соединение")
        buf += d
    return buf


def recv_frame(sock):
    magic, ftype, length = HDR.unpack(recv_exact(sock, HDR.size))
    if magic != MAGIC:
        raise ConnectionError(f"битый magic=0x{magic:08x} (ждали 0x{MAGIC:08x})")
    if length > MAX_FRAME:
        raise ConnectionError(f"подозрительная длина кадра: {length}")
    payload = recv_exact(sock, length) if length else b""
    return ftype, payload


def send_frame(sock, ftype: int, payload: bytes = b""):
    sock.sendall(HDR.pack(MAGIC, ftype, len(payload)) + payload)


def reader_loop(op: Operator, srv: socket.socket, tls_ctx, seq, shutdown: threading.Event):
    """Поток-читатель: accept + чтение кадров всех подключений подряд.

    Активное соединение ОДНО (агент переподключается к тому же слушателю),
    поэтому читаем последовательно; конкурентность тут в том, что чтение
    идёт ВСЕГДА, даже когда главный поток сидит в input().
    """
    conn = None
    while not shutdown.is_set() and not op.exit_flag.is_set():
        # ── ждём клиента, если соединения нет ──
        if conn is None:
            srv.settimeout(0.5)
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # слушающий сокет закрыт — выходим
            try:
                if tls_ctx:
                    conn = tls_ctx.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError) as e:
                print(f"\n[operator] TLS-рукопожатие с {addr} не удалось: {e}")
                try:
                    conn.close()
                except OSError:
                    pass
                conn = None
                continue
            conn.settimeout(1.0)  # чтобы реагировать на shutdown/exit_flag
            with op.lock:
                op.current_sock = conn
                op.cur_tag = f"#{next(seq)}"
            op.done.set()  # новая сессия: главному потоку можно слать
            print(f"\n[operator] агент подключился: {addr}"
                  + (f" (TLS {conn.version()})" if tls_ctx else ""))
            continue

        # ── читаем кадры активного соединения ──
        try:
            ftype, payload = recv_frame(conn)
        except socket.timeout:
            continue  # таймаут recv — проверяем флаги, читаем дальше
        except (ConnectionError, OSError):
            print("\n[operator] агент отключился, жду переподключения...")
            try:
                conn.close()
            except OSError:
                pass
            conn = None
            continue

        if ftype == T_OUT:
            op.feed(payload)
        elif ftype == T_PING:
            # RTT честный: агент шлёт ping раз в 5с и получает его сразу,
            # наш эхо-ответ возвращается мгновенно; меряем полный круг эха.
            if payload == b"ping":
                t0 = time.perf_counter()
                try:
                    send_frame(conn, T_PING, payload)
                except OSError:
                    pass
                op.rtt_note((time.perf_counter() - t0) * 1000)
        elif ftype == T_END:
            code = payload.decode("ascii", "replace")
            op.finish(code, conn)
            print(f"\n[exit:{code}]")
            # сессия продолжается; reader читает дальше


def main():
    tls_cert = tls_key = None
    port = PORT
    args = list(sys.argv[1:])
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

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(1)

    tls_ctx = None
    if tls_cert:
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_ctx.load_cert_chain(tls_cert, tls_key)
        print(f"[operator] TLS-режим: cert={tls_cert}")
    print(f"[operator] жду агента на {HOST}:{port} ... (выход: !exit или Ctrl+C)")

    op = Operator()
    seq = __import__("itertools").count(1)
    shutdown = threading.Event()
    reader = threading.Thread(
        target=reader_loop, args=(op, srv, tls_ctx, seq, shutdown), daemon=True
    )
    reader.start()

    try:
        while not op.exit_flag.is_set():
            try:
                cmd = input("lab> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[operator] выходим")
                break
            if not cmd:
                continue
            if cmd == "!exit":
                print("[operator] выходим")
                break
            if cmd == "!stat":
                st = op.rtt_stats()
                print(f"[rtt] {'нет пингов' if not st else f'n={st[0]} median={st[1]:.1f}ms max={st[2]:.1f}ms'}")
                continue
            if cmd == "!drop":
                print("[operator] линк сброшен — жду переподключения агента")
                with op.lock:
                    s = op.current_sock
                if s:
                    try:
                        s.close()
                    except OSError:
                        pass
                continue

            with op.lock:
                sock = op.current_sock
            if sock is None:
                print("[operator] агента нет — жду подключения")
                continue
            op.done.clear()
            try:
                send_frame(sock, T_CMD, cmd.encode("utf-8"))
            except OSError as e:
                print(f"[operator] отправка не прошла: {e} — жду переподключения")
                continue
            # ждём END: reader выставит done; периодически печатаем вывод
            while not op.done.wait(0.3):
                text = op.drain()
                if text:
                    sys.stdout.write(text)
                    sys.stdout.flush()
                if op.exit_flag.is_set():
                    break
            text = op.drain()
            if text:
                sys.stdout.write(text)
                sys.stdout.flush()
            # [exit:code] печатает reader при получении END-кадра
    finally:
        shutdown.set()
        try:
            srv.close()
        except OSError:
            pass
        reader.join(timeout=2)
        print("[operator] остановлен")


if __name__ == "__main__":
    main()
