#!/usr/bin/env python3
"""Автотест lab-agent v2: оркестратор реального пути.

Архитектура честная: поднимаем НАСТОЯЩИЙ listener.py (subprocess, его
stdin/stdout управляется тестом) и НАСТОЯЩИЙ lab-agent.exe — они общаются
между собой (plain или TLS), тест проверяет сквозной путь через STDOUT
listener'а. Крипто не мокается.

Сюиты:
  plain     — транспорт без шифрования (регрессия v1)
  tls       — то же поверх TLS (агент пинит sha256 самоподписанного серта)
  wrongpin  — негативный: агент с неверным pin обязан умереть rc=2

Кадр: 12 байт (3 x u32 LE: magic, type, length) + payload; 1=CMD 2=OUT
3=END 4=PING. В тесте кадры используются только для wrongpin-зонда.

Запуск: python test_e2e.py            (все сюиты)
        python test_e2e.py plain      (быстрая регрессия)
Финал: [RESULT] n/m; exit 0/1.
"""
import hashlib
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "lab-agent.exe")
CERT = os.path.join(HERE, "lab-cert.pem")
KEY = os.path.join(HERE, "lab-key.pem")

MAGIC = 0x31414142
HDR = struct.Struct("<III")
T_CMD, T_OUT, T_END, T_PING = 1, 2, 3, 4
BIG_FILE = r"C:\Windows\explorer.exe"
CERT_SHA256 = hashlib.sha256(
    ssl.PEM_cert_to_DER_cert(open(CERT).read())
).hexdigest()  # пин = sha256 DER-сертификата (ровно его шлёт сервер в TLS),
              # НЕ PEM-файла: у PEM другой хэш из-за base64-обёртки (ловили e2e)
WRONG_SHA256 = "00" * 32

# сообщения STDOUT listener'а, по которым тест ориентируется
RE_CONNECTED = re.compile(r"агент подключился")
RE_EXIT = re.compile(r"\[exit:([^\r\n\]]+)\]")
RE_PING = re.compile(r"\[ping ([0-9.]+)ms\]")
RE_DROP = re.compile(r"линк сброшен")
RE_TLS_FAIL = re.compile(r"TLS-рукопожатие с .* не удалось")


def wait_stdout(buf, pattern, timeout, consume=True):
    """Ждёт regex в накопленном stdout listener'а. Возвращает match или None."""
    rx = re.compile(pattern)
    t0 = time.time()
    while time.time() - t0 < timeout:
        m = rx.search(buf[0])
        if m:
            if consume:
                buf[0] = buf[0][m.end():]
            return m
        time.sleep(0.1)
    return None


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def recv_frame(conn, timeout=5):
    """Кадровый ридер для зонда wrongpin."""
    conn.settimeout(timeout)
    h = b""
    while len(h) < 12:
        d = conn.recv(12 - len(h))
        if not d:
            raise ConnectionError("EOF hdr")
        h += d
    m, t, ln = struct.unpack("<III", h)
    assert m == MAGIC, f"bad magic {m:#x}"
    p = b""
    while len(p) < ln:
        d = conn.recv(ln - len(p))
        if not d:
            raise ConnectionError("EOF payload")
        p += d
    return t, p


def start_listener(port, tls):
    """Настоящий listener.py: stdin=PIPE (управляем), stdout=PIPE (проверяем)."""
    lis = subprocess.Popen(
        [sys.executable, "-u", os.path.join(HERE, "listener.py"), str(port)]
        + (["--tls", CERT, KEY] if tls else []),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    buf = [""]
    ping_count = [0]
    def pump():
        try:
            while True:
                b_ = lis.stdout.read1(65536)
                if not b_:
                    break
                s = b_.decode("utf-8", "replace")
                ping_count[0] += len(RE_PING.findall(s))
                buf[0] += s
        except Exception:
            pass
    import threading
    threading.Thread(target=pump, daemon=True).start()
    return lis, buf, ping_count


def op(lis, cmd):
    lis.stdin.write(cmd.encode() + b"\n")
    lis.stdin.flush()


def start_agent(port, pin=None):
    args = [EXE, "127.0.0.1", str(port)]
    if pin is not None:
        args.append(pin)
    return subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )


def probe_cmd(lis, buf, cmd, expect, timeout=30):
    """Сквозной прогон: шлём команду оператором, ждём вывод+exit в STDOUT."""
    op(lis, cmd)
    tail = wait_stdout(buf, r"\[exit:([^\]\r\n]+)\]", timeout)
    assert tail, f"не дождались [exit:...] за {timeout}с после {cmd!r}"
    code = tail.group(1)
    return code


def dump_diag(name, buf, agent):
    """При провале сценария: хвост STDOUT listener'а + STDOUT агента."""
    tail = buf[0][-400:]
    print(f"[{name}] [diag] stdout listener (хвост): {tail!r}")
    if agent and agent.stdout:
        try:
            chunk = agent.stdout.read1(65536)
            if chunk:
                print(f"[{name}] [diag] stdout агента: {chunk.decode('utf-8', 'replace')!r}")
        except Exception:
            pass


def run_suite(name, port, tls, pin):
    results = []

    def check(label, ok):
        results.append((label, bool(ok)))

    def scenario(num, label, fn):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — прогон дожимаем до финала
            print(f"[{name}] T{num} {label} -> ИСКЛЮЧЕНИЕ: {type(e).__name__}: {e}")
            dump_diag(name, buf, agent)
            check(f"T{num} {label}", False)

    print(f"=== сюита {name} (порт {port}, {'TLS' if tls else 'plain'}) ===")
    lis, buf, ping_count = start_listener(port, tls)
    agent = None
    try:
        # агент стартует и подключается к listener'у (реальный путь)
        agent = start_agent(port, pin=pin)
        m = wait_stdout(buf, RE_CONNECTED, 15)
        if not m:
            raise RuntimeError("агент не подключился к listener'у за 15с")
        print(f"[{name}] коннект: агент <-> listener установлен")

        # T1: echo сквозным путём
        def t1():
            code = probe_cmd(lis, buf, "echo hello-lab-test", "hello-lab-test")
            check("T1 echo", code == "0")
            print(f"[{name}] T1 echo        -> exit={code}")
        scenario(1, "echo", t1)

        # T2: whoami
        def t2():
            code = probe_cmd(lis, buf, "whoami", "")
            check("T2 whoami", code == "0")
            print(f"[{name}] T2 whoami     -> exit={code}")
        scenario(2, "whoami", t2)

        # T3: stderr сливается в общий канал
        def t3():
            code = probe_cmd(lis, buf, "cmd /c dir C:\\ definitely_missing_dir_xyz", "")
            check("T3 stderr", code not in ("pipe_err",))
            print(f"[{name}] T3 stderr      -> exit={code}")
        scenario(3, "stderr", t3)

        # T4/T5: большой бинарный вывод + byte-exact
        def t4():
            op(lis, f"type {BIG_FILE}")
            m5 = wait_stdout(buf, r"\[exit:([^\]\r\n]+)\]", 60)
            assert m5, "не дождались END от type"
            # вывод уже в buf[0]; md5 считаем из того, что напечатал listener.
            # stdout listener декодирует cp866/utf-8 с потерями — для md5 этот
            # путь не годится, поэтому byte-exact проверяем ЗОНДОМ: подключаемся
            # к listener'у нельзя (он сервер для агента), значит проверяем длину
            # вывода и отдельным прямым прогоном agента без listener'а — ниже.
            check("T4 big-END", m5.group(1) == "0")
            print(f"[{name}] T4 big output  -> exit={m5.group(1)}")
        scenario(4, "big output", t4)

        # T5: byte-exact md5 напрямую через агента (без listener'а, те же кадры)
        def t5():
            srv = socket.socket()
            srv.bind(("127.0.0.1", 0))     # свободный порт выбирает ОС
            srv.listen(1)
            p = srv.getsockname()[1]
            ag = start_agent(p, pin=pin) if tls else start_agent(p)
            conn, _ = srv.accept()
            if tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(CERT, KEY)
                conn = ctx.wrap_socket(conn, server_side=True)
            conn.settimeout(60)
            send_cmd = HDR.pack(MAGIC, T_CMD, len(f"type {BIG_FILE}")) + f"type {BIG_FILE}".encode()
            conn.sendall(send_cmd)
            body = b""
            while True:
                t, pl = recv_frame(conn)
                if t == T_OUT:
                    body += pl
                elif t == T_END:
                    break
                elif t == T_PING and pl == b"ping":
                    conn.sendall(HDR.pack(MAGIC, T_PING, 4) + b"ping")
            conn.close()
            ag.kill()
            srv.close()
            disk = md5_file(BIG_FILE)
            live = hashlib.md5(body).hexdigest()
            check("T5 byte-exact", live == disk)
            print(f"[{name}] T5 byte-exact  -> {'совпадает' if live == disk else 'РАСХОЖДЕНИЕ: ' + live} ({len(body)} байт)")
        scenario(5, "byte-exact", t5)

        # T6: внук не держит канал
        def t6():
            t0 = time.time()
            code = probe_cmd(lis, buf, 'start "" /b cmd /c "ping -n 15 127.0.0.1 > nul"', "", timeout=20)
            dt = time.time() - t0
            check("T6 no-grandchild-hold", dt < 10.0)
            print(f"[{name}] T6 внук        -> exit={code} END за {dt:.2f}с")
        scenario(6, "no grandchild hold", t6)

        # T7: heartbeat ВО ВРЕМЯ долгой команды. v2.1: reader читает всегда,
        # RTT копится в op.rtt; печатной строки больше нет — факт heartbeat
        # проверяем операторской командой !stat (n>=1, median/max печатается).
        def t7():
            print(f"[{name}] T7 heartbeat   -> долгая команда ~8с, потом !stat")
            code = probe_cmd(lis, buf, "ping -n 8 127.0.0.1 > nul", "", timeout=30)
            assert code == "0", f"долгая команда упала: exit={code}"
            op(lis, "!stat")
            mst = wait_stdout(buf, r"\[rtt\] n=(\d+) median=([0-9.]+)ms max=([0-9.]+)ms", 10)
            assert mst, "не дождались [rtt] от !stat"
            n = int(mst.group(1))
            check("T7 heartbeat", n >= 1)
            print(f"[{name}] T7 heartbeat   -> RTT n={n} median={mst.group(2)}ms max={mst.group(3)}ms")
        scenario(7, "heartbeat", t7)

        # T8: reconnect через операторскую !drop
        def t8():
            print(f"[{name}] T8 reconnect   -> !drop, жду возврат агента")
            op(lis, "!drop")
            md = wait_stdout(buf, RE_DROP, 5)
            assert md, "listener не подтвердил !drop"
            m2 = wait_stdout(buf, RE_CONNECTED, 30)
            assert m2, "агент не вернулся после !drop за 30с"
            code = probe_cmd(lis, buf, "echo after-reconnect", "")
            check("T8 reconnect", code == "0")
            print(f"[{name}] T8 reconnect   -> агент вернулся, echo exit={code}")
        scenario(8, "reconnect", t8)

        # T9: clean exit
        def t9():
            op(lis, "exit")
            m9 = wait_stdout(buf, r"\[exit:exit\]", 15)
            assert m9, "не дождались [exit:exit]"
            try:
                rc = agent.wait(timeout=10)
            except subprocess.TimeoutExpired:
                agent.kill()
                rc = agent.returncode
            check("T9 clean exit", rc == 0)
            print(f"[{name}] T9 clean exit  -> rc агента={rc}")
        scenario(9, "clean exit", t9)

    except Exception as e:  # noqa: BLE001
        print(f"[{name}] КРИТИЧЕСКАЯ ОШИБКА СЮИТЫ: {type(e).__name__}: {e}")
        check("suite", False)
    finally:
        if agent and agent.poll() is None:
            try:
                agent.kill()
            except OSError:
                pass
        if lis.poll() is None:
            lis.kill()

    passed = sum(1 for _, ok in results if ok)
    for label, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    return passed, len(results)


def test_wrongpin(port):
    """Негативный: агент с неверным pin умирает rc=2, не реконнектится."""
    print(f"=== негативный wrongpin (порт {port}) ===")
    lis, buf, _pingc = start_listener(port, tls=True)
    time.sleep(1.0)
    agent = start_agent(port, pin=WRONG_SHA256)
    ok = False
    try:
        try:
            rc = agent.wait(timeout=15)
        except subprocess.TimeoutExpired:
            agent.kill()
            rc = None
        out = (agent.stdout.read() if agent.stdout else b"").decode("utf-8", "replace")
        ok = (rc == 2) and ("ПИН НЕ СОШЁЛСЯ" in out)
        print(f"  rc={rc}, отказ пина в логе={'ПИН НЕ СОШЁЛСЯ' in out}")
        print("  " + out.replace("\n", "\n  ")[:600])
    finally:
        if agent.poll() is None:
            agent.kill()
        if lis.poll() is None:
            lis.kill()
    return (1, 1) if ok else (0, 1)


def main():
    suites = sys.argv[1:] or ["plain", "tls", "wrongpin"]
    tp = tt = 0
    if "plain" in suites:
        p, t = run_suite("plain", 44441, tls=False, pin=None)
        tp += p; tt += t
    if "tls" in suites:
        p, t = run_suite("tls", 44443, tls=True, pin=CERT_SHA256)
        tp += p; tt += t
    if "wrongpin" in suites:
        p, t = test_wrongpin(44445)
        tp += p; tt += t
    print(f"[RESULT] {tp}/{tt}")
    sys.exit(0 if tp == tt else 1)


if __name__ == "__main__":
    main()
