#!/usr/bin/env python3
"""Автотест lab-agent v1: фреймовый протокол length-prefix.

Кадр = заголовок 12 байт (3 x u32 little-endian: magic, type, length)
       + payload length байт.
type: 1=CMD (тест->агент, UTF-8 без \n)
      2=OUT (бинарные куски вывода команды)
      3=END (payload = ASCII exitcode либо b"exit")
      4=PING (агент шлёт каждые 5с, мы отвечаем эхом на его PING)

Поднимает сервер, запускает агента, гоняет 9 сценариев, печатает реальный
транскрипт. Главная проверка — бинарная целостность (md5) большого файла.
"""
import hashlib
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "lab-agent.exe")
HOST, PORT = "127.0.0.1", 44441

MAGIC = 0x31414142  # "BAA1" в little-endian
HDR = struct.Struct("<III")
T_CMD, T_OUT, T_END, T_PING = 1, 2, 3, 4

BIG_FILE = r"C:\Windows\explorer.exe"


def dec(b):
    """Мягкое декодирование вывода cmd.exe (консоль часто в cp866)."""
    for enc in ("utf-8", "cp866"):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode("latin-1")


def recv_exact(conn, n):
    """Читает ровно n байт или бросает (сокет закрылся/таймаут)."""
    buf = b""
    while len(buf) < n:
        d = conn.recv(n - len(buf))
        if not d:
            raise RuntimeError(f"соединение закрыто, недобрано {n - len(buf)} байт")
        buf += d
    return buf


def recv_frame(conn):
    """Читает один кадр -> (type, payload)."""
    magic, ftype, length = HDR.unpack(recv_exact(conn, HDR.size))
    if magic != MAGIC:
        raise RuntimeError(f"битый magic=0x{magic:08x} (ожидали 0x{MAGIC:08x})")
    if length > 64 * 1024 * 1024:
        raise RuntimeError(f"подозрительная длина кадра: {length}")
    payload = recv_exact(conn, length) if length else b""
    return ftype, payload


def send_cmd(conn, cmd):
    """CMD-кадр: UTF-8 без завершающего \\n."""
    body = cmd.encode("utf-8")
    conn.sendall(HDR.pack(MAGIC, T_CMD, len(body)) + body)


def roundtrip(conn, cmd):
    """Шлёт CMD и читает до END.

    Возвращает (code_str, bytes_body). OUT копим, PING игнорируем
    (на PING отвечаем эхом, чтобы агент не считал канал мёртвым).
    """
    send_cmd(conn, cmd)
    body = b""
    while True:
        ftype, payload = recv_frame(conn)
        if ftype == T_OUT:
            body += payload
        elif ftype == T_END:
            return payload.decode("ascii", "replace"), body
        elif ftype == T_PING:
            # Эхо только на "ping"; "pong" (ответ агента) не эхо-им — иначе
            # бесконечный ping-pong: обе стороны эхо-ят вечно.
            if payload == b"ping":
                print(f"    (во время команды прилетел PING {payload!r} — отвечаю эхом)")
                conn.sendall(HDR.pack(MAGIC, T_PING, len(payload)) + payload)
        else:
            raise RuntimeError(f"неожиданный тип кадра {ftype}")


def md5_file(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    srv.settimeout(40)

    agent = subprocess.Popen(
        [EXE, HOST, str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    results = []
    big_md5_live = [None]  # тело теста 4 -> для byte-exact в тесте 5
    active_conn = [None]   # текущее соединение (тест 8 заменяет его)

    def check(name, ok):
        results.append((name, bool(ok)))

    def scenario(num, label, fn):
        """Оборачиваем каждый сценарий: FAIL фиксируется, прогон продолжается."""
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — тест должен дойти до финала
            print(f"[TEST {num}] {label} -> ИСКЛЮЧЕНИЕ: {type(e).__name__}: {e}")
            check(f"{label} (без исключения)", False)

    try:
        conn, addr = srv.accept()
        conn.settimeout(15)
        active_conn[0] = conn
        print(f"[TEST] агент подключился с {addr}")

        # 1. echo: базовый round-trip CMD -> OUT -> END
        def t1():
            code, body = roundtrip(conn, "echo hello-lab-test")
            text = dec(body).strip()
            print(f"[TEST 1] echo forward -> exit={code}, body={text!r}")
            check("echo forward", "hello-lab-test" in text)
        scenario(1, "echo forward", t1)

        # 2. whoami: команда вообще что-то возвращает
        def t2():
            code, body = roundtrip(conn, "whoami")
            text = dec(body).strip()
            print(f"[TEST 2] whoami       -> exit={code}, ctx={text!r}")
            check("whoami not empty", bool(text))
        scenario(2, "whoami not empty", t2)

        # 3. stderr слит в тот же OUT-канал и виден в тексте
        def t3():
            code, body = roundtrip(conn, "cmd /c dir C:\\ definitely_missing_dir_xyz")
            text = dec(body)
            low = text.lower()
            visible = ("file not found" in low or "cannot find" in low
                       or "не удается найти" in low or "не найд" in low)
            print(f"[TEST 3] stderr merged -> exit={code}, err-visible={visible}")
            check("stderr merged", code != "pipe_err" and visible)
        scenario(3, "stderr merged", t3)

        # 4. большой вывод: перекачка десятками OUT-кадров, бинарник как есть
        def t4():
            code, body = roundtrip(conn, f"type {BIG_FILE}")
            big_md5_live[0] = hashlib.md5(body).hexdigest()
            print(f"[TEST 4] big output   -> exit={code}, bytes={len(body)}, "
                  f"md5={big_md5_live[0]}")
            check("big output streamed", len(body) > 200000)
        scenario(4, "big output streamed", t4)

        # 5. BYTE-EXACT: байты из кадров побитово равны файлу на диске
        def t5():
            disk_md5 = md5_file(BIG_FILE)
            live_md5 = big_md5_live[0]
            print(f"[TEST 5] byte-exact   -> disk_md5={disk_md5}")
            print(f"                        live_md5={live_md5}")
            check("byte-exact md5 matches file", live_md5 is not None and live_md5 == disk_md5)
        scenario(5, "byte-exact md5 matches file", t5)

        # 6. внук-процесс не держит канал: Job Object KILL_ON_JOB_CLOSE
        def t6():
            t0 = time.time()
            code, body = roundtrip(conn, 'start "" /b cmd /c "ping -n 15 127.0.0.1 > nul"')
            dt = time.time() - t0
            print(f"[TEST 6] внук не держит канал -> exit={code}, "
                  f"END через {dt:.2f}с (порог 10с)")
            check("no grandchild hold (<10s)", dt < 10.0)
        scenario(6, "no grandchild hold (<10s)", t6)

        # 7. HEARTBEAT: агент сам шлёт PING каждые ~5с
        def t7():
            print("[TEST 7] heartbeat    -> молчим ~12с, ловим PING...")
            conn.settimeout(13)
            pings, t0 = 0, time.time()
            try:
                while time.time() - t0 < 12:
                    ftype, payload = recv_frame(conn)
                    if ftype == T_PING:
                        pings += 1
                        print(f"    PING #{pings} в t={time.time() - t0:.2f}с "
                              f"payload={payload!r}")
                        # эхо только на "ping"; "pong" агента не эхо-им
                        if payload == b"ping":
                            conn.sendall(HDR.pack(MAGIC, T_PING, len(payload)) + payload)
                    else:
                        print(f"    (в простое неожиданный кадр type={ftype})")
            except socket.timeout:
                print(f"    таймаут окна ожидания (это нормально), получено PING={pings}")
            print(f"[TEST 7] heartbeat    -> PING за 12с = {pings}")
            check("heartbeat pings received", pings >= 1)
            # сбрасываем возможный хвост, чтобы не сбить тест 8/9
            conn.settimeout(0.5)
            try:
                while True:
                    ftype, payload = recv_frame(conn)
                    if ftype == T_PING and payload == b"ping":
                        conn.sendall(HDR.pack(MAGIC, T_PING, len(payload)) + payload)
            except Exception:  # noqa: BLE001 — таймаут == хвост пуст
                pass
        scenario(7, "heartbeat pings received", t7)

        # 8. RECONNECT: агент сам переподключается после жёсткого close()
        def t8():
            print("[TEST 8] reconnect    -> жёстко закрываю сокет, жду новый accept")
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            t0 = time.time()
            new_conn, new_addr = srv.accept()
            new_conn.settimeout(15)
            dt = time.time() - t0
            active_conn[0] = new_conn
            print(f"[TEST 8] reconnect    -> агент вернулся с {new_addr} за {dt:.2f}с")
            code, body = roundtrip(new_conn, "echo after-reconnect")
            text = dec(body).strip()
            print(f"[TEST 8]             -> exit={code}, body={text!r}")
            check("reconnect + echo", "after-reconnect" in text)
        scenario(8, "reconnect + echo", t8)

        # 9. CLEAN EXIT: END с payload "exit", процесс завершается с кодом 0
        def t9():
            # соединение могло быть заменено в тесте 8 — берём актуальное
            code, body = roundtrip(active_conn[0], "exit")
            print(f"[TEST 9] clean exit   -> END payload={code!r}")
            try:
                rc = agent.wait(timeout=10)
            except subprocess.TimeoutExpired:
                agent.kill()
                rc = agent.returncode
            print(f"[TEST 9]             -> код процесса агента = {rc}")
            check("clean exit", code == "exit" and rc == 0)
        scenario(9, "clean exit", t9)
    except Exception as e:  # noqa: BLE001 — сбой соединения не должен терять итог
        print(f"[TEST] КРИТИЧЕСКАЯ ОШИБКА СЕССИИ: {type(e).__name__}: {e}")
        check("сессия целиком", False)
    finally:
        try:
            agent.wait(timeout=10)
        except subprocess.TimeoutExpired:
            agent.kill()
        print(f"[TEST] процесс агента завершился, код={agent.returncode}")
        try:
            srv.close()
        except Exception:  # noqa: BLE001
            pass

    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"[RESULT] {passed}/{len(results)}")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
