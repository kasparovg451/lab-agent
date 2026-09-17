# Lab-Agent — учебная лаборатория (этап v2)

Минимальный удалённый shell для понимания того, КАК устроены такие системы.
Философия лабы: прозрачность. Процесс называется lab-agent.exe, виден в диспетчере,
логирует всё в свою консоль, глушится командой `exit`. Ничего не прячем.

## Правила лабы
1. Запуск только на СВОИХ машинах/ВМ.
2. Никакой маскировки: имя честное, персистентность только штатным видимым schtasks.
3. Цель — понять слой ОС: сокеты, процессы, хэндлы, пайпы, протокол.

## Сборка агента (C, чистый WinAPI+Schannel, ноль внешних зависимостей)
    python build.py    # gcc -O2 -Wall ... -lws2_32 -lsecur32 -ladvapi32 -lcrypt32

## Запуск
Терминал 1 (оператор):
    python listener.py                              # plaintext, порт 4444
    python listener.py --tls lab-cert.pem lab-key.pem [PORT]   # TLS v2
Терминал 2 (хост-машина):
    ./lab-agent.exe 127.0.0.1 4444                  # plaintext
    ./lab-agent.exe 127.0.0.1 4443 <sha256hex>      # TLS + пин серта (v2)
Команды набираешь в терминале 1. Выход: набери `exit`. Операторская
`!drop` рвёт линк (для проверки reconnect'а агента).

## Автотест (канонический: build + e2e + py_compile)
    python verify.py               # полный прогон
    python verify.py --quick       # без e2e
ЭТО официальная тест-команда; CI гоняет её же на windows-latest при каждом
пуше (.github/workflows/verify.yml). e2e — оркестратор реального пути:
поднимает настоящий listener.py (управляет stdin, проверяет stdout) и
настоящего lab-agent.exe — они общаются между собой, тест смотрит сквозной
путь; крипто не мокается. wrongpin — негативный: неверный пин => агент
умирает rc=2, не ретраится. Финал [RESULT] 19/19 (9 plain + 9 tls + 1 wrongpin).

## Оператор v2.1 (два потока)
    lab> команда        — шлёт CMD, вывод печатает поток-читатель
    !stat               — статистика RTT heartbeat'а (n / median / max)
    !drop               — сбросить линк (проверка reconnect'а агента)
    !exit / Ctrl+C      — выход оператора
select() на винде для этой задачи не работает (консольные пайпы) — поэтому
честные потоки: reader всегда читает сокет, даже когда оператор думает.

## Архитектура v2
    [listener.py]  <--TLS(Schannel/ssl) или plain, length-prefix кадры-->  [lab-agent.exe]
      кадр: magic "BAA1" | type (1=CMD 2=OUT 3=END 4=PING) | len | payload
                                                    └─ CreateProcessW("cmd.exe /c ...")
                                                        └─ Job Object (KILL_ON_JOB_CLOSE)
                                                        stdout/stderr -> пайп (Peek+Wait)
                                                        + heartbeat-поток (PING 5с)
    TLS: сервер — python ssl (самоподписанный lab-cert.pem);
         клиент — Schannel, SCH_CRED_MANUAL_CRED_VALIDATION, пин = sha256
         DER-сертификата сервера (печатает при коннекте, сверяет с argv[3]).

## Что нового в v2 (уроки слоя ОС/крипто)
- Пин = sha256 DER-сертификата (того, что едет в TLS-рукопожатии), НЕ PEM-файла:
  у PEM другой хэш из-за base64-обёртки. Главный баг, пойманный e2e.
- SCH_CRED_MANUAL_CRED_VALIDATION отключает trust-store; проверка своя:
  SECPKG_ATTR_REMOTE_CERT_CONTEXT + CryptHashCertificate(CALG_SHA_256).
- Неверный пин — ФАТАЛЬНО (rc=2): реконнект-цикл против чужого сервера недопустим.
- Schannel шифрует кусками cbMaximumMessage (~16КБ) — encrypt-цикл в xsend;
  DecryptMessage требует INCOMPLETE_MESSAGE/EXTRA-обработку в xrecv.
- plaintext и TLS за одним слоем xsend/xrecv — протокол v1 не изменился ни на бит.
- MinGW-нюанс: InitializeSecurityContextW требует 12-й аргумент (ptsExpiry),
  SECURITY_STATUS печатается как %08lx.
- e2e-уроки: (1) не мокать крипто — тест-оркестратор реального пути listener+агент;
  (2) счётчик событий в точке приёма (pump), а не дельта по потребляемому буферу;
  (3) в простое listener блокирован на input() — пинги ловим ВО ВРЕМЯ команды.

## v1 (в силе)
- length-prefix фрейминг (md5-проверка бит-в-бит на 3.4 МБ)
- heartbeat + reconnect (backoff+jitter), SO_RCVTIMEO детект мёртвого линка
- Job Object против внуков, Peek+Wait перекачка, CRITICAL_SECTION на сокет
- эхо только на b"ping", payload кадра вычитывается целиком

## Roadmap (каждый этап = один урок слоя ОС)
- v3: запуск от SYSTEM штатной механикой: `schtasks /ru SYSTEM` на своей машине
- v4: стрим экрана GDI BitBlt своими руками (те же вызовы, что в любом VNC)
- Уроки обороны: Procmon/Sysmon смотрят НАШего агента в реальном времени —
  видно каждый CreateProcess/handle/сокет/рукопожатие TLS.

## Известные ограничения v2 (осознанно, предметы уроков v3+)
- В простое listener не читает пинги (блокирован на input()) — канал считается
  живым по трафику команд; решение (select/поток чтения) — тема v3.
- Пин передаётся argv — в реальных системах его кладут в конфиг/реестр.
- Вывод cmd в CP866, listener декодирует с fallback.
