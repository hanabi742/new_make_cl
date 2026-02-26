#pragma once
// ============================================================
//  MsgClientLogic.hpp
//  - 메시지 클라이언트 로직 전부 inline
//  - Windows / Linux 크로스 플랫폼
//  - make_cloud_prtocal.hpp 규격: [4byte Big-Endian 길이][JSON Body]
// ============================================================

// ── 플랫폼 분기 ──────────────────────────────────────────────
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET sock_t;
    #define SOCK_INVALID    INVALID_SOCKET
    #define sock_close(s)   closesocket(s)
    #define sleep_sec(n)    Sleep((n) * 1000)
    // Windows 콘솔 색상
    inline void color_white()  { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15); }
    inline void color_blue()   { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 11); }
    inline void color_yellow() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14); }
    inline void color_red()    { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12); }
    inline void color_reset()  { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 15); }
#else
    #include <arpa/inet.h>
    #include <sys/socket.h>
    #include <unistd.h>
    #include <pthread.h>
    #include <cstdio>
    typedef int sock_t;
    #define SOCK_INVALID  (-1)
    #define sock_close(s) close(s)
    #define sleep_sec(n)  sleep(n)
    // ANSI 색상
    inline void color_white()  { printf("\033[0m");    }
    inline void color_blue()   { printf("\033[1;34m"); }
    inline void color_yellow() { printf("\033[1;33m"); }
    inline void color_red()    { printf("\033[1;31m"); }
    inline void color_reset()  { printf("\033[0m");    }
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ── 상수 ─────────────────────────────────────────────────────
#define SERVER_IP       "127.0.0.1"
#define SERVER_PORT     9001
#define MAX_BODY        65536
#define MAX_CONTENT     1024
#define HISTORY_MAX     10
#define ALARM_INTERVAL  5
#define PAGE_SIZE       20

// ── JSON 타입 상수 ────────────────────────────────────────────
#define REQ_MSG_SEND        "REQ_MSG_SEND"
#define REQ_MSG_CHECK       "REQ_MSG_CHECK"
#define REQ_MSG_LIST        "REQ_MSG_LIST"
#define REQ_MSG_READ        "REQ_MSG_READ"
#define REQ_MSG_DELETE      "REQ_MSG_DELETE"
#define REQ_MSG_CHECK_USER  "REQ_MSG_CHECK_USER"

// ── 전역 상태 ─────────────────────────────────────────────────
static sock_t        g_sock      = SOCK_INVALID;
static int           g_user_pk   = 0;
static volatile int  g_unread    = 0;

// 이전 수신자 히스토리
static char g_history[HISTORY_MAX][256];
static int  g_history_cnt = 0;

// ── 뮤텍스 ───────────────────────────────────────────────────
#ifdef _WIN32
static CRITICAL_SECTION g_cs;
inline void lock()   { EnterCriticalSection(&g_cs); }
inline void unlock() { LeaveCriticalSection(&g_cs); }
#else
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
inline void lock()   { pthread_mutex_lock(&g_mutex);   }
inline void unlock() { pthread_mutex_unlock(&g_mutex); }
#endif

// ============================================================
//  네트워크 헬퍼
// ============================================================
inline int net_send(sock_t sock, const char* body) {
    uint32_t body_len = (uint32_t)strlen(body);
    uint32_t net_len  = htonl(body_len);
    if (send(sock, (const char*)&net_len, 4, 0) != 4) return -1;
    uint32_t sent = 0;
    while (sent < body_len) {
        int r = send(sock, body + sent, body_len - sent, 0);
        if (r <= 0) return -1;
        sent += r;
    }
    return 0;
}

inline int net_recv(sock_t sock, char* out_buf, int buf_size) {
    uint32_t net_len = 0;
    int r = recv(sock, (char*)&net_len, 4, MSG_WAITALL);
    if (r != 4) return -1;
    uint32_t body_len = ntohl(net_len);
    if (body_len == 0 || (int)body_len >= buf_size) return -1;
    uint32_t got = 0;
    while (got < body_len) {
        r = recv(sock, out_buf + got, body_len - got, 0);
        if (r <= 0) return -1;
        got += r;
    }
    out_buf[got] = '\0';
    return (int)got;
}

// ============================================================
//  간이 JSON 빌더 / 파서
// ============================================================
inline void json_escape(const char* in, char* out, int out_size) {
    int i = 0, j = 0;
    while (in[i] && j < out_size - 2) {
        if      (in[i] == '"')  { out[j++] = '\\'; out[j++] = '"';  }
        else if (in[i] == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (in[i] == '\n') { out[j++] = '\\'; out[j++] = 'n';  }
        else                    { out[j++] = in[i]; }
        i++;
    }
    out[j] = '\0';
}

inline int json_get_str(const char* json, const char* key, char* out, int out_size) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char* p = strstr(json, search);
    if (!p) { out[0] = '\0'; return 0; }
    p += strlen(search);
    int i = 0;
    while (*p && i < out_size - 1) {
        if (*p == '"' && (p == json || *(p-1) != '\\')) break;
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i;
}

inline long long json_get_num(const char* json, const char* key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":", key);
    const char* p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    if (*p == '"') return 0;
    return atoll(p);
}

// ============================================================
//  이전 수신자 히스토리
// ============================================================
inline void history_add(const char* email) {
    for (int i = 0; i < g_history_cnt; i++) {
        if (strcmp(g_history[i], email) == 0) {
            char tmp[256];
            strncpy(tmp, g_history[i], 255);
            for (int j = i; j > 0; j--)
                strncpy(g_history[j], g_history[j-1], 255);
            strncpy(g_history[0], tmp, 255);
            return;
        }
    }
    if (g_history_cnt < HISTORY_MAX) g_history_cnt++;
    for (int j = g_history_cnt - 1; j > 0; j--)
        strncpy(g_history[j], g_history[j-1], 255);
    strncpy(g_history[0], email, 255);
}

inline void history_show() {
    if (g_history_cnt == 0) { printf("  (없음)\n"); return; }
    for (int i = 0; i < g_history_cnt; i++)
        printf("  [%d] %s\n", i + 1, g_history[i]);
}

// ============================================================
//  5초 폴링 스레드
// ============================================================
#ifdef _WIN32
inline unsigned __stdcall alarm_thread(void* arg)
#else
inline void* alarm_thread(void* arg)
#endif
{
    (void)arg;
    char body[512], res[MAX_BODY];
    while (1) {
        sleep_sec(ALARM_INTERVAL);
        if (g_sock == SOCK_INVALID) continue;

        snprintf(body, sizeof(body),
            "{\"type\":\"%s\",\"user_pk\":%d}",
            REQ_MSG_CHECK, g_user_pk);

        if (net_send(g_sock, body) < 0) continue;
        if (net_recv(g_sock, res, sizeof(res)) < 0) continue;

        long long cnt = json_get_num(res, "unread_count");
        lock();
        g_unread = (int)cnt;
        unlock();
    }
#ifndef _WIN32
    return NULL;
#endif
}

// ============================================================
//  메뉴: 메시지 보내기
// ============================================================
inline void menu_send() {
    char receiver[256] = {0};
    char content[MAX_CONTENT + 1] = {0};
    char res[MAX_BODY];

    printf("\n=== 메시지 보내기 ===\n");

    // 수신자 입력 (히스토리)
    printf("보낼 대상 이메일 (이전 기록: 번호 입력 또는 직접 입력):\n");
    history_show();
    printf("> ");
    fflush(stdout);

    char input[256] = {0};
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\r\n")] = '\0';

    int idx = atoi(input);
    if (idx >= 1 && idx <= g_history_cnt) {
        strncpy(receiver, g_history[idx - 1], 255);
        printf("선택된 수신자: %s\n", receiver);
    } else {
        strncpy(receiver, input, 255);
    }

    if (strlen(receiver) == 0) {
        printf("수신자를 입력하세요.\n");
        return;
    }

    // 수신자 존재 여부 확인
    {
        char body[512], esc[512];
        json_escape(receiver, esc, sizeof(esc));
        snprintf(body, sizeof(body),
            "{\"type\":\"%s\",\"receiver\":\"%s\",\"user_pk\":%d}",
            REQ_MSG_CHECK_USER, esc, g_user_pk);

        if (net_send(g_sock, body) < 0 || net_recv(g_sock, res, sizeof(res)) < 0) {
            printf("[오류] 서버 통신 실패\n");
            return;
        }
        char result[64];
        json_get_str(res, "result", result, sizeof(result));
        if (strcmp(result, "OK") != 0) {
            color_red();
            printf("존재하지 않는 사용자입니다: %s\n", receiver);
            color_reset();
            return;
        }
    }

    // 메시지 내용 입력
    printf("메시지 내용 (최대 1024byte):\n> ");
    fflush(stdout);
    fgets(content, MAX_CONTENT + 1, stdin);
    content[strcspn(content, "\r\n")] = '\0';

    if (strlen(content) == 0) {
        printf("메시지 내용을 입력하세요.\n");
        return;
    }
    if (strlen(content) > MAX_CONTENT) {
        content[MAX_CONTENT] = '\0';
        printf("[알림] 1024byte 초과, 잘립니다.\n");
    }

    // 전송 전 확인창
    printf("\n┌─────────────────────────────────────┐\n");
    printf("│           전송 전 확인                │\n");
    printf("├─────────────────────────────────────┤\n");
    printf("│ 수신자: %-28s│\n", receiver);
    printf("│ 내용  : %-28s│\n", content);
    printf("└─────────────────────────────────────┘\n");
    printf("보내시겠습니까? [1: 보낸다 / 0: 보내지 않는다]: ");
    fflush(stdout);

    char confirm[8] = {0};
    fgets(confirm, sizeof(confirm), stdin);
    if (confirm[0] != '1') {
        printf("전송 취소되었습니다.\n");
        return;
    }

    // 실제 전송
    {
        char esc_recv[512], esc_cont[2048], body[4096];
        json_escape(receiver, esc_recv, sizeof(esc_recv));
        json_escape(content,  esc_cont, sizeof(esc_cont));
        snprintf(body, sizeof(body),
            "{\"type\":\"%s\",\"user_pk\":%d,\"receiver\":\"%s\",\"content\":\"%s\"}",
            REQ_MSG_SEND, g_user_pk, esc_recv, esc_cont);

        if (net_send(g_sock, body) < 0 || net_recv(g_sock, res, sizeof(res)) < 0) {
            printf("[오류] 서버 통신 실패\n");
            return;
        }
        char result[64];
        json_get_str(res, "result", result, sizeof(result));
        if (strcmp(result, "OK") == 0) {
            color_blue();
            printf("메시지 전송 완료!\n");
            color_reset();
            history_add(receiver);
        } else {
            char msg[256];
            json_get_str(res, "message", msg, sizeof(msg));
            color_red();
            printf("전송 실패: %s\n", msg);
            color_reset();
        }
    }
}

// ============================================================
//  메뉴: 메시지 확인 (목록 + 페이지네이션)
// ============================================================
inline void menu_view() {
    char body[512], res[MAX_BODY];
    int  page  = 1;
    long long total = 0;

    while (1) {
        snprintf(body, sizeof(body),
            "{\"type\":\"%s\",\"user_pk\":%d,\"page\":%d,\"page_size\":%d}",
            REQ_MSG_LIST, g_user_pk, page, PAGE_SIZE);

        if (net_send(g_sock, body) < 0 || net_recv(g_sock, res, sizeof(res)) < 0) {
            printf("[오류] 서버 통신 실패\n");
            return;
        }

        total = json_get_num(res, "total");
        int total_pages = (int)((total + PAGE_SIZE - 1) / PAGE_SIZE);
        if (total_pages < 1) total_pages = 1;

        printf("\n=== 메시지 목록 [%d/%d 페이지] (총 %lld개) ===\n",
               page, total_pages, total);

        // messages 배열 파싱
        const char* arr_start = strstr(res, "\"messages\":[");
        if (!arr_start) {
            printf("메시지가 없습니다.\n");
        } else {
            arr_start += strlen("\"messages\":[");
            const char* p = arr_start;
            int count = 0;

            while (*p && *p != ']' && count < PAGE_SIZE) {
                if (*p != '{') { p++; continue; }

                int depth = 0;
                const char* obj_start = p;
                while (*p) {
                    if      (*p == '{') depth++;
                    else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
                    p++;
                }
                int obj_len = (int)(p - obj_start);
                char obj[MAX_BODY];
                if (obj_len >= (int)sizeof(obj)) obj_len = (int)sizeof(obj) - 1;
                strncpy(obj, obj_start, obj_len);
                obj[obj_len] = '\0';

                long long msg_id  = json_get_num(obj, "msg_id");
                long long read_st = json_get_num(obj, "read_status");
                char sender[256]={0}, sent_at[64]={0}, content[MAX_CONTENT+1]={0};
                json_get_str(obj, "sender_email", sender,  sizeof(sender));
                json_get_str(obj, "sent_at",      sent_at, sizeof(sent_at));
                json_get_str(obj, "content",      content, sizeof(content));

                count++;
                // read_status: 0=읽음(파란), 1=안읽음(흰)
                if (read_st == 0) color_blue();
                else              color_white();

                printf("[%d] ID:%-6lld 보낸이: %-20s 시간: %s\n",
                       count, msg_id, sender, sent_at);
                printf("     내용: %s\n", content);
                color_reset();

                if (*p == ',') p++;
            }
            if (count == 0) printf("메시지가 없습니다.\n");
        }

        printf("\n[이전: p] [다음: n] [읽기: r<ID>] [삭제: d<ID>] [0: 뒤로]\n> ");
        fflush(stdout);

        char cmd[64] = {0};
        fgets(cmd, sizeof(cmd), stdin);
        cmd[strcspn(cmd, "\r\n")] = '\0';

        if (cmd[0] == '0') {
            break;
        } else if (cmd[0] == 'p' || cmd[0] == 'P') {
            if (page > 1) page--;
            else printf("첫 페이지입니다.\n");
        } else if (cmd[0] == 'n' || cmd[0] == 'N') {
            int tp = (int)((total + PAGE_SIZE - 1) / PAGE_SIZE);
            if (page < tp) page++;
            else printf("마지막 페이지입니다.\n");
        } else if ((cmd[0] == 'r' || cmd[0] == 'R') && strlen(cmd) > 1) {
            long long mid = atoll(cmd + 1);
            char rbody[256], rres[MAX_BODY];
            snprintf(rbody, sizeof(rbody),
                "{\"type\":\"%s\",\"user_pk\":%d,\"msg_id\":%lld}",
                REQ_MSG_READ, g_user_pk, mid);
            if (net_send(g_sock, rbody) >= 0)
                net_recv(g_sock, rres, sizeof(rres));
            printf("읽음 처리 완료 (ID: %lld)\n", mid);
        } else if ((cmd[0] == 'd' || cmd[0] == 'D') && strlen(cmd) > 1) {
            long long mid = atoll(cmd + 1);
            printf("ID %lld 메시지를 삭제하시겠습니까? [1: 예 / 0: 아니오]: ", mid);
            fflush(stdout);
            char dc[8] = {0};
            fgets(dc, sizeof(dc), stdin);
            if (dc[0] == '1') {
                char dbody[256], dres[MAX_BODY];
                snprintf(dbody, sizeof(dbody),
                    "{\"type\":\"%s\",\"user_pk\":%d,\"msg_id\":%lld}",
                    REQ_MSG_DELETE, g_user_pk, mid);
                if (net_send(g_sock, dbody) >= 0)
                    net_recv(g_sock, dres, sizeof(dres));
                printf("삭제 완료.\n");
            } else {
                printf("삭제 취소.\n");
            }
        } else {
            printf("알 수 없는 명령입니다.\n");
        }
    }
}

// ============================================================
//  메인 메시지 메뉴
// ============================================================
inline void menu_message() {
    while (1) {
        lock();
        int unread = g_unread;
        unlock();

        printf("\n");
        if (unread > 0) {
            color_yellow();
            printf("*** 읽지 않은 메시지가 %d개 있습니다! ***\n", unread);
            color_reset();
        }
        printf("=== [메시지] (안읽음: %d) ===\n", unread);
        printf("1. 메시지 보내기\n");
        printf("2. 메시지 확인\n");
        printf("0. 뒤로가기\n");
        printf("선택: ");
        fflush(stdout);

        char input[8] = {0};
        fgets(input, sizeof(input), stdin);
        int choice = atoi(input);

        if      (choice == 1) menu_send();
        else if (choice == 2) menu_view();
        else if (choice == 0) break;
        else printf("잘못된 입력입니다.\n");
    }
}

// ============================================================
//  소켓 초기화 / 정리
// ============================================================
inline int init_network() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("[오류] WSAStartup 실패\n");
        return -1;
    }
    InitializeCriticalSection(&g_cs);
#endif
    return 0;
}

inline void cleanup_network() {
#ifdef _WIN32
    DeleteCriticalSection(&g_cs);
    WSACleanup();
#endif
}

// ============================================================
//  클라이언트 메인
// ============================================================
inline int clientMain(int user_pk) {
    if (init_network() < 0) return -1;

    g_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_sock == SOCK_INVALID) {
        printf("[오류] 소켓 생성 실패\n");
        cleanup_network();
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(SERVER_PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(g_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("[오류] 서버 연결 실패! (%s:%d)\n", SERVER_IP, SERVER_PORT);
        sock_close(g_sock);
        cleanup_network();
        return -1;
    }

    g_user_pk = user_pk;
    printf("서버 연결 성공! (user_pk: %d)\n", g_user_pk);

    // 5초 폴링 스레드 시작
#ifdef _WIN32
    HANDLE tid = (HANDLE)_beginthreadex(NULL, 0,
        (unsigned(__stdcall*)(void*))alarm_thread, NULL, 0, NULL);
    CloseHandle(tid);
#else
    pthread_t tid;
    pthread_create(&tid, NULL, alarm_thread, NULL);
    pthread_detach(tid);
#endif

    // 메인 루프
    while (1) {
        lock();
        int unread = g_unread;
        unlock();

        printf("\n=== 메인 메뉴");
        if (unread > 0) {
            color_yellow();
            printf(" [안읽은 메시지: %d]", unread);
            color_reset();
        }
        printf(" ===\n");
        printf("1. 메시지\n");
        printf("0. 종료\n");
        printf("선택: ");
        fflush(stdout);

        char input[8] = {0};
        fgets(input, sizeof(input), stdin);
        int choice = atoi(input);

        if      (choice == 1) menu_message();
        else if (choice == 0) break;
        else printf("잘못된 입력입니다.\n");
    }
    sock_close(g_sock);
    cleanup_network();
    printf("종료합니다.\n");
    return 0;
}
