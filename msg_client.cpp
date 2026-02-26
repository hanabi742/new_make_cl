// ============================================================
//  msg_client.cpp  —  메시지 클라이언트 C++ 구현
//  C에서 호출 가능하도록 extern "C" 래퍼 제공
// ============================================================
#include "MsgClientLogic.hpp"
#include "msg_client.h"

extern "C" {

int msg_init(int user_pk) {
    if (init_network() < 0) return -1;

    g_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_sock == SOCK_INVALID) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(9001);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(g_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        sock_close(g_sock);
        g_sock = SOCK_INVALID;
        return -1;
    }

    g_user_pk = user_pk;

    // 5초 폴링 스레드 시작
    pthread_t tid;
    pthread_create(&tid, NULL, alarm_thread, NULL);
    pthread_detach(tid);

    return 0;
}

int msg_get_unread(void) {
    lock();
    int n = g_unread;
    unlock();
    return n;
}

void msg_run_menu(void) {
    menu_message();
}

void msg_cleanup(void) {
    if (g_sock != SOCK_INVALID) {
        sock_close(g_sock);
        g_sock = SOCK_INVALID;
    }
    cleanup_network();
}

} // extern "C"
