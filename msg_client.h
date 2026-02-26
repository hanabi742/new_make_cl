#pragma once
// ============================================================
//  msg_client.h  —  C에서 호출할 메시지 함수 선언
// ============================================================

#ifdef __cplusplus
extern "C" {
#endif

// 메시지 서버 연결 + 폴링 스레드 시작
// 반환값: 0 성공, -1 실패
int  msg_init(int user_pk);

// 안읽은 메시지 개수 반환
int  msg_get_unread(void);

// 메시지 메뉴 실행 (블로킹 - 뒤로가기 누르면 반환)
void msg_run_menu(void);

// 메시지 소켓 종료
void msg_cleanup(void);

#ifdef __cplusplus
}
#endif
