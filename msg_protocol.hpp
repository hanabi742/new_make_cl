#pragma once
// ============================================================
//  msg_protocol.hpp  —  메시지 기능 전용 프로토콜 (JSON 기반)
//  make_cloud_prtocal.hpp 규격 준수:
//    [Header 4byte Big-Endian (Body 길이)] + [Body JSON 문자열]
// ============================================================

#include <cstdint>
#include <string>

#pragma pack(push, 1)
struct PacketHeader {
    uint32_t body_length;  // Big-Endian
};
#pragma pack(pop)

static constexpr size_t MSG_HEADER_SIZE = sizeof(PacketHeader); // 4 bytes
static constexpr size_t MAX_MSG_BODY    = 64 * 1024;            // 64KB

// ── 요청 타입 (Client → Server) ──────────────────────────────
namespace MSG_REQ {
    // 메시지 보내기
    inline constexpr const char* SEND         = "REQ_MSG_SEND";
    // 읽지 않은 메시지 개수 확인 (5초 폴링)
    inline constexpr const char* CHECK_UNREAD = "REQ_MSG_CHECK";
    // 메시지 목록 조회 (페이지네이션)
    inline constexpr const char* LIST         = "REQ_MSG_LIST";
    // 메시지 읽음 처리
    inline constexpr const char* READ         = "REQ_MSG_READ";
    // 메시지 삭제
    inline constexpr const char* DELETE_MSG   = "REQ_MSG_DELETE";
    // 수신자 이메일 존재 여부 확인
    inline constexpr const char* CHECK_USER   = "REQ_MSG_CHECK_USER";
}

// ── 응답 타입 (Server → Client) ──────────────────────────────
namespace MSG_RES {
    inline constexpr const char* SEND         = "RES_MSG_SEND";
    inline constexpr const char* CHECK_UNREAD = "RES_MSG_CHECK";
    inline constexpr const char* LIST         = "RES_MSG_LIST";
    inline constexpr const char* READ         = "RES_MSG_READ";
    inline constexpr const char* DELETE_MSG   = "RES_MSG_DELETE";
    inline constexpr const char* CHECK_USER   = "RES_MSG_CHECK_USER";
    inline constexpr const char* ERROR        = "RES_ERROR";
}

// ── 결과 코드 ─────────────────────────────────────────────────
namespace MSG_RESULT {
    inline constexpr const char* OK           = "OK";
    inline constexpr const char* FAIL         = "FAIL";
    inline constexpr const char* NOT_FOUND    = "NOT_FOUND";
}

// ── JSON 필드 키 ──────────────────────────────────────────────
namespace MSG_FIELD {
    inline constexpr const char* TYPE         = "type";
    inline constexpr const char* RESULT       = "result";
    inline constexpr const char* MESSAGE      = "message";
    inline constexpr const char* USER_PK      = "user_pk";
    inline constexpr const char* RECEIVER     = "receiver";   // 수신자 이메일
    inline constexpr const char* CONTENT      = "content";
    inline constexpr const char* UNREAD_COUNT = "unread_count";
    inline constexpr const char* MESSAGES     = "messages";
    inline constexpr const char* MSG_ID       = "msg_id";
    inline constexpr const char* SENDER_EMAIL = "sender_email";
    inline constexpr const char* SENT_AT      = "sent_at";
    inline constexpr const char* READ_STATUS  = "read_status"; // 0=읽음, 1=안읽음
    inline constexpr const char* PAGE         = "page";
    inline constexpr const char* PAGE_SIZE    = "page_size";
    inline constexpr const char* TOTAL        = "total";
    inline constexpr const char* EXISTS       = "exists";
}

// ── 서버 설정 ─────────────────────────────────────────────────
namespace MSG_SERVER {
    inline constexpr uint16_t PORT            = 9001;
    inline constexpr int      BACKLOG         = 128;
    inline constexpr int      PAGE_SIZE       = 20;
}
