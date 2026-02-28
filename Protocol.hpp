#pragma once

// 1. 공용 표준 헤더 (C/C++ 둘 다 인식)
#include <stdint.h>
#include <string.h>

/* 2. C++ 전용 헤더 및 라이브러리 (서버용)
   __cplusplus 매크로를 사용하여 C 컴파일러(gcc)가 읽지 못하게 격리합니다. */
#ifdef __cplusplus
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <mutex>
#include <thread>
namespace fs = std::filesystem;
#endif

/* 3. OS별 네트워크 헤더 분리 */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

// 4. 상수 정의 (C언어 호환을 위해 namespace 대신 #define이나 enum 사용)
#define SERVER_PORT 9000
#define MAX_PACKET_SIZE (64 * 1024)
#define STORAGE_ROOT "./storage"

/* 5. 패킷 타입 정의 (enum 사용) */
typedef enum
{
    // --- 파일 업로드/다운로드 관련 (1~8) ---
    PKT_REQ_UPLOAD_START = 1,
    PKT_RES_UPLOAD_START = 2,
    PKT_REQ_UPLOAD_CHUNK = 3,
    PKT_REQ_UPLOAD_END = 4,
    PKT_RES_UPLOAD_END = 5,
    PKT_REQ_DOWNLOAD_START = 6,
    PKT_RES_DOWNLOAD_START = 7,
    PKT_RES_DOWNLOAD_DATA = 8,

    // --- 인증 및 이메일 (10~23) ---
    PKT_REQ_REGISTER = 10,
    PKT_RES_REGISTER = 11,
    PKT_REQ_LOGIN = 12,
    PKT_RES_LOGIN = 13,
    PKT_REQ_EMAIL_AUTH = 20,
    PKT_RES_EMAIL_AUTH = 21,
    PKT_REQ_EMAIL_VERIFY = 22,
    PKT_RES_EMAIL_VERIFY = 23,

    // --- 파일 관리 확장 (40~46) ---
    PKT_REQ_LIST = 40,          // 목록 요청
    PKT_RES_LIST = 41,          // 목록 응답 (개별 파일 정보)
    PKT_RES_LIST_END = 42,      // 목록 응답 완료
    PKT_REQ_DELETE = 43,        // 단일 파일 삭제
    PKT_RES_DELETE = 44,        // 삭제 결과
    PKT_REQ_DELETE_FOLDER = 45, // 폴더 전체 삭제
    PKT_RES_DELETE_FOLDER = 46, // 폴더 삭제 결과

    // --- 관리자 및 설정, 용량 조회 (100~311) ---
    PKT_RES_HANDSHAKE = 100,
    PKT_REQ_ADMIN_NOTICE = 200,
    PKT_RES_ADMIN_NOTICE = 201,
    PKT_REQ_ADMIN_BAN = 202,
    PKT_REQ_ADMIN_RESET = 204,
    PKT_REQ_ADMIN_USAGE = 206,
    PKT_REQ_USER_SETTINGS = 300,
    PKT_RES_USER_SETTINGS = 301,
    PKT_REQ_STORAGE_INFO = 310, // 용량 정보 요청
    PKT_RES_STORAGE_INFO = 311, // 용량 정보 응답

    PKT_REQ_UPGRADE_GRADE = 320,
    PKT_RES_UPGRADE_GRADE = 321,
    PKT_REQ_ADMIN_STATUS = 322, // 관리자 시스템 상태 요청
    PKT_RES_ADMIN_STATUS = 323, // 관리자 시스템 상태 응답
} PacketType;

/* 6. 패킷 구조체 (1바이트 정렬) */
#pragma pack(push, 1)
struct FilePacket
{
    int16_t type;       // PacketType
    int32_t user_pk;    // 유저 PK
    int32_t file_pk;    // 파일 PK (업로드 시 서버가 발급, 다운로드 시 클라이언트가 요청)
    // long offset;  // 파일의 어느 위치부터 데이터를 담고 있는지 나타내는 필드입니다. 업로드 시에는 0으로 보내지만, 다운로드 시에는 0부터 시작해서 8KB씩 증가하는 값을 보냅니다. 이렇게 하면 나중에 이어받기 기능을 추가할 때도 이 필드를 활용할 수 있습니다.
    int64_t offset;
    int32_t data_size;  // 실제로 담긴 데이터의 크기입니다. 업로드 시에는 8KB 이하로 보내지만, 마지막 조각은 8KB보다 작을 수 있기 때문에 이 필드가 필요합니다. 다운로드 시에도 8KB씩 보내지만, 마지막 조각은 8KB보다 작을 수 있기 때문에 이 필드가 필요합니다.
    int64_t file_size;  // 파일 전체 크기입니다. 다운로드 시작 응답에서 클라이언트에게 파일 크기를 알려주기 위해 사용됩니다. 업로드 시에는 0으로 보내지만, 다운로드 시에는 실제 파일 크기를 담아서 보냅니다.
    char fileName[256]; // 파일 이름을 저장할 공간 (최대 256바이트)
    char data[8192];    // 8KB 데이터 그릇
};
#pragma pack(pop)

/* 7. C++ 전용 설정 (서버 코드에서 사용) */
#ifdef __cplusplus
namespace ServerConfig
{
    inline constexpr uint16_t PORT = 9000;
    inline constexpr size_t MAX_FILE_SIZE = 1ULL * 1024 * 1024 * 1024;
    inline constexpr const char *ROOT = "./storage";
}
#endif

// [2] 인증 전용 구조체 추가 (기존 FilePacket과 별개로 사용)
#pragma pack(push, 1)
struct AuthPacket
{
    int16_t type;      // PKT_REQ_REGISTER 또는 PKT_REQ_LOGIN
    char id[25];       // 유저 아이디
    char pwd_hash[65]; // 클라이언트가 SHA-256으로 변환해서 보낼 64자리 비밀번호 + NULL
    char name[10];     // [추가] 회원가입 시 받을 이름 필드 (ERD varchar(5) 고려)
};
#pragma pack(pop)

#pragma pack(push, 1)
struct AuthResponse
{
    int16_t type;    // PKT_RES_REGISTER 또는 PKT_RES_LOGIN
    int32_t user_pk; // 성공 시 유저 PK, 실패 시 -1
    int is_admin;    // 0: 일반, 1: 관리자

    // 💡 이 필드가 서버와 클라이언트 양쪽에 똑같이 있어야 '데이터 크기'가 맞아떨어집니다.
    char download_path[131];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ServerHandshakeHeader // 서버 접속 직후 클라이언트가 무조건 처음 받게 되는 헤더 패킷
{
    int16_t type;          // 항상 PKT_RES_HANDSHAKE (100)
    float server_version;  // 서버의 현재 버전 (예: 1.2)
    int32_t current_users; // 현재 접속자 수
    int32_t max_users;     // 서버 최대 수용 인원
    int32_t next_port;     // 포트 변경이 예정되어 있다면 해당 포트 번호 (없으면 0)
};
#pragma pack(pop)

#pragma pack(push, 1)
struct AdminPacket // 관리자가 서버로 명령을 보낼 때 사용할 구조체
{
    int16_t type;      // 위에서 정의한 200, 201, 202 중 하나
    int32_t admin_pk;  // 요청하는 사람의 PK (보안 검증용, 무조건 1이어야 함)
    int32_t target_pk; // 차단할 대상 유저의 PK (차단 기능에서만 사용)
    char data[256];    // 공지사항 메시지 등 문자열 데이터
};
#pragma pack(pop)

#pragma pack(push, 1)
struct UserSettingsPacket
{
    int16_t type;         // PKT_REQ_USER_SETTINGS
    int32_t user_pk;      // 변경을 요청하는 유저의 PK
    int32_t setting_type; // 1: 이름 변경, 2: 비밀번호 변경
    char new_data[131];   // 새 이름, 또는 해시화된 새 비밀번호
};
#pragma pack(pop)

#pragma pack(push, 1)
struct BlacklistReqPacket
{
    int16_t type;
    int32_t self_user_num;
    int32_t blacklist_num;
    char target_email[128];
};
struct BlacklistResPacket
{
    int16_t type;
    int32_t result_code;
    int32_t blacklist_num;
    char target_email[128];
    char created_at[20];
};
#pragma pack(pop)