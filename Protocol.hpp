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
    // --- 파일 업로드 관련 (1~5) ---
    PKT_REQ_UPLOAD_START = 1, // 클라이언트 -> 서버 (업로드 시작 요청)
    PKT_RES_UPLOAD_START = 2, // 서버 -> 클라이언트 (파일 PK 발급 응답)
    PKT_REQ_UPLOAD_CHUNK = 3, // 클라이언트 -> 서버 (파일 조각 전송)
    PKT_REQ_UPLOAD_END = 4,   // 클라이언트 -> 서버 (업로드 완료 보고)
    PKT_RES_UPLOAD_END = 5,   // 서버 -> 클라이언트 (최종 저장 완료 응답)

    // --- 파일 다운로드 관련 (6~8) ---
    PKT_REQ_DOWNLOAD_START = 6, // 클라이언트 -> 서버 (다운로드 요청)
    PKT_RES_DOWNLOAD_START = 7, // 서버 -> 클라이언트 (파일 정보/크기 응답)
    PKT_RES_DOWNLOAD_DATA = 8,  // 서버 -> 클라이언트 (파일 데이터 전송)
    PKT_REQ_DELETE = 9,         // 클라이언트 -> 서버 (삭제 요청)
    PKT_RES_DELETE = 10,        // 서버 -> 클라이언트 (삭제 결과 응답)
                                // --- 인증 관련 (10~13) ---
    PKT_REQ_REGISTER = 11,      // 클라이언트 -> 서버 (회원가입 요청)
    PKT_RES_REGISTER = 12,      // 서버 -> 클라이언트 (가입 결과/PK 응답)
    PKT_REQ_LOGIN = 13,         // 클라이언트 -> 서버 (로그인 요청)
    PKT_RES_LOGIN = 14,         // 서버 -> 클라이언트 (로그인 결과/PK 응답)

    // [이메일 인증 관련 패킷]
    PKT_REQ_EMAIL_AUTH = 20,   // 클라이언트 -> 서버: "이 주소로 메일 보내줘"
    PKT_RES_EMAIL_AUTH = 21,   // 서버 -> 클라이언트: "메일 보냈어(성공/실패)"
    PKT_REQ_EMAIL_VERIFY = 22, // 클라이언트 -> 서버: "내가 입력한 번호(123456) 맞니?"
    PKT_RES_EMAIL_VERIFY = 23  // 서버 -> 클라이언트: "번호 맞다/틀리다"
} PacketType;

/* 6. 패킷 구조체 (1바이트 정렬) */
#pragma pack(push, 1)
struct FilePacket
{
    int16_t type;       // PacketType
    int32_t user_pk;    // 유저 PK
    int32_t file_pk;    // 파일 PK (업로드 시 서버가 발급, 다운로드 시 클라이언트가 요청)
    long offset;        // 파일의 어느 위치부터 데이터를 담고 있는지 나타내는 필드입니다. 업로드 시에는 0으로 보내지만, 다운로드 시에는 0부터 시작해서 8KB씩 증가하는 값을 보냅니다. 이렇게 하면 나중에 이어받기 기능을 추가할 때도 이 필드를 활용할 수 있습니다.
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

struct AuthResponse
{
    int16_t type;    // PKT_RES_REGISTER 또는 PKT_RES_LOGIN
    int32_t user_pk; // 성공 시 발급/조회된 고유 PK (실패 시 -1)
};
#pragma pack(pop)