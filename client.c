#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include "Protocol.hpp"
#include "msg_client.h"
#define OPENSSL_API_COMPAT 0x30000000L

// ═══════════════════════════════════════════════════════════
//  공통 유틸 매크로
// ═══════════════════════════════════════════════════════════

#define CLEAR()                  \
    do                           \
    {                            \
        printf("\033[2J\033[H"); \
        fflush(stdout);          \
    } while (0)

#define FLUSH_STDIN()                                 \
    do                                                \
    {                                                 \
        int _c;                                       \
        while ((_c = getchar()) != '\n' && _c != EOF) \
            ;                                         \
    } while (0)

#define PAUSE()                        \
    do                                 \
    {                                  \
        printf("\n  [Enter] 계속..."); \
        FLUSH_STDIN();                 \
    } while (0)

// ═══════════════════════════════════════════════════════════
//  네트워크 헬퍼
// ═══════════════════════════════════════════════════════════
int recv_all(int sock, char *buf, int size)
{
    int total = 0;
    while (total < size)
    {
        int n = recv(sock, buf + total, size - total, 0);
        if (n <= 0)
            return n;
        total += n;
    }
    return total;
}

// ═══════════════════════════════════════════════════════════
//  유틸 함수
// ═══════════════════════════════════════════════════════════
void get_default_download_path(const char *filename, char *out_path)
{
    const char *home = getenv("HOME");
    if (!home)
        home = getenv("USERPROFILE");
    if (home)
        sprintf(out_path, "%s/Downloads/%s", home, filename);
    else
        strcpy(out_path, filename);
}

void hash_password(const char *plain, char *out)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, plain, strlen(plain));
    SHA256_Final(hash, &ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(out + i * 2, "%02x", hash[i]);
    out[64] = '\0';
}

void delete_file(int sock, int user_pk, int file_pk)
{
    struct FilePacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type    = PKT_REQ_DELETE;
    pkt.user_pk = user_pk;
    pkt.file_pk = file_pk;

    printf("  [System] 서버에 파일 삭제를 요청합니다...\n");
    send(sock, (char *)&pkt, sizeof(pkt), 0);

    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0)
    {
        if (pkt.type == PKT_RES_DELETE && pkt.file_pk == 1)
        {
            printf("  [Success] 파일(PK: %d)이 성공적으로 삭제되었습니다.\n", file_pk);
            printf("  [System] 남은 저장소 용량이 복구되었습니다!\n");
        }
        else
            printf("  [Error] 파일 삭제 실패. (권한이 없거나 이미 삭제된 파일입니다)\n");
    }
    else
        printf("  [Error] 서버 응답이 없습니다.\n");
}

// ═══════════════════════════════════════════════════════════
//  인증
// ═══════════════════════════════════════════════════════════
int handle_email_auth(int sock, char *out_email)
{
    char code[16];
    struct FilePacket pkt;

    // [수정] ERD: ID VARCHAR(25) → 최대 25자 입력 제한
    printf("  이메일 주소 (최대 25자): ");
    scanf("%25s", out_email);
    FLUSH_STDIN();

    memset(&pkt, 0, sizeof(pkt));
    pkt.type = 20;
    strncpy(pkt.data, out_email, sizeof(pkt.data) - 1);
    send(sock, (char *)&pkt, sizeof(pkt), 0);

    printf("  [System] 인증 메일 발송 중...\n");
    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0 && pkt.file_pk == -1)
    {
        printf("  [Error] 발송 실패 (이미 가입된 이메일이거나 서버 오류)\n");
        return 0;
    }

    printf("  [Success] 메일 발송 완료. 6자리 인증번호: ");
    scanf("%15s", code);
    FLUSH_STDIN();

    memset(&pkt, 0, sizeof(pkt));
    pkt.type = 22;
    strncpy(pkt.data, code, sizeof(pkt.data) - 1);
    send(sock, (char *)&pkt, sizeof(pkt), 0);

    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0 && pkt.file_pk == 1)
    {
        printf("  [Success] 이메일 인증 성공!\n");
        return 1;
    }
    printf("  [Error] 인증번호가 틀렸습니다.\n");
    return 0;
}

int request_auth(int sock, int type, const char *id, const char *plain_pwd, const char *name)
{
    struct AuthPacket req;
    memset(&req, 0, sizeof(req));
    req.type = type;
    strncpy(req.id, id, sizeof(req.id) - 1);
    hash_password(plain_pwd, req.pwd_hash);
    if (name)
        strncpy(req.name, name, sizeof(req.name) - 1);
    send(sock, (char *)&req, sizeof(req), 0);

    struct AuthResponse res;
    if (recv_all(sock, (char *)&res, sizeof(res)) <= 0)
        return -1;
    return res.user_pk;
}

// ═══════════════════════════════════════════════════════════
//  파일 기능
// ═══════════════════════════════════════════════════════════
int upload_file(int sock, int user_pk, const char *filename)
{
    struct FilePacket *pkt = (struct FilePacket *)malloc(sizeof(struct FilePacket));
    int file_pk = -1;

    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        printf("  [Error] 파일 없음: %s\n", filename);
        free(pkt);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    memset(pkt, 0, sizeof(*pkt));
    pkt->type      = PKT_REQ_UPLOAD_START;
    pkt->user_pk   = user_pk;
    pkt->file_size = fsize;
    send(sock, (char *)pkt, sizeof(*pkt), 0);

    if (recv_all(sock, (char *)pkt, sizeof(*pkt)) > 0)
    {
        file_pk = pkt->file_pk;
        if (file_pk == -1)
        {
            printf("  [Error] 업로드 거부 (용량 초과 등)\n");
            free(pkt);
            fclose(fp);
            return -1;
        }
        printf("  전송 중: ");
        while (1)
        {
            memset(pkt, 0, sizeof(*pkt));
            pkt->type    = PKT_REQ_UPLOAD_CHUNK;
            pkt->user_pk = user_pk;
            pkt->file_pk = file_pk;
            size_t rb = fread(pkt->data, 1, 8192, fp);
            if (rb > 0)
            {
                pkt->data_size = (int)rb;
                send(sock, (char *)pkt, sizeof(*pkt), 0);
                printf("#");
                fflush(stdout);
            }
            if (feof(fp))
                break;
            usleep(10000);
        }
        fclose(fp);
        printf("\n  전송 완료!\n");
    }

    memset(pkt, 0, sizeof(*pkt));
    pkt->type    = PKT_REQ_UPLOAD_END;
    pkt->user_pk = user_pk;
    pkt->file_pk = file_pk;
    send(sock, (char *)pkt, sizeof(*pkt), 0);

    if (recv_all(sock, (char *)pkt, sizeof(*pkt)) > 0 && pkt->type == PKT_RES_UPLOAD_END)
        printf("  [Success] 업로드 완료!\n");

    free(pkt);
    return file_pk;
}

void download_file(int sock, int user_pk, int file_pk, const char *save_path, const char *filename)
{
    struct FilePacket *pkt = (struct FilePacket *)malloc(sizeof(struct FilePacket));
    memset(pkt, 0, sizeof(*pkt));
    pkt->type    = PKT_REQ_DOWNLOAD_START;
    pkt->user_pk = user_pk;
    pkt->file_pk = file_pk;
    send(sock, (char *)pkt, sizeof(*pkt), 0);

    if (recv_all(sock, (char *)pkt, sizeof(*pkt)) <= 0)
    {
        printf("  [Error] 서버 연결 끊김\n");
        free(pkt);
        return;
    }

    long total = pkt->file_size, received = 0;
    if (total == 0)
    {
        printf("  [Error] 파일 없음\n");
        free(pkt);
        return;
    }

    FILE *fp = fopen(save_path, "wb");
    if (!fp)
    {
        fp = fopen(filename, "wb");
        if (!fp) { free(pkt); return; }
    }

    printf("  다운로드 중 (%ld bytes)...\n", total);
    while (received < total)
    {
        if (recv_all(sock, (char *)pkt, sizeof(*pkt)) <= 0)
        {
            fclose(fp);
            remove(save_path);
            free(pkt);
            return;
        }
        if (pkt->type == PKT_RES_DOWNLOAD_DATA)
        {
            fwrite(pkt->data, 1, pkt->data_size, fp);
            received += pkt->data_size;
            printf("\r  [%ld / %ld]", received, total);
            fflush(stdout);
        }
    }
    printf("\n  [Success] 다운로드 완료!\n");
    fclose(fp);
    free(pkt);
}

// ═══════════════════════════════════════════════════════════
//  서브메뉴: 📂 파일
// ═══════════════════════════════════════════════════════════
void menu_file(int sock, int user_pk)
{
    while (1)
    {
        CLEAR();
        printf("  ╔══════════════════════════════════╗\n");
        printf("  ║     📂  파일 (File)               ║\n");
        printf("  ╠══════════════════════════════════╣\n");
        printf("  ║  1. 저장 (Upload)                ║\n");
        printf("  ║  2. 불러오기 (Download)          ║\n");
        printf("  ║  3. 내 파일 목록                 ║\n");
        printf("  ║  4. 파일 삭제                    ║\n");
        printf("  ║  0. 돌아가기                     ║\n");
        printf("  ╚══════════════════════════════════╝\n");
        printf("  선택: ");

        int ch;
        if (scanf("%d", &ch) != 1) { FLUSH_STDIN(); continue; }
        FLUSH_STDIN();

        if (ch == 0) { CLEAR(); return; }
        CLEAR();

        if (ch == 1)
        {
            char path[256];
            printf("  업로드할 파일 경로: ");
            scanf("%255s", path);
            FLUSH_STDIN();
            upload_file(sock, user_pk, path);
            PAUSE();
        }
        else if (ch == 2)
        {
            int fpk;
            char fname[256], spath[512];
            printf("  파일 PK: ");
            scanf("%d", &fpk);
            FLUSH_STDIN();
            printf("  저장 파일명: ");
            scanf("%255s", fname);
            FLUSH_STDIN();
            get_default_download_path(fname, spath);
            printf("  저장 위치: %s\n", spath);
            download_file(sock, user_pk, fpk, spath, fname);
            PAUSE();
        }
        else if (ch == 3)
        {
            printf("  [System] 파일 목록 조회 (미구현)\n");
            PAUSE();
        }
        else if (ch == 4)
        {
            int dpk;
            printf("  삭제할 파일 PK: ");
            scanf("%d", &dpk);
            FLUSH_STDIN();
            delete_file(sock, user_pk, dpk);
            PAUSE();
        }
        else
        {
            printf("  [Error] 0~4 중 선택하세요.\n");
            PAUSE();
        }
    }
}

// ═══════════════════════════════════════════════════════════
// [추가] 개인 설정 — 기본 이메일 설정
//
// ERD: DEFAULT_EMAIL VARCHAR(64) → 64자 초과 입력 차단
//      ID VARCHAR(25) → 로그인 이메일 최대 25자
//
// PKT_REQ_UPDATE_EMAIL 패킷으로 서버에 요청.
// AuthPacket.id 필드에 새 기본 이메일을 담아 전송.
// ═══════════════════════════════════════════════════════════
static void menu_personal_default_email(int sock, int user_pk, const char *login_email)
{
    CLEAR();
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║     📧  기본 이메일 설정                 ║\n");
    printf("  ╠══════════════════════════════════════════╣\n");

    // ── 서버에서 현재 기본 이메일 조회 ──────────────────────
    struct AuthPacket info_req;
    memset(&info_req, 0, sizeof(info_req));
    info_req.type    = PKT_REQ_GET_USER_INFO;
    info_req.user_pk = user_pk;
    send(sock, (char *)&info_req, sizeof(info_req), 0);

    struct AuthResponse info_res;
    memset(&info_res, 0, sizeof(info_res));

    // [수정] ERD: DEFAULT_EMAIL VARCHAR(64) → 버퍼 65바이트
    char current_default[65] = {0};

    if (recv_all(sock, (char *)&info_res, sizeof(info_res)) > 0 && info_res.user_pk > 0)
    {
        if (strlen(info_res.default_email) > 0)
            strncpy(current_default, info_res.default_email, 64);
        else
            strncpy(current_default, login_email, 64); // 미설정 시 로그인 이메일 표시
    }
    else
    {
        strncpy(current_default, login_email, 64);
    }

    printf("  ║  현재 기본 이메일:                       ║\n");
    printf("  ║  %-40s║\n", current_default);
    printf("  ║                                          ║\n");
    printf("  ║  새 기본 이메일을 입력하세요.            ║\n");
    printf("  ║  (최대 64자 / Enter만 누르면 취소)       ║\n");
    printf("  ╚══════════════════════════════════════════╝\n");
    printf("  새 이메일: ");

    // [수정] ERD: DEFAULT_EMAIL VARCHAR(64) → 최대 64자 입력
    char new_email[65] = {0};
    if (fgets(new_email, sizeof(new_email), stdin) == NULL) return;

    size_t len = strlen(new_email);
    if (len > 0 && new_email[len - 1] == '\n') new_email[len - 1] = '\0';

    // 빈 입력이면 취소
    if (strlen(new_email) == 0)
    {
        printf("  [System] 취소되었습니다.\n");
        PAUSE();
        return;
    }

    // '@' 포함 여부 간단 유효성 검사
    if (strchr(new_email, '@') == NULL)
    {
        printf("  [Error] 올바른 이메일 형식이 아닙니다. ('@' 필요)\n");
        PAUSE();
        return;
    }

    // [수정] ERD: DEFAULT_EMAIL VARCHAR(64) → 64자 초과 차단
    if (strlen(new_email) > 64)
    {
        printf("  [Error] 이메일은 최대 64자까지 입력 가능합니다. (ERD 제한)\n");
        PAUSE();
        return;
    }

    // ── 서버로 기본 이메일 변경 요청 전송 ───────────────────
    struct AuthPacket req;
    memset(&req, 0, sizeof(req));
    req.type    = PKT_REQ_UPDATE_EMAIL;
    req.user_pk = user_pk;
    // [수정] ERD: ID VARCHAR(25)이지만 기본이메일은 DEFAULT_EMAIL(64)에 저장됨
    //        AuthPacket.id 필드 대신 AuthPacket.name 등 여유 필드를 사용하거나
    //        id 필드 크기를 65로 조정 필요 → Protocol.hpp 수정 가이드 참고
    strncpy(req.id, new_email, sizeof(req.id) - 1);

    send(sock, (char *)&req, sizeof(req), 0);

    // ── 서버 응답 수신 ───────────────────────────────────────
    struct AuthResponse res;
    memset(&res, 0, sizeof(res));

    if (recv_all(sock, (char *)&res, sizeof(res)) > 0)
    {
        if (res.user_pk == 1)
            printf("  [Success] 기본 이메일이 '%s'(으)로 변경되었습니다.\n", new_email);
        else
            printf("  [Error] 기본 이메일 변경에 실패했습니다. (서버 오류)\n");
    }
    else
        printf("  [Error] 서버 응답이 없습니다.\n");

    PAUSE();
}

// ═══════════════════════════════════════════════════════════
// [추가] 개인 설정 — 비밀번호 변경
//
// ERD: PW VARCHAR(64) → SHA-256 hex(64자)와 일치
// 현재 PW 검증 후 새 PW로 교체.
// 클라이언트에서 SHA-256 해싱 후 전송 (요구사항 7).
//
// 비밀번호 조건 (요구사항 3-1):
//   - 8자 이상
//   - 영문자 + 숫자 혼합
//   - 비밀번호 확인 일치
// ═══════════════════════════════════════════════════════════
static void menu_personal_change_pw(int sock, int user_pk)
{
    CLEAR();
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║     🔒  비밀번호 변경                    ║\n");
    printf("  ╠══════════════════════════════════════════╣\n");
    printf("  ║  조건: 8자 이상, 영문+숫자 혼합          ║\n");
    printf("  ╚══════════════════════════════════════════╝\n");

    char old_plain[64]    = {0};
    char new_plain[64]    = {0};
    char new_confirm[64]  = {0};

    printf("  현재 비밀번호: ");
    if (fgets(old_plain, sizeof(old_plain), stdin) == NULL) return;
    { size_t l = strlen(old_plain); if (l > 0 && old_plain[l-1] == '\n') old_plain[l-1] = '\0'; }

    printf("  새 비밀번호  : ");
    if (fgets(new_plain, sizeof(new_plain), stdin) == NULL) return;
    { size_t l = strlen(new_plain); if (l > 0 && new_plain[l-1] == '\n') new_plain[l-1] = '\0'; }

    // ── 비밀번호 조건 검사 (요구사항 3-1) ───────────────────
    if (strlen(new_plain) < 8)
    {
        printf("  [Error] 비밀번호는 최소 8자 이상이어야 합니다.\n");
        PAUSE();
        return;
    }

    int has_alpha = 0, has_digit = 0;
    for (int i = 0; new_plain[i]; i++)
    {
        if ((new_plain[i] >= 'a' && new_plain[i] <= 'z') ||
            (new_plain[i] >= 'A' && new_plain[i] <= 'Z')) has_alpha = 1;
        if (new_plain[i] >= '0' && new_plain[i] <= '9')   has_digit = 1;
    }
    if (!has_alpha || !has_digit)
    {
        printf("  [Error] 비밀번호는 영문자와 숫자를 모두 포함해야 합니다.\n");
        PAUSE();
        return;
    }

    // ── 비밀번호 확인 (요구사항 3-1) ────────────────────────
    printf("  새 비밀번호 확인: ");
    if (fgets(new_confirm, sizeof(new_confirm), stdin) == NULL) return;
    { size_t l = strlen(new_confirm); if (l > 0 && new_confirm[l-1] == '\n') new_confirm[l-1] = '\0'; }

    if (strcmp(new_plain, new_confirm) != 0)
    {
        printf("  [Error] 새 비밀번호가 일치하지 않습니다.\n");
        PAUSE();
        return;
    }

    // ── SHA-256 해싱 (요구사항 7: 서버에 평문 전달 금지) ────
    char old_hash[65] = {0};
    char new_hash[65] = {0};
    hash_password(old_plain, old_hash);
    hash_password(new_plain, new_hash);

    // ── 서버로 비밀번호 변경 요청 전송 ──────────────────────
    struct AuthPacket req;
    memset(&req, 0, sizeof(req));
    req.type    = PKT_REQ_UPDATE_PW;
    req.user_pk = user_pk;
    // [수정] ERD: PW VARCHAR(64) → SHA-256 hex 64자 정확히 맞음
    strncpy(req.pwd_hash,     old_hash, sizeof(req.pwd_hash) - 1);
    strncpy(req.new_pwd_hash, new_hash, sizeof(req.new_pwd_hash) - 1);

    send(sock, (char *)&req, sizeof(req), 0);

    // ── 서버 응답 수신 ───────────────────────────────────────
    struct AuthResponse res;
    memset(&res, 0, sizeof(res));

    if (recv_all(sock, (char *)&res, sizeof(res)) > 0)
    {
        if (res.user_pk == 1)
            printf("  [Success] 비밀번호가 성공적으로 변경되었습니다.\n");
        else if (res.user_pk == 0)
            printf("  [Error] 현재 비밀번호가 일치하지 않습니다.\n");
        else
            printf("  [Error] 서버 오류로 변경에 실패했습니다.\n");
    }
    else
        printf("  [Error] 서버 응답이 없습니다.\n");

    PAUSE();
}

// ═══════════════════════════════════════════════════════════
// [추가] 개인 설정 — 이름 변경
//
// ERD: NAME VARCHAR(5) → 최대 5자 입력 제한
// ═══════════════════════════════════════════════════════════
static void menu_personal_change_name(int sock, int user_pk)
{
    CLEAR();
    printf("  ╔══════════════════════════════════════════╗\n");
    printf("  ║     ✏️   이름 변경                        ║\n");
    printf("  ╠══════════════════════════════════════════╣\n");
    // [수정] ERD: NAME VARCHAR(5) → 최대 5자임을 사용자에게 안내
    printf("  ║  새 이름을 입력하세요. (최대 5자)        ║\n");
    printf("  ║  (Enter만 누르면 취소됩니다)             ║\n");
    printf("  ╚══════════════════════════════════════════╝\n");
    printf("  새 이름: ");

    // [수정] ERD: NAME VARCHAR(5) → 버퍼 6바이트 (널 포함)
    char new_name[6] = {0};
    if (fgets(new_name, sizeof(new_name), stdin) == NULL) return;

    size_t len = strlen(new_name);
    if (len > 0 && new_name[len - 1] == '\n') new_name[len - 1] = '\0';

    // 빈 입력이면 취소
    if (strlen(new_name) == 0)
    {
        // fgets가 버퍼를 꽉 채운 경우(5자 초과 입력) 나머지를 버퍼에서 제거
        FLUSH_STDIN();
        printf("  [System] 취소되었습니다.\n");
        PAUSE();
        return;
    }

    // [수정] ERD: NAME VARCHAR(5) → 5자 초과 시 거부 (fgets로 자동 제한되지만 명시적 검사)
    if (strlen(new_name) > 5)
    {
        FLUSH_STDIN();
        printf("  [Error] 이름은 최대 5자까지 입력 가능합니다. (ERD 제한)\n");
        PAUSE();
        return;
    }

    // 5자 초과 잔여 입력 버려야 하는 경우를 대비해 버퍼 정리
    FLUSH_STDIN();

    // ── 서버로 이름 변경 요청 전송 ──────────────────────────
    struct AuthPacket req;
    memset(&req, 0, sizeof(req));
    req.type    = PKT_REQ_UPDATE_NAME;
    req.user_pk = user_pk;
    strncpy(req.name, new_name, sizeof(req.name) - 1);

    send(sock, (char *)&req, sizeof(req), 0);

    // ── 서버 응답 수신 ───────────────────────────────────────
    struct AuthResponse res;
    memset(&res, 0, sizeof(res));

    if (recv_all(sock, (char *)&res, sizeof(res)) > 0)
    {
        if (res.user_pk == 1)
            printf("  [Success] 이름이 '%s'(으)로 변경되었습니다.\n", new_name);
        else
            printf("  [Error] 이름 변경에 실패했습니다. (서버 오류)\n");
    }
    else
        printf("  [Error] 서버 응답이 없습니다.\n");

    PAUSE();
}

// ═══════════════════════════════════════════════════════════
// [추가] 개인 설정 서브메뉴
// ═══════════════════════════════════════════════════════════
static void menu_personal_settings(int sock, int user_pk, const char *login_email)
{
    while (1)
    {
        CLEAR();
        printf("  ╔══════════════════════════════════════════╗\n");
        printf("  ║     👤  개인 설정                        ║\n");
        printf("  ╠══════════════════════════════════════════╣\n");
        printf("  ║  1. 서비스 확인 및 변경 (미구현)        ║\n");
        printf("  ║  2. 기본 이메일 설정                    ║\n");
        printf("  ║  3. 개인정보 변경 (비밀번호 / 이름)     ║\n");
        printf("  ║  0. 돌아가기                            ║\n");
        printf("  ╚══════════════════════════════════════════╝\n");
        printf("  선택: ");

        int ch;
        if (scanf("%d", &ch) != 1) { FLUSH_STDIN(); continue; }
        FLUSH_STDIN();

        if (ch == 0) { CLEAR(); return; }
        CLEAR();

        if (ch == 1)
        {
            printf("  [System] 서비스 확인 및 변경 기능은 준비 중입니다.\n");
            PAUSE();
        }
        else if (ch == 2)
        {
            menu_personal_default_email(sock, user_pk, login_email);
        }
        else if (ch == 3)
        {
            while (1)
            {
                CLEAR();
                printf("  ╔══════════════════════════════════════════╗\n");
                printf("  ║     ✏️   개인정보 변경                    ║\n");
                printf("  ╠══════════════════════════════════════════╣\n");
                printf("  ║  1. 비밀번호 변경                       ║\n");
                printf("  ║  2. 이름 변경 (최대 5자)                ║\n");  // [수정] ERD VARCHAR(5) 안내
                printf("  ║  0. 돌아가기                            ║\n");
                printf("  ╚══════════════════════════════════════════╝\n");
                printf("  선택: ");

                int sub;
                if (scanf("%d", &sub) != 1) { FLUSH_STDIN(); continue; }
                FLUSH_STDIN();

                if (sub == 0) { CLEAR(); break; }
                CLEAR();

                if (sub == 1)
                    menu_personal_change_pw(sock, user_pk);
                else if (sub == 2)
                    menu_personal_change_name(sock, user_pk);
                else
                {
                    printf("  [Error] 0~2 중 선택하세요.\n");
                    PAUSE();
                }
            }
        }
        else
        {
            printf("  [Error] 0~3 중 선택하세요.\n");
            PAUSE();
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  서브메뉴: ⚙️ 설정
// ═══════════════════════════════════════════════════════════
void menu_settings(int sock, int user_pk, const char *email, int *should_logout)
{
    while (1)
    {
        CLEAR();
        printf("  ╔══════════════════════════════════╗\n");
        printf("  ║     ⚙️   설정 (Settings)          ║\n");
        printf("  ╠══════════════════════════════════╣\n");
        printf("  ║  1. 개인 설정                    ║\n");
        printf("  ║  2. 메시지 설정 (미구현)         ║\n");
        printf("  ║  3. 파일 설정 (미구현)           ║\n");
        printf("  ║  4. 내 폴더 삭제 (계정 탈퇴)     ║\n");
        printf("  ║  5. 로그아웃                     ║\n");
        printf("  ║  0. 돌아가기                     ║\n");
        printf("  ╚══════════════════════════════════╝\n");
        printf("  (%s)\n", email);
        printf("  선택: ");

        int ch;
        if (scanf("%d", &ch) != 1) { FLUSH_STDIN(); continue; }
        FLUSH_STDIN();

        if (ch == 0) { CLEAR(); return; }
        CLEAR();

        if (ch == 1)
            menu_personal_settings(sock, user_pk, email);  // [수정] 미구현 → 실제 호출
        else if (ch == 2 || ch == 3)
        {
            printf("  [System] 해당 기능은 준비 중입니다.\n");
            PAUSE();
        }
        else if (ch == 4)
        {
            printf("  [경고] 계정 탈퇴 시 모든 파일이 삭제됩니다.\n");
            printf("  [System] 폴더 삭제 (미구현)\n");
            PAUSE();
        }
        else if (ch == 5)
        {
            printf("  [System] 로그아웃 합니다.\n");
            *should_logout = 1;
            return;
        }
        else
        {
            printf("  [Error] 0~5 중 선택하세요.\n");
            PAUSE();
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  허브 메뉴 — 로그인 후 모든 기능의 진입점
// ═══════════════════════════════════════════════════════════
void menu_hub(int sock, int user_pk, const char *email)
{
    while (1)
    {
        CLEAR();
        int unread = msg_get_unread();

        printf("  ==================================================\n");
        printf("  ☁️  OUR CLOUD SERVER\n");
        printf("  Logged in: %s\n", email);
        printf("  ==================================================\n");
        if (unread > 0)
            printf("  [Status] 📧 새 메시지: %d개\n", unread);
        else
            printf("  [Status] 📧 새 메시지 없음\n");
        printf("  --------------------------------------------------\n\n");
        printf("  1. 📧  메시지 (Message)\n");
        printf("         보내기, 확인, 삭제\n\n");
        printf("  2. 📂  파일 (File)\n");
        printf("         저장(Upload), 불러오기(Download), 삭제\n\n");
        printf("  3. ⚙️   설정 (Settings)\n");
        printf("         개인/메시지/파일 설정, 로그아웃\n\n");
        printf("  4. ❌  나가기 (Exit)\n\n");
        printf("  --------------------------------------------------\n");
        printf("  선택: ");

        int ch;
        if (scanf("%d", &ch) != 1) { FLUSH_STDIN(); continue; }
        FLUSH_STDIN();

        if (ch == 1)
        {
            msg_run_menu();
            CLEAR();
        }
        else if (ch == 2)
            menu_file(sock, user_pk);
        else if (ch == 3)
        {
            int logout = 0;
            menu_settings(sock, user_pk, email, &logout);
            if (logout)
            {
                CLEAR();
                printf("  [System] 로그아웃 완료. 안녕히 가세요!\n\n");
                msg_cleanup();
                return;
            }
        }
        else if (ch == 4)
        {
            CLEAR();
            printf("  [System] 프로그램을 종료합니다. 안녕히 가세요!\n\n");
            msg_cleanup();
            return;
        }
        else
        {
            printf("  [Error] 1~4 중 선택하세요.\n");
            PAUSE();
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  main
// ═══════════════════════════════════════════════════════════
int main()
{
    const char *target_ip = "127.0.0.1";
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(9000);
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("[Error] 서버 연결 실패");
        return -1;
    }

    CLEAR();
    printf("  [System] 서버(%s) 접속 성공!\n\n", target_ip);

    int  user_pk = -1;
    // [수정] ERD: ID VARCHAR(25) → email 버퍼 26바이트면 충분하나 기존 64 유지 (로그인 외에도 사용)
    char email[64] = {0};
    char pw[32]    = {0};

    while (user_pk <= 0)
    {
        CLEAR();
        printf("  ╔══════════════════════════════════╗\n");
        printf("  ║      ☁️  OUR CLOUD SERVER         ║\n");
        printf("  ╠══════════════════════════════════╣\n");
        printf("  ║  1. 로그인                       ║\n");
        printf("  ║  2. 회원가입                     ║\n");
        printf("  ║  0. 종료                         ║\n");
        printf("  ╚══════════════════════════════════╝\n");
        printf("  선택: ");

        int choice;
        if (scanf("%d", &choice) != 1) { FLUSH_STDIN(); continue; }
        FLUSH_STDIN();

        CLEAR();
        if (choice == 0) { close(sock); return 0; }

        if (choice == 2)
        {
            printf("  ── 회원가입 ──────────────────────────\n");
            if (handle_email_auth(sock, email))
            {
                // [수정] ERD: NAME VARCHAR(5) → 최대 5자 입력
                char username[6] = {0};
                printf("  이름 (최대 5자): ");
                scanf("%5s", username);
                FLUSH_STDIN();
                printf("  비밀번호: ");
                scanf("%31s", pw);
                FLUSH_STDIN();
                int pk = request_auth(sock, PKT_REQ_REGISTER, email, pw, username);
                if (pk > 0)
                {
                    user_pk = pk;
                    printf("  [Success] 가입 성공! (ID: %d)\n", user_pk);
                }
                else
                    printf("  [Error] 이미 가입된 이메일이거나 서버 오류\n");
            }
            PAUSE();
        }
        else if (choice == 1)
        {
            printf("  ── 로그인 ────────────────────────────\n");
            // [수정] ERD: ID VARCHAR(25) → 최대 25자
            printf("  이메일: ");
            scanf("%25s", email);
            FLUSH_STDIN();
            printf("  비밀번호: ");
            scanf("%31s", pw);
            FLUSH_STDIN();
            user_pk = request_auth(sock, PKT_REQ_LOGIN, email, pw, "");
            if (user_pk > 0)
                printf("  [Success] 로그인 성공!\n");
            else
            {
                printf("  [Error] 이메일 또는 비밀번호가 틀렸습니다.\n");
                user_pk = -1;
            }
            PAUSE();
        }
    }

    CLEAR();
    if (msg_init(user_pk, email) == 0)
        printf("  [System] 메시지 서버 연결 성공!\n");
    else
        printf("  [System] 메시지 서버 연결 실패 (메시지 기능 비활성화)\n");

    menu_hub(sock, user_pk, email);

    close(sock);
    return 0;
}
