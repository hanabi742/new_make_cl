#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <termios.h>

// 💡 통신 규격과 메시지 시스템 헤더만 포함합니다. (서버 전용 DB 헤더는 제외)
#include "Protocol.hpp"
#include "msg_client.h"

#define OPENSSL_API_COMPAT 0x30000000L

// ═══════════════════════════════════════════════════════════
//  [1] 전역 변수 및 공통 유틸 매크로
// ═══════════════════════════════════════════════════════════

// 💡 사용자 지정 다운로드 경로를 저장하는 전역 변수
char g_download_path[131] = "";

// 화면 클리어 (리눅스 ANSI 시퀀스)
#define CLEAR()                  \
    do                           \
    {                            \
        printf("\033[2J\033[H"); \
        fflush(stdout);          \
    } while (0)

// 입력 버퍼 비우기 (메뉴에서 오작동 방지)
#define FLUSH_STDIN()                                 \
    do                                                \
    {                                                 \
        int _c;                                       \
        while ((_c = getchar()) != '\n' && _c != EOF) \
            ;                                         \
    } while (0)

// 결과 출력 후 엔터 대기
#define PAUSE()                        \
    do                                 \
    {                                  \
        printf("\n  [Enter] 계속..."); \
        FLUSH_STDIN();                 \
    } while (0)

// 네트워크 데이터 수신 보장 함수 (지정한 size만큼 모두 받을 때까지 대기)
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
//  [2] 보안 및 유틸리티 함수
// ═══════════════════════════════════════════════════════════

// 파일 다운로드 경로 설정 (사용자 지정 경로가 있으면 우선 적용)
void get_custom_download_path(const char *filename, char *out_path, const char *saved_path)
{
    if (saved_path != NULL && strlen(saved_path) > 0)
    {
        sprintf(out_path, "%s/%s", saved_path, filename);
    }
    else
    {
        const char *home = getenv("HOME");
        if (!home)
            home = getenv("USERPROFILE");
        if (home)
            sprintf(out_path, "%s/Downloads/%s", home, filename);
        else
            strcpy(out_path, filename);
    }
}

// SHA-256 단방향 암호화 (비밀번호 보호)
void hash_password(const char *plain, char *out)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, plain, strlen(plain));
    SHA256_Final(hash, &ctx);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(out + i * 2, "%02x", hash[i]);
    }
    out[64] = '\0';
}

// 콘솔에서 비밀번호 입력 시 '*' 기호로 마스킹 처리
void input_password(const char *prompt, char *buf, int max_len)
{
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO | ICANON); // 에코 기능 끄기
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    printf("%s", prompt);
    fflush(stdout);

    int i = 0, c;
    while ((c = getchar()) != '\n' && c != EOF && i < max_len - 1)
    {
        if (c == 127 || c == '\b')
        { // 백스페이스 처리
            if (i > 0)
            {
                i--;
                printf("\b \b");
                fflush(stdout);
            }
        }
        else
        {
            buf[i++] = (char)c;
            printf("*");
            fflush(stdout);
        }
    }
    buf[i] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // 에코 기능 복구
    printf("\n");
}

// 비밀번호 유효성 검사 (영문+숫자 혼합, 5~15자)
int validate_password(const char *pw)
{
    int len = (int)strlen(pw);
    if (len < 5 || len > 15)
    {
        printf("  [Error] 비밀번호는 5~15자여야 합니다.\n");
        return 0;
    }
    int has_alpha = 0, has_digit = 0;
    for (int i = 0; i < len; i++)
    {
        if ((pw[i] >= 'a' && pw[i] <= 'z') || (pw[i] >= 'A' && pw[i] <= 'Z'))
            has_alpha = 1;
        else if (pw[i] >= '0' && pw[i] <= '9')
            has_digit = 1;
        else
        {
            printf("  [Error] 영문자와 숫자만 사용할 수 있습니다.\n");
            return 0;
        }
    }
    if (!has_alpha || !has_digit)
    {
        printf("  [Error] 영문자와 숫자를 반드시 혼합해야 합니다.\n");
        return 0;
    }
    return 1;
}

// ═══════════════════════════════════════════════════════════
//  [3] 인증 관련 함수 (이메일 인증, 회원가입, 로그인)
// ═══════════════════════════════════════════════════════════

// 이메일 인증 번호 요청 및 검증
int handle_email_auth(int sock, char *out_email)
{
    char code[16];
    struct FilePacket pkt;
    printf("  이메일 주소: ");
    scanf("%63s", out_email);
    FLUSH_STDIN();

    // 1. 서버로 인증 메일 발송 요청
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = PKT_REQ_EMAIL_AUTH;
    strncpy(pkt.data, out_email, sizeof(pkt.data) - 1);
    send(sock, (char *)&pkt, sizeof(pkt), 0);

    printf("  [System] 인증 메일 발송 중...\n");
    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0 && pkt.file_pk == -1)
    {
        printf("  [Error] 발송 실패 (이미 가입된 이메일이거나 서버 오류)\n");
        return 0;
    }

    // 2. 인증번호 입력 및 서버 검증
    printf("  [Success] 메일 발송 완료. 6자리 인증번호: ");
    scanf("%15s", code);
    FLUSH_STDIN();

    memset(&pkt, 0, sizeof(pkt));
    pkt.type = PKT_REQ_EMAIL_VERIFY;
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

// 서버에 로그인 또는 회원가입 요청
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
    // 💡 sizeof(res)를 사용하여 Protocol.hpp에 정의된 141바이트 전체를 다 읽어야 합니다.
    if (recv_all(sock, (char *)&res, sizeof(res)) <= 0)
        return -1;

    // 💡 로그인 성공 시, 서버가 보내준 유저 고유의 다운로드 경로를 전역 변수에 저장
    if (res.user_pk > 0 && type == PKT_REQ_LOGIN)
    {
        strncpy(g_download_path, res.download_path, sizeof(g_download_path) - 1);
    }
    return res.user_pk;
}

// ═══════════════════════════════════════════════════════════
//  [4] 파일 클라우드 시스템 (업로드, 다운로드, 관리)
// ═══════════════════════════════════════════════════════════

void check_storage_quota(int sock, int user_pk)
{
    struct FilePacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = PKT_REQ_STORAGE_INFO;
    pkt.user_pk = user_pk;
    send(sock, (char *)&pkt, sizeof(pkt), 0);

    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0 && pkt.type == PKT_RES_STORAGE_INFO)
    {
        // [수정] long long 타입으로 캐스팅하고 %lld 포맷을 사용하여 대용량 안전성 확보
        long long max_mb = (long long)pkt.file_size / (1024 * 1024);
        long long remain_mb = (long long)pkt.offset / (1024 * 1024);

        printf("\n  [ ☁️ 총 제공: %lld MB | 사용 중: %lld MB | 남은 용량: %lld MB ]\n",
               max_mb, max_mb - remain_mb, remain_mb);
    }
}

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

    // 1. 업로드 시작 요청
    memset(pkt, 0, sizeof(*pkt));
    pkt->type = PKT_REQ_UPLOAD_START;
    pkt->user_pk = user_pk;
    pkt->file_size = fsize;

    // 경로에서 순수 파일명만 추출
    const char *basename = strrchr(filename, '/');
    if (basename)
        basename++;
    else
        basename = filename;
    strncpy(pkt->data, basename, sizeof(pkt->data) - 1);

    send(sock, (char *)pkt, sizeof(*pkt), 0);
    if (recv_all(sock, (char *)pkt, sizeof(*pkt)) <= 0 || pkt->type != PKT_RES_UPLOAD_START)
    {
        printf("  [Error] 업로드 시작 실패 (서버 응답 없음)\n");
        fclose(fp);
        free(pkt);
        return -1;
    }

    file_pk = pkt->file_pk; // 서버가 발급한 진짜 PK
    if (file_pk < 0)
    {
        printf("  [Error] 서버 거부 (용량 초과 또는 DB 오류)\n");
        fclose(fp);
        free(pkt);
        return -1;
    }

    // 2. 8KB 조각 단위 전송
    long offset = 0;
    while (offset < fsize)
    {
        memset(pkt, 0, sizeof(*pkt));
        pkt->type = PKT_REQ_UPLOAD_CHUNK;
        pkt->user_pk = user_pk;
        pkt->file_pk = file_pk;
        pkt->offset = offset;
        int read_bytes = fread(pkt->data, 1, sizeof(pkt->data), fp);
        if (read_bytes <= 0)
            break;
        pkt->data_size = read_bytes;
        send(sock, (char *)pkt, sizeof(*pkt), 0);
        offset += read_bytes;
        printf("\r  [%ld / %ld bytes]", offset, fsize);
        fflush(stdout);
    }
    printf("\n");

    // 3. 전송 완료 패킷
    memset(pkt, 0, sizeof(*pkt));
    pkt->type = PKT_REQ_UPLOAD_END;
    pkt->user_pk = user_pk;
    pkt->file_pk = file_pk;
    send(sock, (char *)pkt, sizeof(*pkt), 0);

    if (recv_all(sock, (char *)pkt, sizeof(*pkt)) > 0 && pkt->type == PKT_RES_UPLOAD_END && pkt->file_pk > 0)
        printf("  [Success] 업로드 완료! (PK: %d)\n", file_pk);
    else
        printf("  [Error] 업로드 최종 확인 실패\n");

    fclose(fp);
    free(pkt);
    return file_pk;
}

void request_file_list(int sock, int user_pk)
{
    struct FilePacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = PKT_REQ_LIST;
    pkt.user_pk = user_pk;
    if (send(sock, (char *)&pkt, sizeof(pkt), 0) < 0)
        return;

    printf("\n  [목록 조회 중...]\n  %-8s | %-20s | %-10s\n  --------------------------------------------\n", "PK", "파일명", "크기(Byte)");
    while (1)
    {
        if (recv_all(sock, (char *)&pkt, sizeof(pkt)) <= 0 || pkt.type == PKT_RES_LIST_END)
            break;
        if (pkt.type == PKT_RES_LIST)
            printf("  %s\n", pkt.data);
    }
    printf("  --------------------------------------------\n");
}

void download_file(int sock, int user_pk, int file_pk, const char *save_path, const char *filename)
{
    struct FilePacket *pkt = (struct FilePacket *)malloc(sizeof(struct FilePacket));
    memset(pkt, 0, sizeof(*pkt));
    pkt->type = PKT_REQ_DOWNLOAD_START;
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
        if (!fp)
        {
            free(pkt);
            return;
        }
    } // 백업 경로로 시도

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

void delete_file(int sock, int user_pk, int file_pk)
{
    struct FilePacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = PKT_REQ_DELETE;
    pkt.user_pk = user_pk;
    pkt.file_pk = file_pk;
    printf("  [System] 서버에 파일 삭제를 요청합니다...\n");
    send(sock, (char *)&pkt, sizeof(pkt), 0);

    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0)
    {
        if (pkt.type == PKT_RES_DELETE && pkt.file_pk == 1)
            printf("  [Success] 파일(PK: %d)이 삭제되었습니다. (용량 복구됨)\n", file_pk);
        else
            printf("  [Error] 파일 삭제 실패.\n");
    }
}

void delete_folder(int sock, int user_pk)
{
    struct FilePacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = PKT_REQ_DELETE_FOLDER;
    pkt.user_pk = user_pk;
    send(sock, (char *)&pkt, sizeof(pkt), 0);
    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0 && pkt.type == PKT_RES_DELETE_FOLDER)
    {
        if (pkt.file_pk == 1)
            printf("  [Success] 폴더 철거 완료.\n");
        else
            printf("  [Error] 삭제 거부! 폴더 안에 파일이 남아있습니다.\n");
    }
}

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
        printf("  ║  5. 남은 용량 확인               ║\n");
        printf("  ║  0. 돌아가기                     ║\n");
        printf("  ╚══════════════════════════════════╝\n");
        printf("  선택: ");

        int ch;
        if (scanf("%d", &ch) != 1)
        {
            FLUSH_STDIN();
            continue;
        }
        FLUSH_STDIN();
        if (ch == 0)
            return;

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
            request_file_list(sock, user_pk);
            int fpk;
            char fname[256], spath[512];
            printf("\n  다운로드할 파일 PK (취소: 0): ");
            scanf("%d", &fpk);
            FLUSH_STDIN();
            if (fpk > 0)
            {
                printf("  저장할 이름 (경로 제외): ");
                scanf("%255s", fname);
                FLUSH_STDIN();
                get_custom_download_path(fname, spath, g_download_path); // 💡 커스텀 경로 연동
                download_file(sock, user_pk, fpk, spath, fname);
            }
            PAUSE();
        }
        else if (ch == 3)
        {
            request_file_list(sock, user_pk);
            PAUSE();
        }
        else if (ch == 4)
        {
            request_file_list(sock, user_pk);
            int dpk;
            printf("\n  삭제할 파일 PK (취소: 0): ");
            scanf("%d", &dpk);
            FLUSH_STDIN();
            if (dpk > 0)
                delete_file(sock, user_pk, dpk);
            PAUSE();
        }
        else if (ch == 5)
        {
            check_storage_quota(sock, user_pk);
            PAUSE();
        }
        else
            PAUSE();
    }
}

// ═══════════════════════════════════════════════════════════
//  [5] 🚫 블랙리스트 관리 메뉴 (유저 간 메시지 차단)
// ═══════════════════════════════════════════════════════════
void menu_blacklist(int sock, int user_pk)
{
    while (1)
    {
        CLEAR();
        printf("  ╔══════════════════════════════════╗\n");
        printf("  ║     🚫  블랙리스트 관리          ║\n");
        printf("  ╠══════════════════════════════════╣\n");
        printf("  ║  1. 유저 차단 추가               ║\n");
        printf("  ║  2. 차단 해제                    ║\n");
        printf("  ║  3. 차단 목록 보기               ║\n");
        printf("  ║  0. 돌아가기                     ║\n");
        printf("  ╚══════════════════════════════════╝\n");
        printf("  선택: ");

        int ch;
        if (scanf("%d", &ch) != 1)
        {
            FLUSH_STDIN();
            continue;
        }
        FLUSH_STDIN();
        if (ch == 0)
            return;

        CLEAR();
        if (ch == 1)
        {
            char target_email[128] = {0};
            printf("  차단할 상대방 이메일: ");
            scanf("%127s", target_email);
            FLUSH_STDIN();

            struct BlacklistReqPacket req = {500, user_pk, 0, ""};
            strncpy(req.target_email, target_email, 127);
            send(sock, (char *)&req, sizeof(req), 0);

            struct BlacklistResPacket res;
            memset(&res, 0, sizeof(res));
            if (recv_all(sock, (char *)&res, sizeof(res)) > 0)
            {
                if (res.result_code == 1)
                    printf("  [Success] '%s' 차단 완료!\n", target_email);
                else if (res.result_code == 0)
                    printf("  [Error] 존재하지 않는 이메일입니다.\n");
                else if (res.result_code == -1)
                    printf("  [Error] 자기 자신을 차단할 수 없습니다.\n");
                else if (res.result_code == -2)
                    printf("  [Error] 이미 차단된 사용자입니다.\n");
                else
                    printf("  [Error] 서버 오류 발생\n");
            }
            PAUSE();
        }
        else if (ch == 2 || ch == 3)
        {
            struct BlacklistReqPacket req = {504, user_pk, 0, ""};
            send(sock, (char *)&req, sizeof(req), 0);

            printf("  %-6s | %-30s | %-16s\n", "번호", "이메일", "차단일시");
            printf("  ----------------------------------------------------------\n");
            int has_item = 0;
            while (1)
            {
                struct BlacklistResPacket res;
                if (recv_all(sock, (char *)&res, sizeof(res)) <= 0 || res.type == 506)
                    break;
                if (res.type == 505)
                {
                    printf("  %-6d | %-30s | %-16s\n", res.blacklist_num, res.target_email, res.created_at);
                    has_item = 1;
                }
            }
            printf("  ----------------------------------------------------------\n");

            if (ch == 2 && has_item)
            {
                printf("  해제할 번호 (취소: 0): ");
                int b_num;
                scanf("%d", &b_num);
                FLUSH_STDIN();
                if (b_num > 0)
                {
                    struct BlacklistReqPacket d_req = {502, user_pk, b_num, ""};
                    send(sock, (char *)&d_req, sizeof(d_req), 0);
                    struct BlacklistResPacket d_res;
                    if (recv_all(sock, (char *)&d_res, sizeof(d_res)) > 0 && d_res.result_code == 1)
                        printf("  [Success] 차단 해제 완료!\n");
                    else
                        printf("  [Error] 해제 실패\n");
                }
            }
            else if (!has_item)
            {
                printf("  차단된 사용자가 없습니다.\n");
            }
            PAUSE();
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  [6] ⚙️ 개인 설정 메뉴
// ═══════════════════════════════════════════════════════════

void request_user_settings(int sock, int user_pk, int type, const char *new_data)
{
    struct UserSettingsPacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = PKT_REQ_USER_SETTINGS;
    pkt.user_pk = user_pk;
    pkt.setting_type = type;
    strncpy(pkt.new_data, new_data, sizeof(pkt.new_data) - 1);
    if (send(sock, (char *)&pkt, sizeof(pkt), 0) <= 0)
        return;

    struct FilePacket res;
    memset(&res, 0, sizeof(res));
    if (recv_all(sock, (char *)&res, sizeof(res)) > 0)
    {
        if (res.file_pk == 1)
            printf("  [Success] 변경 사항이 서버에 반영되었습니다.\n");
        else
            printf("  [Error] 변경 실패\n");
    }
}

void request_upgrade_grade(int sock, int user_pk, const char *target_grade)
{
    struct FilePacket req;
    memset(&req, 0, sizeof(req));
    req.type = PKT_REQ_UPGRADE_GRADE;
    req.user_pk = user_pk;
    strncpy(req.fileName, target_grade, sizeof(req.fileName) - 1);
    if (send(sock, (char *)&req, sizeof(struct FilePacket), 0) < 0)
        return;

    struct FilePacket res;
    memset(&res, 0, sizeof(res));
    if (recv(sock, (char *)&res, sizeof(struct FilePacket), 0) > 0)
    {
        if (res.type == PKT_RES_UPGRADE_GRADE && res.file_pk == 1)
            printf("  [System] 성공적으로 '%s'(으)로 등급 변경!\n", target_grade);
        else
            printf("  [Error] 등급 변경 실패\n");
    }
}

void menu_settings(int sock, int user_pk, const char *email, int *should_logout)
{
    while (1)
    {
        CLEAR();
        printf("  ╔══════════════════════════════════╗\n");
        printf("  ║     ⚙️   설정 (Settings)         ║\n");
        printf("  ╠══════════════════════════════════╣\n");
        printf("  ║  1. 개인 설정 (이름/비번/경로)   ║\n");
        printf("  ║  2. 메시지 설정 (미구현)         ║\n");
        printf("  ║  3. 등급 설정 (용량 확장)        ║\n");
        printf("  ║  4. 내 폴더 삭제 (계정 탈퇴)     ║\n");
        printf("  ║  5. 로그아웃                     ║\n");
        printf("  ║  0. 돌아가기                     ║\n");
        printf("  ╚══════════════════════════════════╝\n");
        printf("  (%s)\n  현재 다운로드 경로: %s\n  선택: ", email, (strlen(g_download_path) > 0 ? g_download_path : "기본값(Downloads)"));

        int ch;
        scanf("%d", &ch);
        FLUSH_STDIN();
        if (ch == 1)
        {
            CLEAR();
            printf("  ╔══════════════════════════════════╗\n");
            printf("  ║       개인 설정 (Personal)       ║\n");
            printf("  ╠══════════════════════════════════╣\n");
            printf("  ║  1. 이름 변경                    ║\n");
            printf("  ║  2. 비밀번호 변경                ║\n");
            printf("  ║  3. 이메일(ID) 변경              ║\n");
            printf("  ║  4. 다운로드 경로 변경           ║\n");
            printf("  ║  0. 취소                         ║\n");
            printf("  ╚══════════════════════════════════╝\n  선택: ");
            int sub_ch;
            if (scanf("%d", &sub_ch) == 1)
            {
                FLUSH_STDIN();
                char input_data[131] = {0};
                if (sub_ch == 1)
                {
                    printf("  새 이름: ");
                    scanf("%64s", input_data);
                    FLUSH_STDIN();
                    request_user_settings(sock, user_pk, 1, input_data);
                }
                else if (sub_ch == 2)
                {
                    char cur_pw[32], new_pw[32], cur_h[65], new_h[65], comb[131];
                    input_password("  현재 비밀번호: ", cur_pw, 32);
                    hash_password(cur_pw, cur_h);
                    do
                    {
                        input_password("  새 비밀번호 (영문+숫자 5~15자): ", new_pw, 32);
                    } while (!validate_password(new_pw));
                    hash_password(new_pw, new_h);
                    sprintf(comb, "%s|%s", cur_h, new_h);
                    request_user_settings(sock, user_pk, 2, comb);
                }
                else if (sub_ch == 3)
                {
                    char new_email[64] = {0};
                    if (handle_email_auth(sock, new_email))
                    {
                        request_user_settings(sock, user_pk, 3, new_email);
                        *should_logout = 1;
                        return;
                    }
                }
                else if (sub_ch == 4)
                {
                    printf("  새 다운로드 절대경로 (예:/home/user/dl): ");
                    scanf("%130s", input_data);
                    FLUSH_STDIN();
                    request_user_settings(sock, user_pk, 4, input_data);
                    strncpy(g_download_path, input_data, sizeof(g_download_path) - 1); // 변수 동기화
                }
            }
            PAUSE();
        }
        else if (ch == 3)
        {
            CLEAR();
            printf("  1. 일반(100MB)  2. 비지니스(200MB)  3. VIP(500MB)  4. VVIP(1GB)  0. 취소\n  선택: ");
            int g_ch;
            if (scanf("%d", &g_ch) == 1)
            {
                FLUSH_STDIN();
                const char *gr[] = {"", "일반", "비지니스", "VIP", "VVIP"};
                if (g_ch >= 1 && g_ch <= 4)
                {
                    // 1. 서버에 등급 업그레이드 요청
                    request_upgrade_grade(sock, user_pk, gr[g_ch]);

                    // 2. [추가] 업그레이드 직후 최신 남은 용량을 서버에서 다시 받아와 화면에 출력!
                    printf("\n  [System] 최신 용량 정보를 동기화합니다...\n");
                    check_storage_quota(sock, user_pk);
                }
            }
            PAUSE();
        }
        else if (ch == 4)
        {
            int confirm;
            printf("  [경고] 지우시겠습니까? (1:예): ");
            if (scanf("%d", &confirm) == 1 && confirm == 1)
            {
                FLUSH_STDIN();
                delete_folder(sock, user_pk);
            }
            PAUSE();
        }
        else if (ch == 5)
        {
            *should_logout = 1;
            return;
        }
        else if (ch == 0)
            return;
    }
}

// ═══════════════════════════════════════════════════════════
//  [7] 👑 최고 관리자 (PK: 1) 전용 메뉴
// ═══════════════════════════════════════════════════════════
bool check_admin(int user_pk) { return user_pk == 1; }

void request_admin_action(int sock, int admin_pk, int target_pk, int type, const char *message)
{
    AdminPacket pkt = {0};
    pkt.type = type;
    pkt.admin_pk = admin_pk;
    pkt.target_pk = target_pk;
    if (message != NULL)
        strncpy(pkt.data, message, sizeof(pkt.data) - 1);
    if (send(sock, (char *)&pkt, sizeof(AdminPacket), 0) <= 0)
        return;

    if (type == PKT_REQ_ADMIN_STATUS)
    {
        AdminPacket res = {0};
        if (recv_all(sock, (char *)&res, sizeof(AdminPacket)) > 0 && res.type == PKT_RES_ADMIN_STATUS)
        {
            long long used_bytes = 0, remain_bytes = 0;
            sscanf(res.data, "%lld|%lld", &used_bytes, &remain_bytes);
            printf("\n  [ ☁️ CLOUD SERVER STATUS ]\n");
            printf("  ▶ 현재 접속자 : %d 명\n", res.target_pk);
            printf("  ▶ 남은 용량   : %lld MB\n", remain_bytes / (1024 * 1024));
            printf("  --------------------------------------\n");
        }
    }
    else
    {
        printf("  [System] 서버로 관리자 명령이 전달되었습니다.\n");
    }
}

void admin_menu(int sock, int admin_pk)
{
    if (admin_pk != 1)
        return;
    int choice;
    while (1)
    {
        CLEAR();
        printf("  ===== 👑 MASTER ADMIN CONSOLE (PK: %d) =====\n", admin_pk);
        request_admin_action(sock, admin_pk, 0, PKT_REQ_ADMIN_STATUS, NULL);
        printf("\n  1. 전체 공지 발송 (DB 저장)\n  2. 강력 블랙리스트 (IP+PK 차단)\n  3. 시스템 전체 초기화\n  0. 나가기\n  선택: ");
        if (scanf("%d", &choice) != 1)
        {
            FLUSH_STDIN();
            continue;
        }
        FLUSH_STDIN();

        if (choice == 0)
            break;
        if (choice == 1)
        {
            char notice[256];
            printf("  공지 내용: ");
            fgets(notice, sizeof(notice), stdin);
            notice[strcspn(notice, "\n")] = 0;
            request_admin_action(sock, admin_pk, 0, PKT_REQ_ADMIN_NOTICE, notice);
        }
        else if (choice == 2)
        {
            int target;
            char ip[64] = "0.0.0.0";
            printf("  차단 PK: ");
            scanf("%d", &target);
            FLUSH_STDIN();
            printf("  차단 IP: ");
            scanf("%63s", ip);
            FLUSH_STDIN();
            request_admin_action(sock, admin_pk, target, PKT_REQ_ADMIN_BAN, ip);
        }
        else if (choice == 3)
        {
            char pw[65], hpw[65];
            input_password("  [위험] 관리자 비밀번호 입력: ", pw, 32);
            hash_password(pw, hpw);
            request_admin_action(sock, admin_pk, 0, PKT_REQ_ADMIN_RESET, hpw);
        }
        PAUSE();
    }
}

// ═══════════════════════════════════════════════════════════
//  [8] 메인 허브 메뉴 및 메인 루프
// ═══════════════════════════════════════════════════════════
void menu_hub(int sock, int user_pk, const char *email)
{
    while (1)
    {
        CLEAR();
        int unread = msg_get_unread(); // msg_client.h에서 제공
        printf("  ==================================================\n");
        printf("  ☁️  OUR CLOUD SERVER (Logged in: %s)\n", email);
        printf("  ==================================================\n");
        if (unread > 0)
            printf("  [Status] 📧 새 메시지: %d개\n", unread);
        else
            printf("  [Status] 📧 새 메시지 없음\n");
        printf("  --------------------------------------------------\n\n");
        printf("  1. 📧  메시지 (Message)\n");
        printf("  2. 📂  파일 (File)\n");
        printf("  3. ⚙️   설정 (Settings)\n");
        printf("  4. 🚫  블랙리스트 (Blacklist)\n");
        printf("  5. ❌  나가기 (Exit)\n\n");
        printf("  --------------------------------------------------\n  선택: ");

        int ch;
        if (scanf("%d", &ch) != 1)
        {
            FLUSH_STDIN();
            continue;
        }
        FLUSH_STDIN();

        if (ch == 1)
        {
            msg_run_menu();
            CLEAR();
        } // 메시지 서버용 UI 호출
        else if (ch == 2)
            menu_file(sock, user_pk);
        else if (ch == 3)
        {
            int logout = 0;
            menu_settings(sock, user_pk, email, &logout);
            if (logout)
            {
                msg_cleanup();
                return;
            }
        }
        else if (ch == 4)
            menu_blacklist(sock, user_pk);
        else if (ch == 5)
        {
            msg_cleanup();
            return;
        }
    }
}

int main(int argc, char *argv[])
{
    const char *target_ip = (argc >= 2) ? argv[1] : "127.0.0.1";
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {AF_INET, htons(9000)};
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("[Error] 서버 연결 실패");
        return -1;
    }

    struct ServerHandshakeHeader hand;
    recv_all(sock, (char *)&hand, sizeof(hand));

    int user_pk = -1;
    char email[64] = {0}, pw[32] = {0};

    while (user_pk <= 0)
    {
        CLEAR();
        printf("  ╔══════════════════════════════════╗\n");
        printf("  ║      ☁️  OUR CLOUD SERVER         ║\n");
        printf("  ╠══════════════════════════════════╣\n");
        printf("  ║  1. 로그인                       ║\n");
        printf("  ║  2. 회원가입                     ║\n");
        printf("  ║  0. 종료                         ║\n");
        printf("  ╚══════════════════════════════════╝\n  선택: ");
        int choice;
        if (scanf("%d", &choice) != 1)
        {
            FLUSH_STDIN();
            continue;
        }
        FLUSH_STDIN();

        if (choice == 0)
        {
            close(sock);
            return 0;
        }
        if (choice == 2)
        {
            printf("  ── 회원가입 ──────────────────────────\n");
            if (handle_email_auth(sock, email))
            {
                char name[10];
                printf("  이름: ");
                scanf("%9s", name);
                FLUSH_STDIN();
                do
                {
                    input_password("  비번 (영문+숫자 5~15자): ", pw, 32);
                } while (!validate_password(pw));
                user_pk = request_auth(sock, PKT_REQ_REGISTER, email, pw, name);
                if (user_pk > 0)
                    printf("  [Success] 가입 성공! (ID: %d)\n", user_pk);
            }
            PAUSE();
        }
        else if (choice == 1)
        {
            printf("  ── 로그인 ────────────────────────────\n  이메일: ");
            scanf("%63s", email);
            FLUSH_STDIN();
            input_password("  비번: ", pw, 32);
            user_pk = request_auth(sock, PKT_REQ_LOGIN, email, pw, "");

            if (user_pk > 0)
            {
                printf("  [Success] 로그인 성공!\n");
                if (check_admin(user_pk))
                {
                    printf("  [System] 최고 관리자입니다. 관리자 메뉴? (1:Yes/0:No): ");
                    int g;
                    scanf("%d", &g);
                    FLUSH_STDIN();
                    if (g == 1)
                        admin_menu(sock, user_pk);
                }
            }
            else
            {
                printf("  [Error] 이메일/비밀번호 오류 또는 차단됨\n");
                user_pk = -1;
            }
            PAUSE();
        }
    }

    // 9001번 메시지 서버 백그라운드 연결
    msg_init(user_pk, email);

    // 메인 시스템 진입
    menu_hub(sock, user_pk, email);

    close(sock);
    return 0;
}