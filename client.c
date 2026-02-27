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

// ANSI 화면 클리어 + 커서 맨 위
#define CLEAR()                  \
    do                           \
    {                            \
        printf("\033[2J\033[H"); \
        fflush(stdout);          \
    } while (0)

// scanf 후 stdin 버퍼에 남은 개행/문자 제거 (서브메뉴 오입력 원천 차단)
#define FLUSH_STDIN()                                 \
    do                                                \
    {                                                 \
        int _c;                                       \
        while ((_c = getchar()) != '\n' && _c != EOF) \
            ;                                         \
    } while (0)

// 결과 출력 후 Enter 대기
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
void delete_folder(int sock, int user_pk)
{
    struct FilePacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = 45;
    pkt.user_pk = user_pk;
    send(sock, (char *)&pkt, sizeof(pkt), 0);
    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0 && pkt.type == 46)
    {
        if (pkt.file_pk == 1)
            printf("  [Success] 폴더 철거 완료.\n");
        else
            printf("  [Error] 삭제 거부! 폴더 안에 파일이 남아있습니다.\n");
    }
}

void check_storage_quota(int sock, int user_pk)
{
    struct FilePacket pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = 310;
    pkt.user_pk = user_pk;
    send(sock, (char *)&pkt, sizeof(pkt), 0);
    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0 && pkt.type == 311)
    {
        long max_mb = pkt.file_size / (1024 * 1024);
        long remain_mb = pkt.offset / (1024 * 1024);
        printf("\n  [ 총 제공: %ld MB | 사용 중: %ld MB | 남은 용량: %ld MB ]\n", max_mb, max_mb - remain_mb, remain_mb);
    }
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

    // 삭제 요청 패킷 세팅
    pkt.type = PKT_REQ_DELETE; // Protocol.hpp에 정의되어 있어야 함
    pkt.user_pk = user_pk;
    pkt.file_pk = file_pk;

    printf("  [System] 서버에 파일 삭제를 요청합니다...\n");
    send(sock, (char *)&pkt, sizeof(pkt), 0);

    // 서버의 응답 대기
    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0)
    {
        if (pkt.type == PKT_RES_DELETE && pkt.file_pk == 1)
        {
            printf("  [Success] 파일(PK: %d)이 성공적으로 삭제되었습니다.\n", file_pk);
            printf("  [System] 남은 저장소 용량이 복구되었습니다!\n");
        }
        else
        {
            printf("  [Error] 파일 삭제 실패. (권한이 없거나 이미 삭제된 파일입니다)\n");
        }
    }
    else
    {
        printf("  [Error] 서버 응답이 없습니다.\n");
    }
}

// ═══════════════════════════════════════════════════════════
//  인증
// ═══════════════════════════════════════════════════════════
int handle_email_auth(int sock, char *out_email)
{
    char code[16];
    struct FilePacket pkt;

    printf("  이메일 주소: ");
    scanf("%63s", out_email);
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
    pkt->type = PKT_REQ_UPLOAD_START;
    pkt->user_pk = user_pk;
    pkt->file_size = fsize;

    // 💡 [핵심 수정] 경로에서 순수 파일명만 추출하여 패킷에 담습니다.
    const char *basename = strrchr(filename, '/'); // 리눅스 경로 슬래시 찾기
    if (basename)
    {
        basename++; // 슬래시('/') 다음 글자부터 진짜 파일명
    }
    else
    {
        basename = filename; // 슬래시가 없으면 전체가 파일명
    }

    // 안전하게 복사
    strncpy(pkt->data, basename, sizeof(pkt->data) - 1);
    pkt->data[sizeof(pkt->data) - 1] = '\0';

    send(sock, (char *)pkt, sizeof(*pkt), 0);

    // 서버로부터 UPLOAD_START 응답 (file_pk) 받기
    if (recv_all(sock, (char *)pkt, sizeof(*pkt)) <= 0 || pkt->type != PKT_RES_UPLOAD_START)
    {
        printf("  [Error] 업로드 시작 실패\n");
        fclose(fp);
        free(pkt);
        return -1;
    }

    file_pk = pkt->file_pk;
    if (file_pk < 0)
    {
        printf("  [Error] 서버 거부 (용량 초과 또는 DB 오류)\n");
        fclose(fp);
        free(pkt);
        return -1;
    }

    // 파일을 8KB씩 나눠서 전송
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

    // 업로드 완료 신호 전송
    memset(pkt, 0, sizeof(*pkt));
    pkt->type = PKT_REQ_UPLOAD_END;
    pkt->user_pk = user_pk;
    pkt->file_pk = file_pk;
    send(sock, (char *)pkt, sizeof(*pkt), 0);

    // 최종 응답 대기
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
    pkt.type = 40; // PKT_REQ_LIST
    pkt.user_pk = user_pk;

    if (send(sock, (char *)&pkt, sizeof(pkt), 0) < 0)
        return;

    printf("\n  [목록 조회 중...]\n");
    // 헤더 출력은 루프 밖에서 한 번만
    printf("  %-8s | %-20s | %-10s\n", "PK", "파일명", "크기(Byte)");
    printf("  --------------------------------------------\n");

    while (1)
    {
        // 서버로부터 패킷 하나를 통째로 읽음
        if (recv_all(sock, (char *)&pkt, sizeof(pkt)) <= 0)
            break;

        // ★ 서버가 "목록 전송 끝" 신호(42)를 보내면 루프 탈출
        if (pkt.type == 42)
        {
            break;
        }

        // 목록 데이터(41)인 경우에만 출력
        if (pkt.type == 41)
        {
            printf("  %s\n", pkt.data);
        }
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
void request_upgrade_grade(int sock, int user_pk, const char *target_grade)
{
    // 💡 1. struct 키워드 추가 및 C언어 표준 방식(memset)으로 초기화
    struct FilePacket req;
    memset(&req, 0, sizeof(req));

    req.type = PKT_REQ_UPGRADE_GRADE;
    req.user_pk = user_pk;

    strncpy(req.fileName, target_grade, sizeof(req.fileName) - 1);

    // 💡 2. sizeof 연산자 안에도 struct 명시
    if (send(sock, (char *)&req, sizeof(struct FilePacket), 0) < 0)
    {
        printf("  [Error] 서버로 등급 변경 요청을 보내지 못했습니다.\n");
        return;
    }

    // 💡 3. 응답 받을 때도 struct 명시 및 초기화
    struct FilePacket res;
    memset(&res, 0, sizeof(res));

    if (recv(sock, (char *)&res, sizeof(struct FilePacket), 0) > 0)
    {
        if (res.type == PKT_RES_UPGRADE_GRADE)
        {
            // 서버에서 성공 시 file_pk에 1을 담아 보내도록 설계했습니다.
            if (res.file_pk == 1)
            {
                printf("  [System] 성공적으로 '%s'(으)로 등급이 변경되었습니다!\n", target_grade);
                printf("  [System] 메인 메뉴의 '남은 용량 확인'에서 늘어난 용량을 확인해보세요.\n");
            }
            else
            {
                printf("  [Error] 등급 변경 실패 (DB 업데이트 오류)\n");
            }
        }
        else
        {
            printf("  [Error] 등급 변경 실패 (서버 응답 오류)\n");
        }
    }
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
        {
            CLEAR();
            return;
        }

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
            printf("  [System] 최근 파일 목록 (최대 20개)\n");
            request_file_list(sock, user_pk); // 💡 다운로드 전 목록 출력

            int fpk;
            char fname[256], spath[512];
            printf("\n  다운로드할 파일 PK (취소: 0): ");
            scanf("%d", &fpk);
            FLUSH_STDIN();
            if (fpk == 0)
                continue;

            printf("  저장할 이름 (경로 제외): ");
            scanf("%255s", fname);
            FLUSH_STDIN();
            get_default_download_path(fname, spath);
            download_file(sock, user_pk, fpk, spath, fname);
            PAUSE();
        }
        else if (ch == 4)
        {
            printf("  [System] 내 파일 목록\n");
            request_file_list(sock, user_pk); // 💡 삭제 전 목록 출력

            int dpk;
            printf("\n  삭제할 파일 PK (취소: 0): ");
            scanf("%d", &dpk);
            FLUSH_STDIN();
            if (dpk != 0)
                delete_file(sock, user_pk, dpk);
            PAUSE();
        }
        else if (ch == 5)
        {
            check_storage_quota(sock, user_pk);
            PAUSE();
        }
        else
        {
            printf("  [Error] 0~5 중 선택하세요.\n");
            PAUSE();
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  서브메뉴: ⚙️ 설정
// ═══════════════════════════════════════════════════════════
void menu_settings(int sock, int user_pk, const char *email, int *should_logout)
{
    (void)sock;
    (void)user_pk;
    while (1)
    {
        CLEAR();
        printf("  ╔══════════════════════════════════╗\n");
        printf("  ║     ⚙️   설정 (Settings)         ║\n");
        printf("  ╠══════════════════════════════════╣\n");
        printf("  ║  1. 개인 설정 (미구현)           ║\n");
        printf("  ║  2. 메시지 설정 (미구현)         ║\n");
        printf("  ║  3. 등급 설정 (용량 확장)        ║\n");
        printf("  ║  4. 내 폴더 삭제 (계정 탈퇴)     ║\n");
        printf("  ║  5. 로그아웃                     ║\n");
        printf("  ║  0. 돌아가기                     ║\n");
        printf("  ╚══════════════════════════════════╝\n");
        printf("  (%s)\n", email);
        printf("  선택: ");

        int ch;
        if (ch == 1)
        {
            printf("  ╔══════════════════════════════════╗\n");
            printf("  ║       개인 설정 (Personal)       ║\n");
            printf("  ╠══════════════════════════════════╣\n");
            printf("  ║  1. 이름 변경                    ║\n");
            printf("  ║  2. 비밀번호 변경                ║\n");
            printf("  ║  3. 이메일(ID) 변경              ║\n");
            printf("  ║  0. 취소                         ║\n");
            printf("  ╚══════════════════════════════════╝\n");
            printf("  선택: ");

            int sub_ch;
            if (scanf("%d", &sub_ch) == 1)
            {
                FLUSH_STDIN();
                char input_data[65] = {0};

                if (sub_ch == 1)
                {
                    printf("  새로운 이름 입력: ");
                    scanf("%64s", input_data);
                    FLUSH_STDIN();
                    request_user_settings(sock, user_pk, 1, input_data);
                }
                else if (sub_ch == 2)
                {
                    char plain_pw[32];
                    printf("  새로운 비밀번호 입력: ");
                    scanf("%31s", plain_pw);
                    FLUSH_STDIN();
                    // 💡 [핵심] 비밀번호는 반드시 클라이언트에서 해시화 후 전송!
                    hash_password(plain_pw, input_data);
                    request_user_settings(sock, user_pk, 2, input_data);
                }
                else if (sub_ch == 3)
                {
                    char new_email[64] = {0};
                    printf("  [System] 새로운 이메일로 인증을 진행합니다.\n");

                    // 💡 [핵심] 기존에 만들어둔 회원가입용 이메일 인증 함수를 재사용!
                    if (handle_email_auth(sock, new_email))
                    {
                        // 인증(및 중복검사)에 통과했을 때만 서버에 변경 요청을 보냄
                        request_user_settings(sock, user_pk, 3, new_email);

                        // 💡 [UX/보안 고려] 로그인 ID가 바뀌었으므로 로그아웃 시키는 것이 안전합니다.
                        printf("  [System] 이메일(ID)이 변경되었습니다. 새 이메일로 다시 로그인해주세요.\n");
                        *should_logout = 1;
                        return; // 메뉴 루프 탈출
                    }
                    else
                    {
                        printf("  [System] 인증에 실패하여 이메일 변경이 취소되었습니다.\n");
                    }
                }
                else if (sub_ch == 0)
                {
                    printf("  [System] 취소했습니다.\n");
                }
            }
            else
            {
                FLUSH_STDIN();
            }
            PAUSE();
        }
        else if (ch == 2)
        {
            printf("  [System] 메시지 설정은 준비 중입니다.\n");
            PAUSE();
        }
        FLUSH_STDIN();

        if (ch == 0)
        {
            CLEAR();
            return;
        }

        CLEAR();
        // 💡 기존 3번(등급 설정)을 준비 중 목록에서 제외했습니다.
        if (ch == 1 || ch == 2)
        {
            printf("  [System] 해당 기능은 준비 중입니다.\n");
            PAUSE();
        }
        else if (ch == 3) // 💡 3번 등급 설정 로직 추가
        {
            printf("  ╔══════════════════════════════════╗\n");
            printf("  ║       등급 설정 (Storage)        ║\n");
            printf("  ╠══════════════════════════════════╣\n");
            printf("  ║  1. 일반     (100MB)             ║\n");
            printf("  ║  2. 비지니스 (200MB)             ║\n");
            printf("  ║  3. VIP      (500MB)             ║\n");
            printf("  ║  4. VVIP     (1GB)               ║\n");
            printf("  ║  0. 취소                         ║\n");
            printf("  ╚══════════════════════════════════╝\n");
            printf("  변경할 등급 선택: ");

            int grade_ch;
            if (scanf("%d", &grade_ch) == 1)
            {
                FLUSH_STDIN();
                char target_grade[32] = "";

                if (grade_ch == 1)
                    strcpy(target_grade, "일반");
                else if (grade_ch == 2)
                    strcpy(target_grade, "비지니스");
                else if (grade_ch == 3)
                    strcpy(target_grade, "VIP");
                else if (grade_ch == 4)
                    strcpy(target_grade, "VVIP");
                else if (grade_ch == 0)
                {
                    printf("  [System] 등급 변경을 취소합니다.\n");
                }
                else
                {
                    printf("  [Error] 올바른 번호를 선택해주세요.\n");
                }

                // 올바른 등급을 선택했을 경우 서버로 변경 요청
                if (grade_ch >= 1 && grade_ch <= 4)
                {
                    // 💡 서버에 등급 변경 패킷을 보내는 함수 호출
                    request_upgrade_grade(sock, user_pk, target_grade);
                }
            }
            else
            {
                FLUSH_STDIN();
                printf("  [Error] 숫자를 입력해주세요.\n");
            }
            PAUSE();
        }
        else if (ch == 4)
        {
            printf("  [경고] 빈 폴더만 철거 가능합니다. 지우시겠습니까? (1:예): ");
            int confirm;
            if (scanf("%d", &confirm) == 1 && confirm == 1)
            {
                FLUSH_STDIN();
                delete_folder(sock, user_pk);
            }
            else
            {
                FLUSH_STDIN();
            }
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
//  메시지/파일/설정 으로 완전히 분기 → 번호 충돌 없음
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
        if (scanf("%d", &ch) != 1)
        {
            FLUSH_STDIN();
            continue;
        }
        FLUSH_STDIN(); // ← 버퍼 완전 비우기 → 서브메뉴 오입력 원천 차단

        if (ch == 1)
        {
            msg_run_menu(); // MsgClientLogic.hpp → menu_message() 호출
            CLEAR();
        }
        else if (ch == 2)
        {
            menu_file(sock, user_pk);
        }
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
    addr.sin_port = htons(9000);
    inet_pton(AF_INET, target_ip, &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("[Error] 서버 연결 실패");
        return -1;
    }

    CLEAR();
    printf("  [System] 서버(%s) 접속 성공!\n\n", target_ip);

    int user_pk = -1;
    char email[64] = {0};
    char pw[32] = {0};

    // ── 인증 루프 ────────────────────────────────────────────
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
        if (scanf("%d", &choice) != 1)
        {
            FLUSH_STDIN();
            continue;
        }
        FLUSH_STDIN();

        CLEAR();
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
                char username[10] = {0};
                printf("  이름: ");
                scanf("%9s", username);
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
                {
                    printf("  [Error] 이미 가입된 이메일이거나 서버 오류\n");
                }
            }
            PAUSE();
        }
        else if (choice == 1)
        {
            printf("  ── 로그인 ────────────────────────────\n");
            printf("  이메일: ");
            scanf("%63s", email);
            FLUSH_STDIN();
            printf("  비밀번호: ");
            scanf("%31s", pw);
            FLUSH_STDIN();
            user_pk = request_auth(sock, PKT_REQ_LOGIN, email, pw, "");
            if (user_pk > 0)
            {
                printf("  [Success] 로그인 성공!\n");
            }
            else
            {
                printf("  [Error] 이메일 또는 비밀번호가 틀렸습니다.\n");
                user_pk = -1;
            }
            PAUSE();
        }
    }

    // ── 메시지 서버 연결 ─────────────────────────────────────
    CLEAR();
    if (msg_init(user_pk, email) == 0) // 💡 email 인자 추가
        printf("  [System] 메시지 서버 연결 성공!\n");
    else
        printf("  [System] 메시지 서버 연결 실패 (메시지 기능 비활성화)\n");

    // ── 허브 메뉴 진입 ───────────────────────────────────────
    menu_hub(sock, user_pk, email);

    close(sock);
    return 0;
}