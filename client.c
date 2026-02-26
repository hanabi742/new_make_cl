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
#define CLEAR()      do { printf("\033[2J\033[H"); fflush(stdout); } while(0)

// scanf 후 stdin 버퍼에 남은 개행/문자 제거 (서브메뉴 오입력 원천 차단)
#define FLUSH_STDIN() do { int _c; while ((_c = getchar()) != '\n' && _c != EOF); } while(0)

// 결과 출력 후 Enter 대기
#define PAUSE()      do { printf("\n  [Enter] 계속..."); FLUSH_STDIN(); } while(0)

// ═══════════════════════════════════════════════════════════
//  네트워크 헬퍼
// ═══════════════════════════════════════════════════════════
int recv_all(int sock, char *buf, int size)
{
    int total = 0;
    while (total < size) {
        int n = recv(sock, buf + total, size - total, 0);
        if (n <= 0) return n;
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
    if (!home) home = getenv("USERPROFILE");
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

// ═══════════════════════════════════════════════════════════
//  인증
// ═══════════════════════════════════════════════════════════
int handle_email_auth(int sock, char *out_email)
{
    char code[16];
    struct FilePacket pkt;

    printf("  이메일 주소: ");
    scanf("%63s", out_email); FLUSH_STDIN();

    memset(&pkt, 0, sizeof(pkt));
    pkt.type = 20;
    strncpy(pkt.data, out_email, sizeof(pkt.data) - 1);
    send(sock, (char *)&pkt, sizeof(pkt), 0);

    printf("  [System] 인증 메일 발송 중...\n");
    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0 && pkt.file_pk == -1) {
        printf("  [Error] 발송 실패 (이미 가입된 이메일이거나 서버 오류)\n");
        return 0;
    }

    printf("  [Success] 메일 발송 완료. 6자리 인증번호: ");
    scanf("%15s", code); FLUSH_STDIN();

    memset(&pkt, 0, sizeof(pkt));
    pkt.type = 22;
    strncpy(pkt.data, code, sizeof(pkt.data) - 1);
    send(sock, (char *)&pkt, sizeof(pkt), 0);

    if (recv_all(sock, (char *)&pkt, sizeof(pkt)) > 0 && pkt.file_pk == 1) {
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
    if (name) strncpy(req.name, name, sizeof(req.name) - 1);
    send(sock, (char *)&req, sizeof(req), 0);

    struct AuthResponse res;
    if (recv_all(sock, (char *)&res, sizeof(res)) <= 0) return -1;
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
    if (!fp) { printf("  [Error] 파일 없음: %s\n", filename); free(pkt); return -1; }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    memset(pkt, 0, sizeof(*pkt));
    pkt->type = PKT_REQ_UPLOAD_START;
    pkt->user_pk = user_pk;
    pkt->file_size = fsize;
    send(sock, (char *)pkt, sizeof(*pkt), 0);

    if (recv_all(sock, (char *)pkt, sizeof(*pkt)) > 0) {
        file_pk = pkt->file_pk;
        if (file_pk == -1) {
            printf("  [Error] 업로드 거부 (용량 초과 등)\n");
            free(pkt); fclose(fp); return -1;
        }
        printf("  전송 중: ");
        while (1) {
            memset(pkt, 0, sizeof(*pkt));
            pkt->type    = PKT_REQ_UPLOAD_CHUNK;
            pkt->user_pk = user_pk;
            pkt->file_pk = file_pk;
            size_t rb = fread(pkt->data, 1, 8192, fp);
            if (rb > 0) {
                pkt->data_size = (int)rb;
                send(sock, (char *)pkt, sizeof(*pkt), 0);
                printf("#"); fflush(stdout);
            }
            if (feof(fp)) break;
            usleep(10000);
        }
        fclose(fp);
        printf("\n  전송 완료!\n");
    }

    memset(pkt, 0, sizeof(*pkt));
    pkt->type = PKT_REQ_UPLOAD_END;
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

    if (recv_all(sock, (char *)pkt, sizeof(*pkt)) <= 0) {
        printf("  [Error] 서버 연결 끊김\n"); free(pkt); return;
    }

    long total = pkt->file_size, received = 0;
    if (total == 0) { printf("  [Error] 파일 없음\n"); free(pkt); return; }

    FILE *fp = fopen(save_path, "wb");
    if (!fp) { fp = fopen(filename, "wb"); if (!fp) { free(pkt); return; } }

    printf("  다운로드 중 (%ld bytes)...\n", total);
    while (received < total) {
        if (recv_all(sock, (char *)pkt, sizeof(*pkt)) <= 0) {
            fclose(fp); remove(save_path); free(pkt); return;
        }
        if (pkt->type == PKT_RES_DOWNLOAD_DATA) {
            fwrite(pkt->data, 1, pkt->data_size, fp);
            received += pkt->data_size;
            printf("\r  [%ld / %ld]", received, total); fflush(stdout);
        }
    }
    printf("\n  [Success] 다운로드 완료!\n");
    fclose(fp); free(pkt);
}

// ═══════════════════════════════════════════════════════════
//  서브메뉴: 📂 파일
// ═══════════════════════════════════════════════════════════
void menu_file(int sock, int user_pk)
{
    while (1) {
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
        if (ch == 1) {
            char path[256];
            printf("  업로드할 파일 경로: ");
            scanf("%255s", path); FLUSH_STDIN();
            upload_file(sock, user_pk, path);
            PAUSE();
        }
        else if (ch == 2) {
            int fpk; char fname[256], spath[512];
            printf("  파일 PK: "); scanf("%d", &fpk); FLUSH_STDIN();
            printf("  저장 파일명: "); scanf("%255s", fname); FLUSH_STDIN();
            get_default_download_path(fname, spath);
            printf("  저장 위치: %s\n", spath);
            download_file(sock, user_pk, fpk, spath, fname);
            PAUSE();
        }
        else if (ch == 3) {
            printf("  [System] 파일 목록 조회 (미구현)\n");
            PAUSE();
        }
        else if (ch == 4) {
            int dpk;
            printf("  삭제할 파일 PK: "); scanf("%d", &dpk); FLUSH_STDIN();
            printf("  [System] 삭제 요청 (미구현)\n");
            PAUSE();
        }
        else {
            printf("  [Error] 0~4 중 선택하세요.\n");
            PAUSE();
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  서브메뉴: ⚙️ 설정
// ═══════════════════════════════════════════════════════════
void menu_settings(int sock, int user_pk, const char *email, int *should_logout)
{
    (void)sock; (void)user_pk;
    while (1) {
        CLEAR();
        printf("  ╔══════════════════════════════════╗\n");
        printf("  ║     ⚙️   설정 (Settings)          ║\n");
        printf("  ╠══════════════════════════════════╣\n");
        printf("  ║  1. 개인 설정 (미구현)           ║\n");
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
        if (ch == 1 || ch == 2 || ch == 3) {
            printf("  [System] 해당 기능은 준비 중입니다.\n");
            PAUSE();
        }
        else if (ch == 4) {
            printf("  [경고] 계정 탈퇴 시 모든 파일이 삭제됩니다.\n");
            printf("  [System] 폴더 삭제 (미구현)\n");
            PAUSE();
        }
        else if (ch == 5) {
            printf("  [System] 로그아웃 합니다.\n");
            *should_logout = 1;
            return;
        }
        else {
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
    while (1) {
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
        FLUSH_STDIN();   // ← 버퍼 완전 비우기 → 서브메뉴 오입력 원천 차단

        if (ch == 1) {
            msg_run_menu();   // MsgClientLogic.hpp → menu_message() 호출
            CLEAR();
        }
        else if (ch == 2) {
            menu_file(sock, user_pk);
        }
        else if (ch == 3) {
            int logout = 0;
            menu_settings(sock, user_pk, email, &logout);
            if (logout) {
                CLEAR();
                printf("  [System] 로그아웃 완료. 안녕히 가세요!\n\n");
                msg_cleanup();
                return;
            }
        }
        else if (ch == 4) {
            CLEAR();
            printf("  [System] 프로그램을 종료합니다. 안녕히 가세요!\n\n");
            msg_cleanup();
            return;
        }
        else {
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

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[Error] 서버 연결 실패");
        return -1;
    }

    CLEAR();
    printf("  [System] 서버(%s) 접속 성공!\n\n", target_ip);

    int  user_pk = -1;
    char email[64] = {0};
    char pw[32]    = {0};

    // ── 인증 루프 ────────────────────────────────────────────
    while (user_pk <= 0) {
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

        if (choice == 2) {
            printf("  ── 회원가입 ──────────────────────────\n");
            if (handle_email_auth(sock, email)) {
                char username[10] = {0};
                printf("  이름: "); scanf("%9s", username); FLUSH_STDIN();
                printf("  비밀번호: "); scanf("%31s", pw); FLUSH_STDIN();
                int pk = request_auth(sock, PKT_REQ_REGISTER, email, pw, username);
                if (pk > 0) {
                    user_pk = pk;
                    printf("  [Success] 가입 성공! (ID: %d)\n", user_pk);
                } else {
                    printf("  [Error] 이미 가입된 이메일이거나 서버 오류\n");
                }
            }
            PAUSE();
        }
        else if (choice == 1) {
            printf("  ── 로그인 ────────────────────────────\n");
            printf("  이메일: "); scanf("%63s", email); FLUSH_STDIN();
            printf("  비밀번호: "); scanf("%31s", pw); FLUSH_STDIN();
            user_pk = request_auth(sock, PKT_REQ_LOGIN, email, pw, "");
            if (user_pk > 0) {
                printf("  [Success] 로그인 성공!\n");
            } else {
                printf("  [Error] 이메일 또는 비밀번호가 틀렸습니다.\n");
                user_pk = -1;
            }
            PAUSE();
        }
    }

    // ── 메시지 서버 연결 ─────────────────────────────────────
    CLEAR();
    if (msg_init(user_pk) == 0)
        printf("  [System] 메시지 서버 연결 성공!\n");
    else
        printf("  [System] 메시지 서버 연결 실패 (메시지 기능 비활성화)\n");

    // ── 허브 메뉴 진입 ───────────────────────────────────────
    menu_hub(sock, user_pk, email);

    close(sock);
    return 0;
}
