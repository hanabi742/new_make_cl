#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <thread>
#include "Protocol.hpp"
#include "AuthManager.hpp"
#include "StorageManager.hpp"
#include "MsgServerLogic.hpp"  // 메시지 서버 (포트 9001)

using namespace std;
using namespace std::filesystem;
using json = nlohmann::json;

#define OPENSSL_API_COMPAT 0x30000000L

int recv_all(int sock, char *buf, int size)
{
    int total_recv = 0;
    while (total_recv < size)
    {
        int len = recv(sock, buf + total_recv, size - total_recv, 0);
        if (len <= 0)
            return len;
        total_recv += len;
    }
    return total_recv;
}

int main()
{
    AuthManager auth;
    StorageManager storage;
    storage.initStorage();
    cout << "[Server] 저장소 준비 완료!" << endl;

    // 메시지 서버 별도 스레드로 실행 (포트 9001)
    thread([]{ serverMain(); }).detach();
    cout << "[Server] 메시지 서버 스레드 시작 (Port: 9001)" << endl;

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in server_addr = {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(9000);

    bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_sock, 5);
    cout << "[Server] 클라이언트 접속 대기 중... (Port: 9000)" << endl;

    int client_sock = accept(server_sock, nullptr, nullptr);
    cout << "[Server] 클라이언트 연결됨!" << endl;

    FilePacket *packet = new FilePacket();
    int fake_db_pk_counter = 100;

    bool is_uploading = false;
    int current_user = -1;
    int current_file = -1;
    string current_original_name = "";
    size_t current_file_size = 0;

    string session_email = "";

    while (true)
    {
        int16_t packet_type;
        int peek_len = recv(client_sock, (char *)&packet_type, sizeof(int16_t), MSG_PEEK);
        if (peek_len <= 0)
            break;

        int target_size = sizeof(FilePacket);

        if (packet_type == PKT_REQ_LOGIN || packet_type == PKT_REQ_REGISTER)
        {
            target_size = sizeof(AuthPacket);
        }

        int recv_len = recv_all(client_sock, (char *)packet, target_size);
        if (recv_len <= 0)
            break;

        switch (static_cast<PacketType>(packet->type))
        {
        case PKT_REQ_UPLOAD_START:
        {
            cout << "[Server] 업로드 요청. 유저: " << packet->user_pk << endl;
            current_original_name = packet->data;
            current_file_size = packet->file_size;

            size_t max_quota = (packet->user_pk == 10) ? (100 * 1024 * 1024) : (10 * 1024 * 1024);
            size_t current_used = storage.getUserTotalUsed(packet->user_pk);

            if (current_used + current_file_size > max_quota)
            {
                cout << "[경고] 용량 초과! 업로드 거부." << endl;
                FilePacket res = {};
                res.type = PKT_RES_UPLOAD_END;
                res.file_pk = -1;
                send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                break;
            }

            storage.createUserDirectory(packet->user_pk);
            fake_db_pk_counter++;

            is_uploading = true;
            current_user = packet->user_pk;
            current_file = fake_db_pk_counter;

            FilePacket res = {};
            res.type = PKT_RES_UPLOAD_START;
            res.file_pk = current_file;
            send(client_sock, (char *)&res, sizeof(FilePacket), 0);
            break;
        }

        case PKT_REQ_UPLOAD_CHUNK:
        {
            storage.saveTempChunk(packet->user_pk, packet->file_pk, packet->data, packet->data_size);
            break;
        }

        case PKT_REQ_UPLOAD_END:
        {
            int db_file_pk = -1;
            if (storage.moveFileToFinal(packet->user_pk, packet->file_pk,
                                        current_original_name, current_file_size,
                                        &db_file_pk))
            {
                cout << "[Server] 업로드 확정 완료. 파일: " << current_original_name
                     << " | DB FILE_PK: " << db_file_pk << endl;
                is_uploading = false;

                FilePacket res = {};
                res.type = PKT_RES_UPLOAD_END;
                res.file_pk = packet->file_pk;
                send(client_sock, (char *)&res, sizeof(FilePacket), 0);
            }
            break;
        }

        case PKT_REQ_DOWNLOAD_START:
        {
            size_t fsize = storage.getFileSize(packet->user_pk, packet->file_pk);
            FilePacket res = {};
            res.type = PKT_RES_DOWNLOAD_START;
            res.file_size = fsize;
            send(client_sock, (char *)&res, sizeof(FilePacket), 0);

            if (fsize > 0)
            {
                size_t offset = 0;
                while (offset < fsize)
                {
                    FilePacket chunk = {};
                    chunk.type = PKT_RES_DOWNLOAD_DATA;
                    size_t read_bytes = storage.readFileChunk(packet->user_pk, packet->file_pk, offset, chunk.data);
                    if (read_bytes > 0)
                    {
                        chunk.data_size = (int)read_bytes;
                        if (send(client_sock, (char *)&chunk, sizeof(FilePacket), 0) <= 0)
                            break;
                        offset += read_bytes;
                    }
                    else
                        break;
                }
            }
            break;
        }

        case PKT_REQ_EMAIL_AUTH:
        {
            session_email = packet->data;
            cout << "[Server] 인증 번호 요청 접수: " << session_email << endl;

            FilePacket res = {};
            res.type = PKT_RES_EMAIL_AUTH;

            if (auth.requestEmailAuth(session_email))
            {
                res.file_pk = 1;
                cout << "[Server] 메일 발송 성공" << endl;
            }
            else
            {
                res.file_pk = -1;
                cout << "[Server] 메일 발송 실패" << endl;
            }
            send(client_sock, (char *)&res, sizeof(FilePacket), 0);
            break;
        }

        case PKT_REQ_EMAIL_VERIFY:
        {
            string input_code = packet->data;
            cout << "[Server] 인증 번호 검증 시도: " << session_email << " -> " << input_code << endl;

            FilePacket res = {};
            res.type = PKT_RES_EMAIL_VERIFY;

            if (auth.verifyEmail(session_email, input_code))
            {
                res.file_pk = 1;
                cout << "[Server] 인증 성공!" << endl;
            }
            else
            {
                res.file_pk = -1;
                cout << "[Server] 인증 실패 (번호 불일치)" << endl;
            }
            send(client_sock, (char *)&res, sizeof(FilePacket), 0);
            break;
        }

        case PKT_REQ_REGISTER:
        {
            AuthPacket *auth_pkt = (AuthPacket *)packet;

            // ── [수정된 부분 — 딱 한 줄] ──────────────────────────────────
            // 기존: auth.registerUser(auth_pkt->id, auth_pkt->pwd_hash)
            // 변경: name 필드를 추가로 전달 (AuthPacket.name 활용)
            int new_pk = auth.registerUser(auth_pkt->id, auth_pkt->pwd_hash, auth_pkt->name);
            // ─────────────────────────────────────────────────────────────

            if (new_pk > 0)
            {
                storage.createUserDirectory(new_pk);
                cout << "[Server] 회원가입 성공! PK: " << new_pk << endl;
            }

            AuthResponse res = {};
            res.type = PKT_RES_REGISTER;
            res.user_pk = new_pk;
            send(client_sock, (char *)&res, sizeof(AuthResponse), 0);
            break;
        }

        case PKT_REQ_LOGIN:
        {
            AuthPacket *auth_pkt = (AuthPacket *)packet;
            int login_pk = auth.loginUser(auth_pkt->id, auth_pkt->pwd_hash);

            AuthResponse res = {};
            res.type = PKT_RES_LOGIN;
            res.user_pk = login_pk;
            send(client_sock, (char *)&res, sizeof(AuthResponse), 0);
            break;
        }

        default:
            break;
        }
    }

    delete packet;
    close(client_sock);
    close(server_sock);
    return 0;
}
