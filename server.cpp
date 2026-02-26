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
#include "MsgServerLogic.hpp" // 메시지 서버 (포트 9001)

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
    thread([]
           { serverMain(); })
        .detach();
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

    // [수정] 중복 선언 제거 — current_original_name, current_file_size를 한 번만 선언
    string current_original_name = "";
    size_t current_file_size = 0;
    bool is_uploading = false;
    int current_user = -1;
    int current_file = -1;

    string session_email = "";

    while (true)
    {
        int16_t packet_type;
        int peek_len = recv(client_sock, (char *)&packet_type, sizeof(int16_t), MSG_PEEK);
        if (peek_len <= 0)
            break;

        int target_size = sizeof(FilePacket);

        // [추가] 개인정보 변경 패킷들도 AuthPacket 크기로 수신
        if (packet_type == PKT_REQ_LOGIN    ||
            packet_type == PKT_REQ_REGISTER ||
            packet_type == PKT_REQ_UPDATE_PW    ||   // [추가] 비밀번호 변경 패킷
            packet_type == PKT_REQ_UPDATE_NAME  ||   // [추가] 이름 변경 패킷
            packet_type == PKT_REQ_UPDATE_EMAIL ||   // [추가] 기본 이메일 설정 패킷
            packet_type == PKT_REQ_GET_USER_INFO)     // [추가] 사용자 정보 조회 패킷
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
            cout << "[Upload] 요청 - 유저PK: " << packet->user_pk << endl;
            current_original_name = packet->data;
            current_file_size = packet->file_size;

            size_t max_quota = (packet->user_pk == 10) ? (100 * 1024 * 1024) : (10 * 1024 * 1024);
            long long remaining_quota = storage.getRemainingQuota(packet->user_pk, max_quota);

            if (current_file_size > remaining_quota)
            {
                cout << "[거부] 용량 초과! (남은 용량: " << remaining_quota << " 바이트)" << endl;
                FilePacket res = {};
                res.type = PKT_RES_UPLOAD_END;
                res.file_pk = -1;
                send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                break;
            }

            storage.createUserDirectory(packet->user_pk);

            int real_file_pk = storage.createPendingFileRecord(packet->user_pk, current_original_name, current_file_size);

            if (real_file_pk < 0)
            {
                cout << "[거부] DB 레코드 생성 실패" << endl;
                FilePacket res = {};
                res.type = PKT_RES_UPLOAD_END;
                res.file_pk = -1;
                send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                break;
            }

            is_uploading = true;
            current_user = packet->user_pk;
            current_file = real_file_pk;

            FilePacket res = {};
            res.type = PKT_RES_UPLOAD_START;
            res.file_pk = real_file_pk;
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
            if (storage.moveFileToFinal(packet->user_pk, packet->file_pk, current_original_name, current_file_size))
            {
                std::string server_path = "./storage/server/" + std::to_string(packet->user_pk) + "/" + std::to_string(packet->file_pk) + ".dat";
                storage.finalizeFileRecord(packet->file_pk, server_path);

                cout << "[Upload End] 파일 저장 및 DB 업데이트 완료 (PK: " << packet->file_pk << ")" << endl;
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
            else
            {
                cout << "[Error] 다운로드 실패: 파일 크기가 0이거나 파일을 찾을 수 없음 (PK: " << packet->file_pk << ")" << endl;
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
            int new_pk = auth.registerUser(auth_pkt->id, auth_pkt->pwd_hash, auth_pkt->name);

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

        // =====================================================================
        // [추가] 사용자 정보 조회 (개인설정 화면 진입 시 현재 이름/기본이메일 표시)
        //
        // 클라이언트가 PKT_REQ_GET_USER_INFO를 보내면
        // AuthPacket.id = "" (빈 값, user_pk만 사용)
        // 서버는 AuthResponse.name + AuthResponse.default_email로 응답
        // =====================================================================
        case PKT_REQ_GET_USER_INFO:  // [추가]
        {
            AuthPacket *auth_pkt = (AuthPacket *)packet;

            string cur_name, cur_def_email;
            bool ok = auth.getUserInfo(auth_pkt->user_pk, cur_name, cur_def_email);

            AuthResponse res = {};
            res.type    = PKT_RES_GET_USER_INFO;  // [추가]
            res.user_pk = ok ? auth_pkt->user_pk : -1;

            // AuthResponse 구조체에 name, default_email 필드가 추가되어야 함
            // → Protocol.hpp 의 AuthResponse 수정 필요 (아래 주석 참고)
            strncpy(res.name,          cur_name.c_str(),      sizeof(res.name) - 1);
            strncpy(res.default_email, cur_def_email.c_str(), sizeof(res.default_email) - 1);

            send(client_sock, (char *)&res, sizeof(AuthResponse), 0);
            break;
        }

        // =====================================================================
        // [추가] 기본 이메일 설정
        //
        // 클라이언트 → 서버: AuthPacket
        //   - user_pk     : 변경할 사용자 PK
        //   - id          : 새로 설정할 기본 발신 이메일
        //
        // 서버 → 클라이언트: AuthResponse
        //   - user_pk     :  1 = 성공, -1 = 실패
        // =====================================================================
        case PKT_REQ_UPDATE_EMAIL:  // [추가]
        {
            AuthPacket *auth_pkt = (AuthPacket *)packet;
            cout << "[Server] 기본 이메일 변경 요청: user_pk=" << auth_pkt->user_pk
                 << ", new_email=" << auth_pkt->id << endl;

            bool ok = auth.updateDefaultEmail(auth_pkt->user_pk, auth_pkt->id);

            AuthResponse res = {};
            res.type    = PKT_RES_UPDATE_EMAIL;   // [추가]
            res.user_pk = ok ? 1 : -1;
            send(client_sock, (char *)&res, sizeof(AuthResponse), 0);
            break;
        }

        // =====================================================================
        // [추가] 비밀번호 변경
        //
        // 클라이언트 → 서버: AuthPacket
        //   - user_pk     : 변경할 사용자 PK
        //   - pwd_hash    : 현재 비밀번호의 SHA-256 해시 (검증용)
        //   - new_pwd_hash: 새 비밀번호의 SHA-256 해시
        //
        // 서버 → 클라이언트: AuthResponse
        //   - user_pk     :  1 = 성공, 0 = 현재PW 불일치, -1 = DB 오류
        // =====================================================================
        case PKT_REQ_UPDATE_PW:  // [추가]
        {
            AuthPacket *auth_pkt = (AuthPacket *)packet;
            cout << "[Server] 비밀번호 변경 요청: user_pk=" << auth_pkt->user_pk << endl;

            // pwd_hash    = 현재 비밀번호 해시 (검증용)
            // new_pwd_hash= 새 비밀번호 해시
            int result = auth.updatePassword(
                auth_pkt->user_pk,
                auth_pkt->pwd_hash,
                auth_pkt->new_pwd_hash   // AuthPacket에 new_pwd_hash 필드 필요 → Protocol.hpp 수정
            );

            AuthResponse res = {};
            res.type    = PKT_RES_UPDATE_PW;  // [추가]
            res.user_pk = result;             //  1=성공, 0=불일치, -1=오류
            send(client_sock, (char *)&res, sizeof(AuthResponse), 0);
            break;
        }

        // =====================================================================
        // [추가] 이름 변경
        //
        // 클라이언트 → 서버: AuthPacket
        //   - user_pk : 변경할 사용자 PK
        //   - name    : 새 이름
        //
        // 서버 → 클라이언트: AuthResponse
        //   - user_pk :  1 = 성공, -1 = 실패
        // =====================================================================
        case PKT_REQ_UPDATE_NAME:  // [추가]
        {
            AuthPacket *auth_pkt = (AuthPacket *)packet;
            cout << "[Server] 이름 변경 요청: user_pk=" << auth_pkt->user_pk
                 << ", new_name=" << auth_pkt->name << endl;

            bool ok = auth.updateName(auth_pkt->user_pk, auth_pkt->name);

            AuthResponse res = {};
            res.type    = PKT_RES_UPDATE_NAME;  // [추가]
            res.user_pk = ok ? 1 : -1;
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
