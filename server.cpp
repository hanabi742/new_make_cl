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
#include "UserManager.hpp"
#include "AdminManager.hpp"

using namespace std;
using namespace std::filesystem;
using json = nlohmann::json;

#define OPENSSL_API_COMPAT 0x30000000L

vector<int> client_sockets; // 현재 접속 중인 클라이언트 소켓 목록
mutex v_mtx;                // 벡터 접근 보호용 뮤텍스
int MAX_USERS = 30;         // 서버 최대 수용 인원 (관리자가 변경 가능하도록 변수화)

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

void remove_client(int sock)
{
    lock_guard<mutex> lock(v_mtx);
    client_sockets.erase(remove(client_sockets.begin(), client_sockets.end(), sock), client_sockets.end());
    close(sock);
}


int main()
{
    AuthManager auth;
    StorageManager storage;
    storage.initStorage();
    cout << "[Server] 저장소 준비 완료!" << endl;

    // UserManager와 AdminManager 생성 (의존성 주입)
    UserManager user_mgr(auth, storage);
    AdminManager admin(auth, storage);
    cout << "[Server] 모든 매니저 초기화 완료." << endl;

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

    // 클라이언트 1명을 처리하는 람다 (스레드로 실행됨)
    // auto handle_client = [&](int client_sock)
    auto handle_client = [&](int client_sock, string client_ip)
    {
        FilePacket *packet = new FilePacket();

        string current_original_name = "";
        size_t current_file_size = 0;
        bool is_uploading = false;
        int current_user = -1;
        int current_file = -1;
        string session_email = "";

        try
        {
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
                else if (packet_type == PKT_REQ_ADMIN_NOTICE || packet_type == PKT_REQ_ADMIN_BAN || packet_type == PKT_REQ_ADMIN_RESET)
                {
                    target_size = sizeof(AdminPacket);  // 관리자 명령어 처리를 위한 정확한 패킷 사이즈 할당
                }
                else if (packet_type == PKT_REQ_USER_SETTINGS)
                {
                    target_size = sizeof(UserSettingsPacket);   // 유저 설정 변경 패킷 사이즈 할당
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

                        size_t max_quota = user_mgr.getMaxQuota(packet->user_pk);
                        size_t current_used = storage.getUserTotalUsed(packet->user_pk);

                        // getRemainingQuota 함수로 '남은 용량'을 정확히 계산
                        long long remaining_quota = storage.getRemainingQuota(packet->user_pk, max_quota);

                        if (current_file_size > remaining_quota)
                        {
                            cout << "[거부] 용량 초과! (남은 용량: " << remaining_quota << " 바이트)" << endl;
                            FilePacket res = {};
                            res.type = PKT_RES_UPLOAD_END;
                            res.file_pk = -1; // 실패 신호
                            send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                            break;
                        }

                        storage.createUserDirectory(packet->user_pk);

                        // 💡 [변경 3] 가짜 카운터(fake_db_pk_counter) 삭제! DB에서 진짜 고유 PK 발급
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
                        current_file = real_file_pk; // 세션 변수에 진짜 PK 저장

                        FilePacket res = {};
                        res.type = PKT_RES_UPLOAD_START;
                        res.file_pk = real_file_pk; // 클라이언트에게 진짜 DB PK 전달
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                        break;
                    }

                    // ── [파일 조각 수신] ──────────────────────────────────────────
                    case PKT_REQ_UPLOAD_CHUNK:
                    {
                        // 이제 packet->file_pk는 무조건 DB에 존재하는 고유한 값입니다.
                        storage.saveTempChunk(packet->user_pk, packet->file_pk, packet->data, packet->data_size);
                        break;
                    }

                    // ── [파일 업로드 완료] ──────────────────────────────────────────
                    case PKT_REQ_UPLOAD_END:
                    {
                        // 1. 임시 파일을 최종 위치(.dat)로 이동하고 JSON 메타데이터 기록
                        if (storage.moveFileToFinal(packet->user_pk, packet->file_pk, current_original_name, current_file_size))
                        {
                            // 2. 최종 저장된 물리적 서버 경로
                            std::string server_path = "./storage/server/" + std::to_string(packet->user_pk) + "/" + std::to_string(packet->file_pk) + ".dat";

                            // 💡 [변경 4] 새로 INSERT 하는 것이 아니라, 기존 레코드에 서버 경로(SERVER_PATH)만 UPDATE
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

                    // ── [파일 다운로드 시작] ──────────────────────────────────────────
                    case PKT_REQ_DOWNLOAD_START:
                    {
                        // 💡 [핵심] StorageManager 내부에서 DB를 조회하여 실제 경로를 찾아 크기를 반환하도록 설계됨
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
                                    break; // 더 이상 읽을 데이터가 없으면 탈출
                            }
                        }
                        else
                        {
                            cout << "[Error] 다운로드 실패: 파일 크기가 0이거나 파일을 찾을 수 없음 (PK: " << packet->file_pk << ")" << endl;
                        }
                        break;
                    }
                    case PKT_REQ_LIST: // 40
                    {
                        string list_data = storage.getUserFileList(packet->user_pk);
                        FilePacket res = {};
                        res.type = PKT_RES_LIST; // 41
                        res.user_pk = packet->user_pk;

                        size_t max_data_len = sizeof(res.data) - 1;
                        size_t offset = 0;

                        // 데이터가 클 수 있으므로 패킷 크기만큼 안전하게 잘라서 전송
                        while (offset < list_data.size())
                        {
                            memset(res.data, 0, sizeof(res.data));
                            size_t copy_len = min(list_data.size() - offset, max_data_len);
                            strncpy(res.data, list_data.c_str() + offset, copy_len);
                            send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                            offset += copy_len;
                        }

                        // 전송 끝 알림
                        res.type = PKT_RES_LIST_END; // 42
                        memset(res.data, 0, sizeof(res.data));
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                        break;
                    }
                    case PKT_REQ_DELETE_FOLDER: 
                    {
                        bool success = storage.deleteUserFolder(packet->user_pk);
                        FilePacket res = {};
                        res.type = PKT_RES_DELETE_FOLDER; 
                        res.file_pk = success ? 1 : -1;   // 1: 성공, -1: 실패 (파일 남음)
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                        break;
                    }

                    case PKT_REQ_STORAGE_INFO: 
                    {
                        long long max_quota = (packet->user_pk == 10) ? (100 * 1024 * 1024) : (10 * 1024 * 1024); 
                        long long remaining = storage.getRemainingQuota(packet->user_pk, max_quota);

                        FilePacket res = {};
                        res.type = PKT_RES_STORAGE_INFO;
                        res.user_pk = packet->user_pk;
                        res.file_size = max_quota; 
                        res.offset = remaining;    
                        
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                        break;
                    }

                    // ── [파일 삭제] ─────────────────────────────
                    case PKT_REQ_DELETE: // 43
                    {
                        bool success = storage.deleteFile(packet->user_pk, packet->file_pk);
                        FilePacket res = {};
                        res.type = PKT_RES_DELETE; // 44
                        res.file_pk = success ? 1 : -1;
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
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

                        // 로그인 성공 시, 혹시 차단된 계정인지 2차 확인 (AdminManager)
                        if (login_pk > 0 && admin.isAccessDenied(client_ip, login_pk))
                        {
                            cout << "[Security] 차단된 계정 접속 시도: " << login_pk << endl;
                            login_pk = -1; // 로그인 실패 처리
                        }

                        AuthResponse res = {};
                        res.type = PKT_RES_LOGIN;
                        res.user_pk = login_pk;
                        send(client_sock, (char *)&res, sizeof(AuthResponse), 0);
                        break;
                    }

                    case PKT_REQ_ADMIN_NOTICE:
                    {
                        AdminPacket *admin_pkt = (AdminPacket *)packet;
                        if (admin.check_admin(admin_pkt->admin_pk))
                        {
                            admin.sendGlobalNotice(admin_pkt->data);
                        }
                        break;
                    }

                    case PKT_REQ_ADMIN_BAN:
                    {
                        AdminPacket *admin_pkt = (AdminPacket *)packet; //
                        if (admin.check_admin(admin_pkt->admin_pk))
                        {
                            admin.banUser(admin_pkt->target_pk);
                        }
                        break;
                    }

                    case PKT_REQ_ADMIN_RESET:
                    {
                        AdminPacket *admin_pkt = (AdminPacket *)packet;
                        if (admin.check_admin(admin_pkt->admin_pk))
                        {
                            admin.resetSystem();
                        }
                        break;
                    }

                    case PKT_REQ_USER_SETTINGS:
                    {
                        UserSettingsPacket *req = (UserSettingsPacket *)packet;
                        bool success = false;

                        if (req->setting_type == 1)
                        {
                            success = user_mgr.updateUserName(req->user_pk, req->new_data);
                        }
                        else if (req->setting_type == 2)
                        {
                            success = user_mgr.updateUserPassword(req->user_pk, req->new_data);
                        }

                        FilePacket res = {};
                        res.type = PKT_RES_USER_SETTINGS;
                        res.file_pk = success ? 1 : -1;
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                        break;
                    }
                    default:
                        break;
                }
            }
        }
        catch (const std::exception &e)
        {
            cout << "[Error] 스레드 예외 발생: " << e.what() << endl;
        }

        delete packet;
        cout << "[Exit] 클라이언트 접속 종료 (IP: " << client_ip << ")" << endl;
        remove_client(client_sock);
    }; // handle_client 람다 끝

    // 클라이언트 접속을 무한정 받는 루프
    while (true)
    {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        // int client_sock = accept(server_sock, nullptr, nullptr);
        if (client_sock < 0)
        {
            cerr << "[Server] accept 실패, 계속 대기..." << endl;
            continue;
        }
        cout << "[Server] 클라이언트 연결됨!" << endl;

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        // ─────────────────────────────────────────────────────────
        // [방어 1단계] IP 블랙리스트 체크 (문지기)
        // ─────────────────────────────────────────────────────────
        if (admin.isAccessDenied(client_ip))
        {
            cout << "[Block] 차단된 IP 접속 시도 거부: " << client_ip << endl;
            close(client_sock);
            continue;
        }

        // ─────────────────────────────────────────────────────────
        // [안내 2단계] 핸드셰이크 헤더 발송 (안내데스크)
        // ─────────────────────────────────────────────────────────
        ServerHandshakeHeader header = {0};
        header.type = PKT_RES_HANDSHAKE;
        header.server_version = 1.2f;

        v_mtx.lock();
        header.current_users = client_sockets.size();
        header.max_users = MAX_USERS;
        v_mtx.unlock();
        header.next_port = 0;

        send(client_sock, (char *)&header, sizeof(header), 0);

        if (header.current_users >= header.max_users)
        {
            cout << "[Full] 정원 초과로 접속 거부: " << client_ip << endl;
            close(client_sock);
            continue;
        }

        // ─────────────────────────────────────────────────────────
        // [입장 허용] 스레드 생성 및 서비스 시작
        // ─────────────────────────────────────────────────────────
        {
            lock_guard<mutex> lock(v_mtx);
            client_sockets.push_back(client_sock);
        }

        cout << "[Connect] 새 접속: " << client_ip << " (현재: " << client_sockets.size() << "명)" << endl;
        
        // 클라이언트마다 별도 스레드로 처리 (서버는 계속 대기)
        // thread(handle_client, client_sock).detach();
        thread(handle_client, client_sock, string(client_ip)).detach();
    }

    close(server_sock);
    return 0;
}