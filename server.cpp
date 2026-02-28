#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>
#include <mutex>
#include "Protocol.hpp"
#include "AuthManager.hpp"
#include "StorageManager.hpp"
#include "MsgServerLogic.hpp"
#include "UserManager.hpp"
#include "AdminManager.hpp"
#include "BlacklistManager.hpp"

using namespace std;
using namespace std::filesystem;

#define OPENSSL_API_COMPAT 0x30000000L

// 전역 변수 및 동기화 객체
vector<int> client_sockets;
mutex v_mtx;
int MAX_USERS = 30;

// 네트워크 데이터 완전 수신 보장 함수
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

// 접속 종료 클라이언트 정리
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

    UserManager user_mgr(auth, storage);
    AdminManager admin(auth, storage);
    admin.setClientList(&client_sockets, &v_mtx);
    BlacklistManager blacklist_mgr;
    cout << "[Server] 모든 매니저 초기화 완료." << endl;

    // 메시지 서버 포트 9001 실행
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

    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        return -1;
    }
    listen(server_sock, 5);
    cout << "[Server] 클라이언트 접속 대기 중... (Port: 9000)" << endl;

    // 클라이언트 처리 람다 함수
    auto handle_client = [&](int client_sock, string client_ip)
    {
        FilePacket *packet = new FilePacket();

        string current_original_name = "";
        size_t current_file_size_val = 0;
        bool is_uploading = false;
        int current_user = -1;
        int current_file = -1;
        string session_email = "";

        try
        {
            while (true)
            {
                int16_t packet_type;
                // 1. 헤더 2바이트 먼저 수신
                int type_len = recv_all(client_sock, (char *)&packet_type, sizeof(int16_t));
                if (type_len <= 0)
                    break;

                packet->type = packet_type;
                int target_size = sizeof(FilePacket);

                // 패킷 타입에 따른 구조체 크기 설정
                if (packet_type == PKT_REQ_LOGIN || packet_type == PKT_REQ_REGISTER)
                    target_size = sizeof(AuthPacket);
                else if (packet_type == PKT_REQ_ADMIN_NOTICE || packet_type == PKT_REQ_ADMIN_BAN ||
                         packet_type == PKT_REQ_ADMIN_RESET || packet_type == PKT_REQ_ADMIN_STATUS)
                    target_size = sizeof(AdminPacket);
                else if (packet_type == PKT_REQ_USER_SETTINGS)
                    target_size = sizeof(UserSettingsPacket);
                else if (packet_type == 500 || packet_type == 502 || packet_type == 504)
                    target_size = sizeof(BlacklistReqPacket);

                // 2. 나머지 본문 수신
                int rest_size = target_size - sizeof(int16_t);
                int recv_len = recv_all(client_sock, ((char *)packet) + sizeof(int16_t), rest_size);
                if (recv_len <= 0)
                    break;

                // [블랙리스트 기능 처리]
                if (packet->type == 500 || packet->type == 502 || packet->type == 504)
                {
                    BlacklistReqPacket *bl_req = (BlacklistReqPacket *)packet;
                    if (packet->type == 500)
                    {
                        int result = blacklist_mgr.addBlacklist(bl_req->self_user_num, bl_req->target_email);
                        BlacklistResPacket res = {501, result};
                        send(client_sock, (char *)&res, sizeof(res), 0);
                    }
                    else if (packet->type == 502)
                    {
                        int result = blacklist_mgr.removeBlacklist(bl_req->self_user_num, bl_req->blacklist_num);
                        BlacklistResPacket res = {503, result};
                        send(client_sock, (char *)&res, sizeof(res), 0);
                    }
                    else if (packet->type == 504)
                    {
                        auto list = blacklist_mgr.getMyBlacklist(bl_req->self_user_num);
                        for (const auto &entry : list)
                        {
                            BlacklistResPacket res = {505, 1, entry.blacklist_num};
                            strncpy(res.target_email, entry.target_email.c_str(), 127);
                            strncpy(res.created_at, entry.created_at.c_str(), 19);
                            send(client_sock, (char *)&res, sizeof(res), 0);
                        }
                        BlacklistResPacket end_res = {506};
                        send(client_sock, (char *)&end_res, sizeof(end_res), 0);
                    }
                    continue;
                }

                // [메인 프로토콜 처리]
                switch (static_cast<PacketType>(packet->type))
                {
                case PKT_REQ_UPLOAD_START:
                {
                    cout << "[Upload] 요청 - 유저PK: " << packet->user_pk << endl;
                    current_original_name = packet->data;

                    // 대용량 처리를 위한 long long 타입 계산
                    long long req_file_size = (long long)packet->file_size;
                    long long max_quota = auth.getUserMaxStorage(packet->user_pk);
                    long long current_used = storage.getUserTotalUsed(packet->user_pk);
                    long long remaining_quota = max_quota - current_used;

                    if (req_file_size > remaining_quota)
                    {
                        cout << "[거부] 용량 초과! (남은: " << remaining_quota << " bytes)" << endl;
                        FilePacket res = {};
                        res.type = PKT_RES_UPLOAD_END;
                        res.file_pk = -1;
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                        break;
                    }

                    storage.createUserDirectory(packet->user_pk);
                    int real_file_pk = storage.createPendingFileRecord(packet->user_pk, current_original_name, (size_t)req_file_size);

                    if (real_file_pk < 0)
                    {
                        FilePacket res = {};
                        res.type = PKT_RES_UPLOAD_END;
                        res.file_pk = -1;
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                        break;
                    }

                    is_uploading = true;
                    current_user = packet->user_pk;
                    current_file = real_file_pk;
                    current_file_size_val = (size_t)req_file_size;

                    FilePacket res = {};
                    res.type = PKT_RES_UPLOAD_START;
                    res.file_pk = real_file_pk;
                    send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                    break;
                }

                case PKT_REQ_UPLOAD_CHUNK:
                    storage.saveTempChunk(packet->user_pk, packet->file_pk, packet->data, packet->data_size);
                    break;

                case PKT_REQ_UPLOAD_END:
                    if (storage.moveFileToFinal(packet->user_pk, packet->file_pk, current_original_name, current_file_size_val))
                    {
                        string server_path = "./storage/server/" + to_string(packet->user_pk) + "/" + to_string(packet->file_pk) + ".dat";
                        storage.finalizeFileRecord(packet->file_pk, server_path);
                        is_uploading = false;
                        FilePacket res = {PKT_RES_UPLOAD_END};
                        res.file_pk = packet->file_pk;
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                    }
                    break;

                case PKT_REQ_DOWNLOAD_START:
                {
                    size_t fsize = storage.getFileSize(packet->user_pk, packet->file_pk);
                    FilePacket res = {PKT_RES_DOWNLOAD_START};
                    res.file_size = (int64_t)fsize;
                    send(client_sock, (char *)&res, sizeof(FilePacket), 0);

                    if (fsize > 0)
                    {
                        size_t offset = 0;
                        while (offset < fsize)
                        {
                            FilePacket chunk = {PKT_RES_DOWNLOAD_DATA};
                            size_t read_bytes = storage.readFileChunk(packet->user_pk, packet->file_pk, offset, chunk.data);
                            if (read_bytes > 0)
                            {
                                chunk.data_size = (int)read_bytes;
                                send(client_sock, (char *)&chunk, sizeof(FilePacket), 0);
                                offset += read_bytes;
                            }
                            else
                                break;
                        }
                    }
                    break;
                }

                case PKT_REQ_LIST:
                {
                    string list_data = storage.getUserFileList(packet->user_pk);
                    FilePacket res = {PKT_RES_LIST};
                    size_t offset = 0;
                    while (offset < list_data.size())
                    {
                        memset(res.data, 0, 8192);
                        size_t copy_len = min(list_data.size() - offset, (size_t)8191);
                        strncpy(res.data, list_data.c_str() + offset, copy_len);
                        send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                        offset += copy_len;
                    }
                    FilePacket end_res = {PKT_RES_LIST_END};
                    send(client_sock, (char *)&end_res, sizeof(FilePacket), 0);
                    break;
                }

                case PKT_REQ_STORAGE_INFO:
                {
                    long long max_quota = auth.getUserMaxStorage(packet->user_pk);
                    long long remaining = storage.getRemainingQuota(packet->user_pk, max_quota);
                    FilePacket res = {PKT_RES_STORAGE_INFO};
                    res.file_size = max_quota;
                    res.offset = (int64_t)remaining;
                    send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                    break;
                }

                case PKT_REQ_EMAIL_AUTH:
                {
                    session_email = packet->data;
                    FilePacket res = {PKT_RES_EMAIL_AUTH};
                    res.file_pk = auth.requestEmailAuth(session_email) ? 1 : -1;
                    send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                    break;
                }

                case PKT_REQ_EMAIL_VERIFY:
                {
                    FilePacket res = {PKT_RES_EMAIL_VERIFY};
                    res.file_pk = auth.verifyEmail(session_email, packet->data) ? 1 : -1;
                    send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                    break;
                }

                case PKT_REQ_UPGRADE_GRADE:
                {
                    bool success = auth.upgradeUserGrade(packet->user_pk, packet->fileName);
                    FilePacket res = {PKT_RES_UPGRADE_GRADE};
                    res.file_pk = success ? 1 : -1;
                    send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                    break;
                }

                case PKT_REQ_REGISTER:
                {
                    AuthPacket *auth_pkt = (AuthPacket *)packet;
                    int new_pk = auth.registerUser(auth_pkt->id, auth_pkt->pwd_hash, auth_pkt->name);
                    if (new_pk > 0)
                        storage.createUserDirectory(new_pk);
                    AuthResponse res = {PKT_RES_REGISTER, new_pk};
                    send(client_sock, (char *)&res, sizeof(AuthResponse), 0);
                    break;
                }

                case PKT_REQ_LOGIN:
                {
                    AuthPacket *auth_pkt = (AuthPacket *)packet;
                    int login_pk = auth.loginUser(auth_pkt->id, auth_pkt->pwd_hash);
                    if (login_pk > 0 && admin.isAccessDenied(client_ip, login_pk))
                        login_pk = -1;
                    AuthResponse res = {PKT_RES_LOGIN, login_pk};
                    send(client_sock, (char *)&res, sizeof(AuthResponse), 0);
                    break;
                }

                case PKT_REQ_ADMIN_NOTICE:
                {
                    AdminPacket *admin_pkt = (AdminPacket *)packet;
                    if (admin.isMasterAdmin(admin_pkt->admin_pk))
                    {
                        string notice = "[전체공지] " + string(admin_pkt->data);
                        admin.sendGlobalNotice(notice);
                        admin.saveGlobalNoticeToDB(admin_pkt->admin_pk, notice);
                        FilePacket res = {PKT_RES_ADMIN_NOTICE};
                        strncpy(res.data, notice.c_str(), 8191);
                        lock_guard<mutex> lock(v_mtx);
                        for (int s : client_sockets)
                            send(s, (char *)&res, sizeof(FilePacket), 0);
                    }
                    break;
                }

                case PKT_REQ_ADMIN_BAN:
                {
                    AdminPacket *admin_pkt = (AdminPacket *)packet;
                    if (admin.isMasterAdmin(admin_pkt->admin_pk))
                    {
                        string target_ip_str = string(admin_pkt->data);
                        // [에러 해결] 인자 순서 수정: (admin_pk, ip, target_pk, 사유)
                        admin.addCombinedBlacklist(admin_pkt->admin_pk, target_ip_str, admin_pkt->target_pk, "운영자 수동 차단");
                    }
                    break;
                }

                case PKT_REQ_ADMIN_RESET:
                {
                    AdminPacket *admin_pkt = (AdminPacket *)packet;
                    if (admin.isMasterAdmin(admin_pkt->admin_pk))
                    {
                        admin.resetSystemWithAuth(admin_pkt->admin_pk, string(admin_pkt->data));
                    }
                    break;
                }

                case PKT_REQ_ADMIN_STATUS:
                {
                    AdminPacket *admin_pkt = (AdminPacket *)packet;
                    if (admin.isMasterAdmin(admin_pkt->admin_pk))
                    {
                        long long u, r;
                        admin.getCloudUsageStatus(u, r);
                        AdminPacket res = {PKT_RES_ADMIN_STATUS, 0, admin.getCurrentClientCount()};
                        snprintf(res.data, 255, "%lld|%lld", u, r);
                        send(client_sock, (char *)&res, sizeof(AdminPacket), 0);
                    }
                    break;
                }

                case PKT_REQ_USER_SETTINGS:
                {
                    UserSettingsPacket *req = (UserSettingsPacket *)packet;
                    bool success = false;
                    if (req->setting_type == 1)
                        success = user_mgr.updateUserName(req->user_pk, req->new_data);
                    else if (req->setting_type == 2)
                    {
                        string data = req->new_data;
                        size_t pos = data.find('|');
                        if (pos != string::npos)
                            success = user_mgr.verifyAndUpdatePassword(req->user_pk, data.substr(0, pos), data.substr(pos + 1));
                    }
                    else if (req->setting_type == 3)
                        success = user_mgr.changeUserEmail(req->user_pk, req->new_data);
                    FilePacket res = {PKT_RES_USER_SETTINGS};
                    res.file_pk = success ? 1 : -1;
                    send(client_sock, (char *)&res, sizeof(FilePacket), 0);
                    break;
                }
                default:
                    break;
                }
            }
        }
        catch (const exception &e)
        {
            cout << "[Error] " << e.what() << endl;
        }

        delete packet;
        remove_client(client_sock);
    };

    while (true)
    {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0)
            continue;

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);

        if (admin.isAccessDenied(client_ip))
        {
            close(client_sock);
            continue;
        }

        ServerHandshakeHeader header = {PKT_RES_HANDSHAKE, 1.2f};
        v_mtx.lock();
        header.current_users = client_sockets.size();
        header.max_users = MAX_USERS;
        v_mtx.unlock();

        send(client_sock, (char *)&header, sizeof(header), 0);

        if (header.current_users >= header.max_users)
        {
            close(client_sock);
            continue;
        }

        {
            lock_guard<mutex> lock(v_mtx);
            client_sockets.push_back(client_sock);
        }
        thread(handle_client, client_sock, string(client_ip)).detach();
    }

    close(server_sock);
    return 0;
}