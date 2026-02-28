#pragma once
// ============================================================
//  MsgServerLogic.hpp
//  - 메시지 서버 로직 (MariaDB + JSON)
//  - MEMBERSHIP (USER_NUM, NAME, PW, ID, GRADE) 연동
//  - MESSAGE (MESSAGE_NUM, SEND_USER, TAKE_USER, DETAIL, READ_STATUS, CREATED_AT, USER_NUM)
// ============================================================

#include <mariadb/mysql.h>
#include <iostream>
#include <string>
#include <cstring>
#include <thread>
#include <vector>
#include <sstream>
#include <algorithm>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>

#include "msg_protocol.hpp"
#include "DBConfig.hpp"
#include "BlacklistManager.hpp" // [추가 - 재훈] 블랙리스트 필터링

// ============================================================
//  간이 JSON 빌더 / 파서
// ============================================================
namespace SimpleJSON
{
    inline std::string escape(const std::string &s)
    {
        std::string out;
        out.reserve(s.size());
        for (char c : s)
        {
            if (c == '"')
                out += "\\\"";
            else if (c == '\\')
                out += "\\\\";
            else if (c == '\n')
                out += "\\n";
            else if (c == '\r')
                out += "\\r";
            else
                out += c;
        }
        return out;
    }

    class Builder
    {
        std::string buf_;
        bool first_ = true;

    public:
        Builder() { buf_ = "{"; }
        Builder &str(const std::string &k, const std::string &v)
        {
            if (!first_)
                buf_ += ",";
            buf_ += "\"" + k + "\":\"" + escape(v) + "\"";
            first_ = false;
            return *this;
        }
        Builder &num(const std::string &k, long long v)
        {
            if (!first_)
                buf_ += ",";
            buf_ += "\"" + k + "\":" + std::to_string(v);
            first_ = false;
            return *this;
        }
        Builder &raw(const std::string &k, const std::string &v)
        {
            if (!first_)
                buf_ += ",";
            buf_ += "\"" + k + "\":" + v;
            first_ = false;
            return *this;
        }
        std::string build() { return buf_ + "}"; }
    };

    inline std::string getString(const std::string &json, const std::string &key)
    {
        std::string search = "\"" + key + "\":\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos)
            return "";
        pos += search.size();
        size_t end = pos;
        while (end < json.size())
        {
            if (json[end] == '"' && json[end - 1] != '\\')
                break;
            end++;
        }
        return json.substr(pos, end - pos);
    }

    inline std::string getNumber(const std::string &json, const std::string &key)
    {
        std::string search = "\"" + key + "\":";
        size_t pos = json.find(search);
        if (pos == std::string::npos)
            return "0";
        pos += search.size();
        if (pos < json.size() && json[pos] == '"')
            return "0";
        size_t end = pos;
        while (end < json.size() && (isdigit(json[end]) || json[end] == '-'))
            end++;
        return json.substr(pos, end - pos);
    }
}

// ============================================================
//  네트워크 헬퍼
// ============================================================
namespace NetHelper
{
    inline bool sendPacket(int sock, const std::string &body)
    {
        uint32_t len = htonl((uint32_t)body.size());
        if (send(sock, &len, 4, 0) != 4)
            return false;
        size_t sent = 0;
        while (sent < body.size())
        {
            int r = send(sock, body.c_str() + sent, body.size() - sent, 0);
            if (r <= 0)
                return false;
            sent += r;
        }
        return true;
    }

    inline std::string recvPacket(int sock)
    {
        uint32_t net_len = 0;
        int r = recv(sock, &net_len, 4, MSG_WAITALL);
        if (r != 4)
            return "";
        uint32_t body_len = ntohl(net_len);
        if (body_len == 0 || body_len > MAX_MSG_BODY)
            return "";
        std::string body(body_len, '\0');
        size_t got = 0;
        while (got < body_len)
        {
            r = recv(sock, &body[got], body_len - got, 0);
            if (r <= 0)
                return "";
            got += r;
        }
        return body;
    }

    inline void sendError(int sock, const std::string &msg)
    {
        std::cerr << "[MsgServer] 에러 응답 전송: " << msg << std::endl;
        std::string body = SimpleJSON::Builder()
                               .str(MSG_FIELD::TYPE, MSG_RES::ERROR)
                               .str(MSG_FIELD::RESULT, MSG_RESULT::FAIL)
                               .str(MSG_FIELD::MESSAGE, msg)
                               .build();
        sendPacket(sock, body);
    }
}

// ============================================================
//  DB 헬퍼
// ============================================================
namespace DBHelper
{
    inline MYSQL *connect()
    {
        std::cout << "[DBHelper] DB 연결 시도... (host=" DB_HOST ", user=" DB_USER ", db=" DB_NAME ")" << std::endl;
        MYSQL *c = mysql_init(NULL);
        if (!c)
        {
            std::cerr << "[DBHelper Error] mysql_init 실패" << std::endl;
            return nullptr;
        }
        if (!mysql_real_connect(c, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, NULL, 0))
        {
            std::cerr << "[DBHelper Error] 연결 실패!" << std::endl;
            std::cerr << "[DBHelper Error] 에러 코드  : " << mysql_errno(c) << std::endl;
            std::cerr << "[DBHelper Error] 에러 메시지: " << mysql_error(c) << std::endl;
            std::cerr << "[DBHelper Error] 힌트) 1045=계정오류 / 1049=DB없음 / 2002=서버꺼짐" << std::endl;
            mysql_close(c);
            return nullptr;
        }
        mysql_set_character_set(c, "utf8mb4");
        std::cout << "[DBHelper] DB 연결 성공!" << std::endl;
        return c;
    }

    inline std::string escape(MYSQL *conn, const std::string &s)
    {
        std::string out(s.size() * 2 + 1, '\0');
        unsigned long len = mysql_real_escape_string(conn, &out[0], s.c_str(), s.size());
        out.resize(len);
        return out;
    }

    inline std::string getIDByUserNum(MYSQL *db, const std::string &user_num)
    {
        std::cout << "[DBHelper] getIDByUserNum() user_num=" << user_num << std::endl;
        std::string sql = "SELECT ID FROM MEMBERSHIP WHERE USER_NUM=" + user_num + " LIMIT 1";
        if (mysql_query(db, sql.c_str()))
        {
            std::cerr << "[DBHelper Error] getIDByUserNum 쿼리 실패: " << mysql_error(db) << std::endl;
            return "";
        }
        MYSQL_RES *res = mysql_store_result(db);
        MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
        std::string id = (row && row[0]) ? row[0] : "";
        if (res)
            mysql_free_result(res);
        if (id.empty())
            std::cerr << "[DBHelper] user_num=" << user_num << " → ID 없음" << std::endl;
        else
            std::cout << "[DBHelper] user_num=" << user_num << " → ID=" << id << std::endl;
        return id;
    }
}

// ============================================================
//  메시지 핸들러
// ============================================================
namespace MsgHandler
{

    // ── REQ_MSG_CHECK_USER: ID(이메일) 존재 확인 ──
    inline void handleCheckUser(int sock, const std::string &body, MYSQL *db)
    {
        std::string id = SimpleJSON::getString(body, MSG_FIELD::RECEIVER);
        std::cout << "[MsgHandler] CHECK_USER: id=" << id << std::endl;
        std::string safe = DBHelper::escape(db, id);

        std::string sql = "SELECT USER_NUM FROM MEMBERSHIP WHERE ID='" + safe + "' LIMIT 1";
        if (mysql_query(db, sql.c_str()))
        {
            std::cerr << "[MsgHandler Error] CHECK_USER 쿼리 실패: " << mysql_error(db) << std::endl;
            NetHelper::sendError(sock, "DB error");
            return;
        }
        MYSQL_RES *res = mysql_store_result(db);
        MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
        bool exists = (row != nullptr);
        int user_num = exists ? std::stoi(row[0]) : 0;
        if (res)
            mysql_free_result(res);

        std::cout << "[MsgHandler] CHECK_USER 결과: " << (exists ? "EXISTS" : "NOT FOUND") << std::endl;

        std::string out = SimpleJSON::Builder()
                              .str(MSG_FIELD::TYPE, MSG_RES::CHECK_USER)
                              .str(MSG_FIELD::RESULT, exists ? MSG_RESULT::OK : MSG_RESULT::NOT_FOUND)
                              .num(MSG_FIELD::EXISTS, exists ? 1 : 0)
                              .num(MSG_FIELD::USER_PK, user_num)
                              .build();
        NetHelper::sendPacket(sock, out);
    }

    // ── REQ_MSG_SEND: 메시지 발송 ──
    inline void handleSend(int sock, const std::string &body, MYSQL *db)
    {
        std::string sender_num_str = SimpleJSON::getNumber(body, MSG_FIELD::USER_PK);
        std::string receiver_id = SimpleJSON::getString(body, MSG_FIELD::RECEIVER);
        std::string content = SimpleJSON::getString(body, MSG_FIELD::CONTENT);

        std::cout << "[MsgHandler] SEND: sender_pk=" << sender_num_str
                  << ", receiver=" << receiver_id << std::endl;

        if (content.size() > 1024)
            content = content.substr(0, 1024);

        // 받는 사람 ID 존재 여부 확인
        std::string safe_recv = DBHelper::escape(db, receiver_id);
        std::string sql_check = "SELECT USER_NUM FROM MEMBERSHIP WHERE ID='" + safe_recv + "' LIMIT 1";
        if (mysql_query(db, sql_check.c_str()))
        {
            std::cerr << "[MsgHandler Error] SEND 수신자 조회 실패: " << mysql_error(db) << std::endl;
            NetHelper::sendError(sock, "DB error");
            return;
        }
        MYSQL_RES *cres = mysql_store_result(db);
        if (!cres || mysql_num_rows(cres) == 0)
        {
            if (cres)
                mysql_free_result(cres);
            std::cerr << "[MsgHandler] SEND 실패: 수신자 없음 (" << receiver_id << ")" << std::endl;
            std::string out = SimpleJSON::Builder()
                                  .str(MSG_FIELD::TYPE, MSG_RES::SEND)
                                  .str(MSG_FIELD::RESULT, MSG_RESULT::NOT_FOUND)
                                  .str(MSG_FIELD::MESSAGE, "Recipient not found")
                                  .build();
            NetHelper::sendPacket(sock, out);
            return;
        }

        // [추가 - 재훈] 수신자 USER_NUM 저장 후 블랙리스트 체크
        MYSQL_ROW crow = mysql_fetch_row(cres);
        int receiver_num = (crow && crow[0]) ? atoi(crow[0]) : -1;
        int sender_num = atoi(sender_num_str.c_str());
        mysql_free_result(cres);

        BlacklistManager bl_checker;
        if (bl_checker.isBlocked(receiver_num, sender_num))
        {
            std::cerr << "[MsgHandler] 차단된 사용자의 메시지 거부: sender=" << sender_num
                      << " → receiver=" << receiver_num << std::endl;
            std::string out = SimpleJSON::Builder()
                                  .str(MSG_FIELD::TYPE, MSG_RES::SEND)
                                  .str(MSG_FIELD::RESULT, MSG_RESULT::FAIL)
                                  .str(MSG_FIELD::MESSAGE, "Blocked by recipient")
                                  .build();
            NetHelper::sendPacket(sock, out);
            return;
        }
        // [추가 끝 - 재훈]

        std::string safe_content = DBHelper::escape(db, content);

        std::string sql =
            "INSERT INTO MESSAGE (SEND_USER, TAKE_USER, DETAIL, READ_STATUS, CREATED_AT, USER_NUM) VALUES (" + sender_num_str + ", '" + safe_recv + "', '" + safe_content + "', 1, NOW(), " + sender_num_str + ")";

        std::cout << "[MsgHandler] MESSAGE INSERT 실행 중..." << std::endl;

        if (mysql_query(db, sql.c_str()))
        {
            std::cerr << "[MsgHandler Error] MESSAGE INSERT 실패!" << std::endl;
            std::cerr << "[MsgHandler Error] 에러 코드  : " << mysql_errno(db) << std::endl;
            std::cerr << "[MsgHandler Error] 에러 메시지: " << mysql_error(db) << std::endl;
            NetHelper::sendError(sock, "Insert failed");
            return;
        }

        std::cout << "[MsgHandler] MESSAGE INSERT 성공!" << std::endl;

        std::string out = SimpleJSON::Builder()
                              .str(MSG_FIELD::TYPE, MSG_RES::SEND)
                              .str(MSG_FIELD::RESULT, MSG_RESULT::OK)
                              .build();
        NetHelper::sendPacket(sock, out);
    }

    // ── REQ_MSG_CHECK_UNREAD: 안읽은 메시지 수 확인 ──
    inline void handleCheckUnread(int sock, const std::string &body, MYSQL *db)
    {
        std::string pk = SimpleJSON::getNumber(body, MSG_FIELD::USER_PK);
        std::string my_id = DBHelper::getIDByUserNum(db, pk);

        if (my_id.empty())
        {
            NetHelper::sendError(sock, "User session invalid");
            return;
        }

        std::string safe_id = DBHelper::escape(db, my_id);
        std::string sql = "SELECT COUNT(*) FROM MESSAGE WHERE TAKE_USER='" + safe_id + "' AND READ_STATUS=1";

        if (mysql_query(db, sql.c_str()))
        {
            NetHelper::sendError(sock, "DB error");
            return;
        }

        MYSQL_RES *res = mysql_store_result(db);
        MYSQL_ROW row = res ? mysql_fetch_row(res) : nullptr;
        int count = (row && row[0]) ? std::stoi(row[0]) : 0;
        if (res)
            mysql_free_result(res);

        std::string out = SimpleJSON::Builder()
                              .str(MSG_FIELD::TYPE, MSG_RES::CHECK_UNREAD)
                              .str(MSG_FIELD::RESULT, MSG_RESULT::OK)
                              .num(MSG_FIELD::UNREAD_COUNT, count)
                              .build();
        NetHelper::sendPacket(sock, out);
    }

    // ── REQ_MSG_LIST: 메시지 목록 조회 ──
    inline void handleList(int sock, const std::string &body, MYSQL *db)
    {
        std::string pk = SimpleJSON::getNumber(body, MSG_FIELD::USER_PK);
        std::string my_id = DBHelper::getIDByUserNum(db, pk);
        int page = std::stoi(SimpleJSON::getNumber(body, MSG_FIELD::PAGE));
        if (page < 1)
            page = 1;
        int offset = (page - 1) * 20; // PAGE_SIZE = 20

        std::string safe_id = DBHelper::escape(db, my_id);

        // 총 개수
        std::string sql_count = "SELECT COUNT(*) FROM MESSAGE WHERE TAKE_USER='" + safe_id + "'";
        mysql_query(db, sql_count.c_str());
        MYSQL_RES *cres = mysql_store_result(db);
        MYSQL_ROW crow = cres ? mysql_fetch_row(cres) : nullptr;
        int total = crow ? std::stoi(crow[0]) : 0;
        mysql_free_result(cres);

        // 목록 (JOIN을 통해 보낸 사람의 ID를 가져옴)
        std::string sql =
            "SELECT m.MESSAGE_NUM, s.ID, m.CREATED_AT, m.READ_STATUS, m.DETAIL "
            "FROM MESSAGE m "
            "JOIN MEMBERSHIP s ON m.SEND_USER = s.USER_NUM "
            "WHERE m.TAKE_USER='" +
            safe_id + "' "
                      "ORDER BY m.CREATED_AT DESC LIMIT 20 OFFSET " +
            std::to_string(offset);

        if (mysql_query(db, sql.c_str()))
        {
            NetHelper::sendError(sock, "List query failed");
            return;
        }

        MYSQL_RES *res = mysql_store_result(db);
        std::string arr = "[";
        bool first = true;
        if (res)
        {
            MYSQL_ROW row;
            while ((row = mysql_fetch_row(res)))
            {
                if (!first)
                    arr += ",";
                arr += SimpleJSON::Builder()
                           .num(MSG_FIELD::MSG_ID, std::stoll(row[0]))     // MESSAGE_NUM
                           .str(MSG_FIELD::SENDER_EMAIL, row[1])           // 보낸사람 ID
                           .str(MSG_FIELD::SENT_AT, row[2])                // CREATED_AT
                           .num(MSG_FIELD::READ_STATUS, std::stoi(row[3])) // READ_STATUS
                           .str(MSG_FIELD::CONTENT, (char *)row[4])        // DETAIL
                           .build();
                first = false;
            }
            mysql_free_result(res);
        }
        arr += "]";

        std::string out = SimpleJSON::Builder()
                              .str(MSG_FIELD::TYPE, MSG_RES::LIST)
                              .str(MSG_FIELD::RESULT, MSG_RESULT::OK)
                              .num(MSG_FIELD::TOTAL, total)
                              .raw(MSG_FIELD::MESSAGES, arr)
                              .build();
        NetHelper::sendPacket(sock, out);
    }

    // ── REQ_MSG_READ: 읽음 처리 ──
    inline void handleRead(int sock, const std::string &body, MYSQL *db)
    {
        std::string msg_id = SimpleJSON::getNumber(body, MSG_FIELD::MSG_ID);
        std::string pk = SimpleJSON::getNumber(body, MSG_FIELD::USER_PK);
        std::string my_id = DBHelper::getIDByUserNum(db, pk);

        std::string sql = "UPDATE MESSAGE SET READ_STATUS=0 WHERE MESSAGE_NUM=" + msg_id +
                          " AND TAKE_USER='" + DBHelper::escape(db, my_id) + "'";
        mysql_query(db, sql.c_str());

        std::string out = SimpleJSON::Builder()
                              .str(MSG_FIELD::TYPE, MSG_RES::READ)
                              .str(MSG_FIELD::RESULT, MSG_RESULT::OK)
                              .build();
        NetHelper::sendPacket(sock, out);
    }

    // ── REQ_MSG_DELETE: 메시지 삭제 ──
    inline void handleDelete(int sock, const std::string &body, MYSQL *db)
    {
        std::string msg_id = SimpleJSON::getNumber(body, MSG_FIELD::MSG_ID);
        std::string pk = SimpleJSON::getNumber(body, MSG_FIELD::USER_PK);
        std::string my_id = DBHelper::getIDByUserNum(db, pk);

        // 보낸 사람(SEND_USER)이 본인이거나 받는 사람(TAKE_USER)이 본인인 경우만 삭제
        std::string sql = "DELETE FROM MESSAGE WHERE MESSAGE_NUM=" + msg_id +
                          " AND (SEND_USER=" + pk + " OR TAKE_USER='" + DBHelper::escape(db, my_id) + "')";
        mysql_query(db, sql.c_str());

        std::string out = SimpleJSON::Builder()
                              .str(MSG_FIELD::TYPE, MSG_RES::DELETE_MSG)
                              .str(MSG_FIELD::RESULT, MSG_RESULT::OK)
                              .build();
        NetHelper::sendPacket(sock, out);
    }

    inline void clientWorker(int client_sock)
    {
        std::cout << "[MsgServer] 클라이언트 연결됨: sock=" << client_sock << std::endl;
        while (true)
        {
            std::string body = NetHelper::recvPacket(client_sock);
            if (body.empty())
            {
                std::cout << "[MsgServer] 패킷 수신 종료 또는 연결 끊김 (sock=" << client_sock << ")" << std::endl;
                break;
            }

            std::string type = SimpleJSON::getString(body, MSG_FIELD::TYPE);
            std::cout << "[MsgServer] 요청 수신: type=" << type << " (sock=" << client_sock << ")" << std::endl;

            MYSQL *db = DBHelper::connect();
            if (!db)
            {
                std::cerr << "[MsgServer] DB 연결 실패 → 요청 처리 불가 (type=" << type << ")" << std::endl;
                NetHelper::sendError(client_sock, "DB connection failed");
                break;
            }

            if (type == MSG_REQ::CHECK_USER)
                handleCheckUser(client_sock, body, db);
            else if (type == MSG_REQ::SEND)
                handleSend(client_sock, body, db);
            else if (type == MSG_REQ::CHECK_UNREAD)
                handleCheckUnread(client_sock, body, db);
            else if (type == MSG_REQ::LIST)
                handleList(client_sock, body, db);
            else if (type == MSG_REQ::READ)
                handleRead(client_sock, body, db);
            else if (type == MSG_REQ::DELETE_MSG)
                handleDelete(client_sock, body, db);
            else
            {
                std::cerr << "[MsgServer] 알 수 없는 요청 타입: " << type << std::endl;
            }

            mysql_close(db);
            std::cout << "[MsgServer] 요청 처리 완료: type=" << type << std::endl;
        }
        std::cout << "[MsgServer] 클라이언트 소켓 종료: sock=" << client_sock << std::endl;
        close(client_sock);
    }
}

// ============================================================
//  서버 메인 실행부
// ============================================================
inline int serverMain()
{
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MSG_SERVER::PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        return -1;
    listen(server_sock, 10);

    std::cout << "[MsgServer] Running on port " << MSG_SERVER::PORT << "..." << std::endl;

    while (true)
    {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock > 0)
        {
            std::thread(MsgHandler::clientWorker, client_sock).detach();
        }
    }
    return 0;
}