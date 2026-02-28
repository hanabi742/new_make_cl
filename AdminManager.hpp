#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <mariadb/mysql.h>
#include "AuthManager.hpp"
#include "StorageManager.hpp"
#include "DBConfig.hpp"

class AdminManager
{
private:
    AuthManager &auth;
    StorageManager &storage;
    MYSQL *conn;

    // 실시간 클라이언트 소켓 관리를 위한 포인터 (접속자 수 파악용)
    std::vector<int> *client_sockets = nullptr;
    std::mutex *v_mtx = nullptr;

    // [설계 1] 서버 전체 임시 클라우드 용량 (1000GB)
    const long long TOTAL_CLOUD_CAPACITY = 1000LL * 1024 * 1024 * 1024;

public:
    AdminManager(AuthManager &a, StorageManager &s) : auth(a), storage(s)
    {
        conn = mysql_init(NULL);
        if (mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, NULL, 0) == NULL)
        {
            std::cerr << "[Admin DB Error] 관리자 DB 연결 실패: " << mysql_error(conn) << std::endl;
            conn = nullptr;
        }
        else
        {
            mysql_set_character_set(conn, "utf8mb4");
            std::cout << "[AdminDB] USERS DB 연결 성공 (관리자 모듈 작동 준비 완료)" << std::endl;
        }
    }

    ~AdminManager()
    {
        if (conn)
        {
            mysql_close(conn);
            conn = nullptr;
        }
    }

    // 서버 메인에서 클라이언트 소켓 리스트를 주입받는 함수
    void setClientList(std::vector<int> *sockets, std::mutex *mtx)
    {
        client_sockets = sockets;
        v_mtx = mtx;
    }

    // ─────────────────────────────────────────────────────────────
    // [시스템 모니터링 기능]
    // ─────────────────────────────────────────────────────────────

    // [설계 4] 현재 접속 중인 클라이언트 수 확인 (Mutex를 활용한 안전한 접근)
    int getCurrentClientCount()
    {
        if (!client_sockets || !v_mtx)
            return 0;

        std::lock_guard<std::mutex> lock(*v_mtx);
        return client_sockets->size();
    }

    // [설계 1] 1000GB 기준 서버 전체 사용량 및 잔여 용량 반환
    void getCloudUsageStatus(long long &out_used_bytes, long long &out_remain_bytes)
    {
        out_used_bytes = 0;
        if (!conn)
            return;

        const char *query = "SELECT SUM(FILE_SIZE) FROM FILE_PATH";
        if (mysql_query(conn, query) == 0)
        {
            MYSQL_RES *result = mysql_store_result(conn);
            if (result)
            {
                MYSQL_ROW row = mysql_fetch_row(result);
                if (row && row[0])
                    out_used_bytes = std::stoll(row[0]);
                mysql_free_result(result);
            }
        }
        out_remain_bytes = TOTAL_CLOUD_CAPACITY - out_used_bytes;
    }

    // ─────────────────────────────────────────────────────────────
    // [보안 및 차단 기능]
    // ─────────────────────────────────────────────────────────────

    // [설계 2] 블랙리스트 추가 (IP와 계정을 동시에 묶어서 완벽 차단)
    bool addCombinedBlacklist(const std::string &ip, int user_pk, const std::string &reason)
    {
        if (!conn)
            return false;

        // 1. IP와 PK를 블랙리스트 테이블에 동시 기록
        char query[512];
        snprintf(query, sizeof(query),
                 "INSERT INTO BLACKLIST (IP_ADDRESS, USER_NUM, REASON) VALUES ('%s', %d, '%s')",
                 ip.c_str(), user_pk, reason.c_str());

        if (mysql_query(conn, query))
        {
            std::cerr << "[Admin Error] 블랙리스트 등록 실패: " << mysql_error(conn) << std::endl;
            return false;
        }

        // 2. 해당 유저의 계정 상태를 BANNED로 즉시 변경
        snprintf(query, sizeof(query), "UPDATE MEMBERSHIP SET STATUS = 'BANNED' WHERE USER_NUM = %d", user_pk);
        mysql_query(conn, query);

        std::cout << "[Admin] 보안 조치 완료: IP(" << ip << ") 및 유저(PK: " << user_pk << ") 동시 차단됨." << std::endl;
        return true;
    }

    // 통합 접근 거부 검증 (접속 시 IP 확인, 로그인 시 PK 추가 확인)
    bool isAccessDenied(const std::string &ip, int user_pk = -1)
    {
        if (!conn)
            return false;

        char query[512];
        if (user_pk == -1)
        {
            snprintf(query, sizeof(query), "SELECT 1 FROM BLACKLIST WHERE IP_ADDRESS = '%s'", ip.c_str());
        }
        else
        {
            // IP가 차단되었거나, 계정이 차단되었거나 둘 중 하나라도 걸리면 접근 거부
            snprintf(query, sizeof(query),
                     "SELECT 1 FROM BLACKLIST WHERE IP_ADDRESS = '%s' OR USER_NUM = %d", ip.c_str(), user_pk);
        }

        if (mysql_query(conn, query))
            return false;

        MYSQL_RES *result = mysql_store_result(conn);
        bool is_blocked = (result && mysql_num_rows(result) > 0);
        mysql_free_result(result);

        return is_blocked;
    }

    // ─────────────────────────────────────────────────────────────
    // [최고 관리자 전용 기능 (PK 1번 제어)]
    // ─────────────────────────────────────────────────────────────

    // 오직 1번 PK만 관리자로 인정
    bool isMasterAdmin(int user_pk)
    {
        return user_pk == 1;
    }

    // [설계 3] PK 1번 비밀번호 검증 후 시스템 전체 초기화
    bool resetSystemWithAuth(int admin_pk, const std::string &input_pw)
    {
        if (!isMasterAdmin(admin_pk) || !conn)
        {
            std::cerr << "[Admin Error] 권한이 없거나 DB에 연결할 수 없습니다." << std::endl;
            return false;
        }

        // 1. 관리자(PK:1)의 비밀번호 해시를 DB에서 가져와 비교 검증
        char auth_query[256];
        snprintf(auth_query, sizeof(auth_query), "SELECT PW FROM MEMBERSHIP WHERE USER_NUM = 1");

        if (mysql_query(conn, auth_query))
            return false;

        MYSQL_RES *res = mysql_store_result(conn);
        MYSQL_ROW row = mysql_fetch_row(res);

        // 데이터가 없거나 비밀번호가 일치하지 않으면 거부
        if (!row || input_pw != row[0])
        {
            std::cout << "[Admin Warning] 관리자 인증 실패: 비밀번호 불일치." << std::endl;
            mysql_free_result(res);
            return false;
        }
        mysql_free_result(res);

        // 2. 인증 성공 시 데이터 소멸 진행 (테이블 구조는 남김)
        std::cout << "[Admin Warning] 비밀번호 인증 완료. 시스템 초기화를 시작합니다..." << std::endl;

        // 외래키 무결성 체크를 임시 해제하고 데이터를 날린 뒤 다시 켭니다.
        const char *queries[] = {
            "SET FOREIGN_KEY_CHECKS = 0",
            "TRUNCATE TABLE FILE_PATH",
            "DELETE FROM MEMBERSHIP WHERE USER_NUM > 1", // PK 1번(운영자) 본인은 삭제 제외
            "TRUNCATE TABLE BLACKLIST",
            "SET FOREIGN_KEY_CHECKS = 1"};

        for (const char *q : queries)
        {
            if (mysql_query(conn, q))
            {
                std::cerr << "[Admin Error] 초기화 중 DB 오류 발생: " << mysql_error(conn) << std::endl;
                return false;
            }
        }

        // 3. 실제 물리적 파일들도 모두 철거
        storage.clearAllPhysicalFiles();
        std::cout << "[Admin] 시스템 전체 초기화가 안전하게 완료되었습니다." << std::endl;
        return true;
    }

    // 1. 전체 공지 메시지 발송 (로그 용도)
    void sendGlobalNotice(const std::string &message)
    {
        std::cout << "[Admin System] 전체 공지 큐 등록: " << message << std::endl;
    }
    // 💡 전체 공지 메시지 발송 및 DB 저장
    void saveGlobalNoticeToDB(int admin_pk, const std::string &message)
    {
        if (!conn)
            return;
        char safe_msg[1024];
        mysql_real_escape_string(conn, safe_msg, message.c_str(), message.size());

        char query[2048];
        // MEMBERSHIP에 있는 모든 유저의 ID를 가져와서 개별 메시지로 일괄 저장합니다!
        snprintf(query, sizeof(query),
                 "INSERT INTO MESSAGE (SEND_USER, TAKE_USER, DETAIL, READ_STATUS, CREATED_AT, USER_NUM) "
                 "SELECT %d, ID, '%s', 1, NOW(), %d FROM MEMBERSHIP",
                 admin_pk, safe_msg, admin_pk);

        if (mysql_query(conn, query))
        {
            std::cerr << "[Admin System] 공지사항 DB 저장 실패: " << mysql_error(conn) << std::endl;
        }
        else
        {
            std::cout << "[Admin System] 전체 공지 DB(MESSAGE 테이블) 저장 완료." << std::endl;
        }
    }
};