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
        if (v_mtx && client_sockets)
        {
            std::lock_guard<std::mutex> lock(*v_mtx);
            return (int)client_sockets->size();
        }
        return 0;
    }

    // [설계 1] 1000GB 기준 서버 전체 사용량 및 잔여 용량 반환
    void getCloudUsageStatus(long long &out_used, long long &out_remain)
    {
        // 1. 총 할당 용량 (1000GB)
        long long total_limit = 1000LL * 1024 * 1024 * 1024;

        // 2. 현재 모든 유저의 사용량 합산 조회
        const char *query = "SELECT SUM(FILE_SIZE) FROM FILE_PATH";
        out_used = 0;

        if (mysql_query(conn, query) == 0)
        {
            MYSQL_RES *res = mysql_store_result(conn);
            if (res)
            {
                MYSQL_ROW row = mysql_fetch_row(res);
                if (row && row[0])
                    out_used = std::stoll(row[0]);
                mysql_free_result(res);
            }
        }
        out_remain = total_limit - out_used;
    }

    // ─────────────────────────────────────────────────────────────
    // [보안 및 차단 기능]
    // ─────────────────────────────────────────────────────────────

    // [설계 2] 블랙리스트 추가 (IP와 계정을 동시에 묶어서 완벽 차단)
    bool addCombinedBlacklist(int admin_pk, const std::string &ip, int target_pk, const std::string &reason)
    {
        // 1. 권한 검사 (PK 1번이 아니면 즉시 거부)
        if (admin_pk != 1)
        {
            std::cerr << "[Security Alert] 비인가 사용자의 차단 시도!" << std::endl;
            return false;
        }

        if (!conn)
            return false;

        char query[1024];
        // 테이블 구조에 맞춰 쿼리 구성 (BLACKLIST_ID는 auto_increment이므로 제외)
        snprintf(query, sizeof(query),
                 "INSERT INTO ADMIN_BLACKLIST (IP_ADDRESS, USER_NUM, REASON) VALUES ('%s', %d, '%s')",
                 ip.c_str(), target_pk, reason.c_str());

        if (mysql_query(conn, query))
        {
            std::cerr << "[Admin DB Error] 차단 기록 실패: " << mysql_error(conn) << std::endl;
            return false;
        }

        // 추가로 MEMBERSHIP 테이블의 상태도 'BANNED'로 변경 (로그인 차단용)
        char update_query[256];
        snprintf(update_query, sizeof(update_query),
                 "UPDATE MEMBERSHIP SET GRADE = 'BANNED' WHERE USER_NUM = %d", target_pk);
        mysql_query(conn, update_query);

        std::cout << "[Admin] 보안 조치 완료: IP(" << ip << ") 및 유저(" << target_pk << ") 영구 차단." << std::endl;
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
    bool resetSystemWithAuth(int admin_pk, const std::string &input_pwd_hash)
    {
        if (admin_pk != 1)
            return false;

        // DB에서 PK 1번의 실제 비밀번호 해시를 가져와 비교
        char check_query[256];
        snprintf(check_query, sizeof(check_query), "SELECT PW FROM MEMBERSHIP WHERE USER_NUM = 1");

        if (mysql_query(conn, check_query))
            return false;
        MYSQL_RES *res = mysql_store_result(conn);
        if (!res)
            return false;

        MYSQL_ROW row = mysql_fetch_row(res);
        std::string admin_db_pw = (row && row[0]) ? row[0] : "";
        mysql_free_result(res);

        if (input_pwd_hash != admin_db_pw)
        {
            std::cerr << "[Admin] 초기화 거부: 운영자 비밀번호가 일치하지 않습니다." << std::endl;
            return false;
        }

        // 실제 삭제 로직 (TABLE은 남기고 데이터만 소멸)
        const char *cleanup_queries[] = {
            "DELETE FROM FILE_PATH",
            "DELETE FROM MESSAGE",
            "DELETE FROM BLACKLIST",                     // 일반 유저 차단 목록
            "DELETE FROM ADMIN_BLACKLIST",               // 관리자 차단 목록
            "DELETE FROM MEMBERSHIP WHERE USER_NUM > 1", // 관리자 제외 전원 삭제
            "ALTER TABLE FILE_PATH AUTO_INCREMENT = 1",
            "ALTER TABLE MEMBERSHIP AUTO_INCREMENT = 2"};

        for (const char *q : cleanup_queries)
        {
            mysql_query(conn, q);
        }

        storage.clearAllPhysicalFiles(); // 물리적 파일도 삭제
        std::cout << "[Admin] 시스템 전체 초기화가 완료되었습니다." << std::endl;
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