#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <mariadb/mysql.h>
#include "AuthManager.hpp"
#include "StorageManager.hpp"

class AdminManager
{
private:
    AuthManager &auth;
    StorageManager &storage;
    MYSQL *conn; // 관리자 전용 DB 커넥션 (독립적인 작업 보장)

public:
    AdminManager(AuthManager &a, StorageManager &s) : auth(a), storage(s)
    {
        conn = mysql_init(NULL);
        if (mysql_real_connect(conn, "10.10.20.101", "HEECHANG", "1234", "USERS", 0, NULL, 0) == NULL)
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

    // ─────────────────────────────────────────────────────────────
    // [시스템 관리 기능]
    // ─────────────────────────────────────────────────────────────

    // 1. 전체 공지 메시지 발송
    void sendGlobalNotice(const std::string &message)
    {
        // 실제 소켓 브로드캐스트는 server.cpp 쪽에서 제어합니다.
        std::cout << "[Admin System] 전체 공지 큐 등록: " << message << std::endl;
    }

    // 2. 서버 전체 사용량 모니터링 (객관적 지표)
    long long getTotalServerUsage()
    {
        if (!conn)
            return 0;

        const char *query = "SELECT SUM(FILE_SIZE) FROM FILE_PATH";
        if (mysql_query(conn, query))
        {
            std::cerr << "[Admin DB Error] 사용량 합산 실패: " << mysql_error(conn) << std::endl;
            return 0;
        }

        MYSQL_RES *result = mysql_store_result(conn);
        long long total_usage = 0;

        if (result)
        {
            MYSQL_ROW row = mysql_fetch_row(result);
            if (row && row[0])
            {
                total_usage = std::stoll(row[0]);
            }
            mysql_free_result(result);
        }
        return total_usage;
    }

    // 3. 서버 포트 변경 예약 알림
    void notifyPortChange(int new_port)
    {
        std::cout << "[Admin] 다음 재시작 시 포트가 " << new_port << "로 변경됩니다." << std::endl;
    }

    // 4. [위험] DB 및 파일 전체 초기화
    bool resetSystem()
    {
        if (!conn)
            return false;

        const char *queries[] = {
            "DELETE FROM FILE_PATH",
            "DELETE FROM MEMBERSHIP WHERE USER_NUM > 1", // [수정] USERS -> MEMBERSHIP
            "ALTER TABLE FILE_PATH AUTO_INCREMENT = 1",
            "ALTER TABLE MEMBERSHIP AUTO_INCREMENT = 2" // [수정] USERS -> MEMBERSHIP
        };

        for (const char *q : queries)
        {
            if (mysql_query(conn, q))
            {
                std::cerr << "[Admin Error] 초기화 중 오류: " << mysql_error(conn) << std::endl;
                return false;
            }
        }

        storage.clearAllPhysicalFiles();
        std::cout << "[Admin] 시스템 전체 초기화가 완료되었습니다." << std::endl;
        return true;
    }

    // ─────────────────────────────────────────────────────────────
    // [보안 및 차단 기능]
    // ─────────────────────────────────────────────────────────────

    // 5. 특정 계정(PK) 접속 차단 처리
    bool banUser(int target_user_pk)
    {
        if (!conn)
            return false;

        char check_query[256];
        // [수정] USERS -> MEMBERSHIP
        snprintf(check_query, sizeof(check_query), "SELECT STATUS FROM MEMBERSHIP WHERE USER_NUM = %d", target_user_pk);

        if (mysql_query(conn, check_query))
            return false;

        MYSQL_RES *result = mysql_store_result(conn);
        if (!result || mysql_num_rows(result) == 0)
        {
            std::cout << "[Admin Error] 존재하지 않는 유저 PK입니다." << std::endl;
            if (result)
                mysql_free_result(result);
            return false;
        }
        mysql_free_result(result);

        char query[256];
        // [수정] USERS -> MEMBERSHIP
        snprintf(query, sizeof(query), "UPDATE MEMBERSHIP SET STATUS = 'BANNED' WHERE USER_NUM = %d", target_user_pk);

        if (mysql_query(conn, query))
        {
            std::cerr << "[Admin DB Error] 차단 쿼리 실패: " << mysql_error(conn) << std::endl;
            return false;
        }

        std::cout << "[Admin System] 유저(PK: " << target_user_pk << ")의 접속이 차단되었습니다." << std::endl;
        return true;
    }

    // 6. 블랙리스트 추가 (IP와 계정을 동시에 묶어서 차단)
    bool addBlacklist(const std::string &ip, int user_pk, const std::string &reason)
    {
        if (!conn)
            return false;

        char query[512];
        snprintf(query, sizeof(query),
                 "INSERT INTO BLACKLIST (IP_ADDRESS, USER_NUM, REASON) VALUES ('%s', %d, '%s')",
                 ip.c_str(), user_pk, reason.c_str());

        if (mysql_query(conn, query))
        {
            std::cerr << "[Admin Error] 블랙리스트 등록 실패: " << mysql_error(conn) << std::endl;
            return false;
        }

        banUser(user_pk); // 아이디도 같이 BANNED 처리

        std::cout << "[Admin] 보안 조치 완료: IP(" << ip << ") 및 유저(" << user_pk << ") 차단됨." << std::endl;
        return true;
    }

    // 7. 통합 접근 거부 검증 (문지기 역할)
    bool isAccessDenied(const std::string &ip, int user_pk = -1)
    {
        if (!conn)
            return false;

        char query[512];
        if (user_pk == -1)
        {
            // 접속 직후 1차 검사 (IP만 확인)
            snprintf(query, sizeof(query), "SELECT 1 FROM BLACKLIST WHERE IP_ADDRESS = '%s'", ip.c_str());
        }
        else
        {
            // 로그인 후 2차 검사 (IP 또는 PK 확인)
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
};