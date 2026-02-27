#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <mariadb/mysql.h>
#include "AuthManager.hpp"
#include "StorageManager.hpp"
#include "Protocol.hpp"
#include "DBConfig.hpp"

class UserManager
{
private:
    AuthManager &auth;
    StorageManager &storage;
    MYSQL *conn; // 유저 정보 관리를 위한 독립적인 DB 커넥션

public:
    UserManager(AuthManager &a, StorageManager &s) : auth(a), storage(s)
    {
        conn = mysql_init(NULL);
        if (mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 0, NULL, 0) == NULL)
        {
            std::cerr << "[User DB Error] 유저 DB 연결 실패: " << mysql_error(conn) << std::endl;
            conn = nullptr;
        }
        else
        {
            mysql_set_character_set(conn, "utf8mb4");
            std::cout << "[UserDB] USERS DB 연결 성공 (개인 설정 모듈 작동 준비 완료)" << std::endl;
        }
    }

    ~UserManager()
    {
        if (conn)
        {
            mysql_close(conn);
            conn = nullptr;
        }
    }

    // ─────────────────────────────────────────────────────────────
    // 1. 이메일(ID) 변경 로직 (무결성 검증 포함)
    // 목적: 이메일을 변경하되, 이미 누군가 쓰고 있는 이메일이면 차단합니다.
    // ─────────────────────────────────────────────────────────────
    bool changeUserEmail(int user_pk, const std::string &new_email)
    {
        if (!conn)
            return false;

        // [방어 로직] 1. 새 이메일이 이미 존재하는지 중복 체크
        char check_query[256];
        snprintf(check_query, sizeof(check_query),
                //  "SELECT USER_NUM FROM USERS WHERE EMAIL = '%s'", new_email.c_str());
                "SELECT USER_NUM FROM MEMBERSHIP WHERE EMAIL = '%s'", new_email.c_str());

        if (mysql_query(conn, check_query) == 0)
        {
            MYSQL_RES *result = mysql_store_result(conn);
            if (result && mysql_num_rows(result) > 0)
            {
                std::cout << "[User System] 거부됨: 이미 사용 중인 이메일(" << new_email << ")입니다." << std::endl;
                mysql_free_result(result);
                return false;
            }
            if (result)
                mysql_free_result(result);
        }

        // [실행 로직] 2. PK는 그대로 둔 채 이메일 컬럼만 업데이트
        char query[256];
        snprintf(query, sizeof(query),
                 "UPDATE MEMBERSHIP SET DEFAULT_EMAIL = '%s' WHERE USER_NUM = %d", new_email.c_str(), user_pk);
        
        if (mysql_query(conn, query))
        {
            std::cerr << "[User DB Error] 이메일 변경 실패: " << mysql_error(conn) << std::endl;
            return false;
        }

        std::cout << "[User System] PK(" << user_pk << ")의 이메일이 성공적으로 변경되었습니다." << std::endl;
        return true;
    }

    // ─────────────────────────────────────────────────────────────
    // 2. 비밀번호 변경
    // 목적: 클라이언트에서 SHA-256으로 해싱되어 넘어온 새 비밀번호를 저장합니다.
    // ─────────────────────────────────────────────────────────────
    bool verifyAndUpdatePassword(int user_pk, const std::string& old_pwd_hash, const std::string& new_pwd_hash)
    {
        if (!conn) return false;

        // [단계 1] 현재 비밀번호가 맞는지 먼저 확인 (로그인 로직 응용)
        char check_query[256];
        snprintf(check_query, sizeof(check_query), 
                 "SELECT USER_NUM FROM MEMBERSHIP WHERE USER_NUM = %d AND PW = '%s'", 
                 user_pk, old_pwd_hash.c_str());

        if (mysql_query(conn, check_query) == 0) 
        {
            MYSQL_RES *result = mysql_store_result(conn);
            if (!result || mysql_num_rows(result) == 0) 
            {
                std::cout << "[User System] 비밀번호 변경 거부: 현재 비밀번호 불일치 (PK: " << user_pk << ")" << std::endl;
                if (result) mysql_free_result(result);
                return false; // 비밀번호가 틀림
            }
            mysql_free_result(result);
        }

        // [단계 2] 맞다면 새 비밀번호로 업데이트
        char update_query[256];
        snprintf(update_query, sizeof(update_query), 
                 "UPDATE MEMBERSHIP SET PW = '%s' WHERE USER_NUM = %d", 
                 new_pwd_hash.c_str(), user_pk);

        if (mysql_query(conn, update_query)) {
            std::cerr << "[User DB Error] 업데이트 실패: " << mysql_error(conn) << std::endl;
            return false;
        }

        std::cout << "[User System] 유저(PK: " << user_pk << ")의 비밀번호가 성공적으로 변경되었습니다." << std::endl;
        return true;
    }

    // ─────────────────────────────────────────────────────────────
    // 3. 이름(닉네임) 변경
    // ─────────────────────────────────────────────────────────────
    bool updateUserName(int user_pk, const std::string &new_name)
    {
        if (!conn)
            return false;

        char query[256];
        char safe_name[256];
        mysql_real_escape_string(conn, safe_name, new_name.c_str(), new_name.length());

        snprintf(query, sizeof(query), "UPDATE MEMBERSHIP SET NAME = '%s' WHERE USER_NUM = %d", safe_name, user_pk);

        if (mysql_query(conn, query))
        {
            std::cerr << "[User DB Error] 이름 변경 실패: " << mysql_error(conn) << std::endl;
            return false;
        }
        std::cout << "[User System] 유저(PK: " << user_pk << ")의 이름이 변경되었습니다." << std::endl;
        return true;
    }
    // 등급 올릴시 DB에서 등급 및 용량 변경
    long long getMaxQuota(int user_pk)
    {
        if (!conn)
            return 0;

        char query[256];
        // MEMBERSHIP 테이블에서 현재 등급을 가져옵니다.
        snprintf(query, sizeof(query), "SELECT GRADE FROM MEMBERSHIP WHERE USER_NUM = %d", user_pk);

        if (mysql_query(conn, query))
            return 0;

        MYSQL_RES *result = mysql_store_result(conn);
        std::string grade = "일반"; // 기본값

        if (result && mysql_num_rows(result) > 0)
        {
            MYSQL_ROW row = mysql_fetch_row(result);
            if (row[0])
                grade = row[0];
        }
        if (result)
            mysql_free_result(result);

        // [핵심 로직] 등급에 따른 용량 매핑 (바이트 단위)
        long long MB = 1024 * 1024;
        long long GB = 1024 * MB;

        if (grade == "일반")
            return 100 * MB; // 일반: 100 Mb
        if (grade == "비지니스")
            return 200 * MB; // 프리미엄: 200 MB
        if (grade == "VIP")
            return 500 * MB; // VIP: 500 MB
        if (grade == "VVIP")
            return 1 * GB; // VVIP: 100 GB

        return 100 * MB; // 안전장치 (알 수 없는 등급일 경우 최소 용량)
    }
};