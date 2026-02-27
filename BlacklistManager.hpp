#pragma once
// ═══════════════════════════════════════════════════════════════════════════
//  BlacklistManager.hpp
//  블랙리스트 추가 / 삭제 / 조회 / 차단 여부 확인 을 담당하는 클래스
//
//  DB 테이블: BLACKLIST
//    blacklist_num  INT  PK AUTO_INCREMENT
//    target_user_num INT  FK → MEMBERSHIP.user_num  (차단 당한 사람)
//    self_user_num   INT  FK → MEMBERSHIP.user_num  (차단 한 사람)
//    created_at      DATETIME
// ═══════════════════════════════════════════════════════════════════════════
#include <iostream>
#include <string>
#include <vector>
#include <mariadb/mysql.h>
#include "DBConfig.hpp"

using namespace std;

// 조회 결과 한 행을 담는 구조체
struct BlacklistEntry {
    int    blacklist_num;
    int    target_user_num;
    string target_email;   // MEMBERSHIP.ID (이메일)
    string created_at;
};

class BlacklistManager {
private:
    MYSQL* db_conn;

    // ── DB 연결 / 재연결 ─────────────────────────────────────────────────────
    bool initDB()
    {
        db_conn = mysql_init(NULL);
        if (!db_conn) {
            cerr << "[BL DB Error] mysql_init 실패" << endl;
            return false;
        }
        if (!mysql_real_connect(db_conn, DB_HOST, DB_USER, DB_PASS, DB_NAME,
                                0, NULL, 0)) {
            cerr << "[BL DB Error] 연결 실패: " << mysql_error(db_conn) << endl;
            mysql_close(db_conn);
            db_conn = nullptr;
            return false;
        }
        mysql_set_character_set(db_conn, "utf8mb4");
        cout << "[BlacklistManager] DB 연결 성공" << endl;
        return true;
    }

    bool ensureConnected()
    {
        if (!db_conn) return initDB();
        if (mysql_ping(db_conn) != 0) {
            mysql_close(db_conn);
            db_conn = nullptr;
            return initDB();
        }
        return true;
    }

public:
    BlacklistManager()  { db_conn = nullptr; initDB(); }
    ~BlacklistManager() { if (db_conn) { mysql_close(db_conn); db_conn = nullptr; } }

    // ─────────────────────────────────────────────────────────────────────────
    // 블랙리스트 추가
    //  self_user_num  : 차단하는 사람 (나)
    //  target_email   : 차단할 상대방의 이메일(ID)
    //
    // 반환값:
    //   1  : 추가 성공
    //   0  : 상대방 이메일을 DB에서 찾을 수 없음
    //  -1  : 자기 자신을 차단하려 했음
    //  -2  : 이미 블랙리스트에 등록된 상대
    //  -3  : DB 오류
    // ─────────────────────────────────────────────────────────────────────────
    int addBlacklist(int self_user_num, const string& target_email)
    {
        if (!ensureConnected()) return -3;

        // ① 상대방 user_num 조회
        char safe_email[129];
        mysql_real_escape_string(db_conn, safe_email,
                                 target_email.c_str(), target_email.size());

        char q[512];
        snprintf(q, sizeof(q),
            "SELECT USER_NUM FROM MEMBERSHIP WHERE ID='%s'", safe_email);

        if (mysql_query(db_conn, q)) {
            cerr << "[BL] 이메일 조회 오류: " << mysql_error(db_conn) << endl;
            return -3;
        }
        MYSQL_RES* res = mysql_store_result(db_conn);
        if (!res) return -3;

        MYSQL_ROW row = mysql_fetch_row(res);
        if (!row || !row[0]) {
            mysql_free_result(res);
            cout << "[BL] 존재하지 않는 이메일: " << target_email << endl;
            return 0;   // 이메일 없음
        }
        int target_num = atoi(row[0]);
        mysql_free_result(res);

        // ② 자기 자신 차단 방지
        if (target_num == self_user_num) {
            cout << "[BL] 자기 자신 차단 시도 거부" << endl;
            return -1;
        }

        // ③ 중복 확인
        snprintf(q, sizeof(q),
            "SELECT COUNT(*) FROM BLACKLIST "
            "WHERE SELF_USER_NUM=%d AND TARGET_USER_NUM=%d",
            self_user_num, target_num);

        if (mysql_query(db_conn, q)) {
            cerr << "[BL] 중복 확인 오류: " << mysql_error(db_conn) << endl;
            return -3;
        }
        res = mysql_store_result(db_conn);
        if (!res) return -3;

        row = mysql_fetch_row(res);
        int already = (row && row[0]) ? atoi(row[0]) : 0;
        mysql_free_result(res);

        if (already > 0) {
            cout << "[BL] 이미 차단된 사용자: " << target_email << endl;
            return -2;  // 이미 등록됨
        }

        // ④ INSERT
        snprintf(q, sizeof(q),
            "INSERT INTO BLACKLIST (SELF_USER_NUM, TARGET_USER_NUM, CREATED_AT) "
            "VALUES (%d, %d, NOW())",
            self_user_num, target_num);

        if (mysql_query(db_conn, q)) {
            cerr << "[BL] INSERT 오류: " << mysql_error(db_conn) << endl;
            return -3;
        }

        cout << "[BL] 차단 추가 성공: self=" << self_user_num
             << " → target=" << target_num
             << " (" << target_email << ")" << endl;
        return 1;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 블랙리스트 삭제
    //  self_user_num    : 차단 해제하는 사람 (나)
    //  blacklist_num    : 삭제할 블랙리스트 항목 PK
    //
    // 반환값:  1=성공  -1=권한 없음 또는 항목 없음  -3=DB 오류
    // ─────────────────────────────────────────────────────────────────────────
    int removeBlacklist(int self_user_num, int blacklist_num)
    {
        if (!ensureConnected()) return -3;

        // 본인 소유 항목인지 확인 후 삭제 (SELF_USER_NUM 일치 조건 포함)
        char q[256];
        snprintf(q, sizeof(q),
            "DELETE FROM BLACKLIST "
            "WHERE BLACKLIST_NUM=%d AND SELF_USER_NUM=%d",
            blacklist_num, self_user_num);

        if (mysql_query(db_conn, q)) {
            cerr << "[BL] DELETE 오류: " << mysql_error(db_conn) << endl;
            return -3;
        }

        unsigned long long affected = mysql_affected_rows(db_conn);
        if (affected == 0) {
            cout << "[BL] 삭제 대상 없음 (PK=" << blacklist_num
                 << ", self=" << self_user_num << ")" << endl;
            return -1;  // 항목 없거나 권한 없음
        }

        cout << "[BL] 차단 해제 성공: BL_PK=" << blacklist_num
             << ", self=" << self_user_num << endl;
        return 1;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 내 블랙리스트 목록 조회
    //  self_user_num : 차단 목록을 조회할 사람 (나)
    //
    // 반환값: vector<BlacklistEntry>
    //  - 비어있으면 블랙리스트 없음 또는 DB 오류
    // ─────────────────────────────────────────────────────────────────────────
    vector<BlacklistEntry> getMyBlacklist(int self_user_num)
    {
        vector<BlacklistEntry> result;
        if (!ensureConnected()) return result;

        char q[512];
        snprintf(q, sizeof(q),
            "SELECT b.BLACKLIST_NUM, b.TARGET_USER_NUM, m.ID, "
            "DATE_FORMAT(b.CREATED_AT, '%%Y-%%m-%%d %%H:%%i') "
            "FROM BLACKLIST b "
            "JOIN MEMBERSHIP m ON m.USER_NUM = b.TARGET_USER_NUM "
            "WHERE b.SELF_USER_NUM = %d "
            "ORDER BY b.CREATED_AT DESC",
            self_user_num);

        if (mysql_query(db_conn, q)) {
            cerr << "[BL] 목록 조회 오류: " << mysql_error(db_conn) << endl;
            return result;
        }

        MYSQL_RES* res = mysql_store_result(db_conn);
        if (!res) return result;

        MYSQL_ROW row;
        while ((row = mysql_fetch_row(res)) != nullptr) {
            BlacklistEntry e;
            e.blacklist_num    = row[0] ? atoi(row[0]) : 0;
            e.target_user_num  = row[1] ? atoi(row[1]) : 0;
            e.target_email     = row[2] ? row[2] : "";
            e.created_at       = row[3] ? row[3] : "";
            result.push_back(e);
        }
        mysql_free_result(res);

        cout << "[BL] 목록 조회: self=" << self_user_num
             << " → " << result.size() << "건" << endl;
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 차단 여부 확인 (메시지 수신 시 필터링 용도)
    //  receiver_num : 수신자 (나)
    //  sender_num   : 발신자 (상대방)
    //
    // 반환값:  true = 차단됨(수신 거부), false = 차단 아님
    // ─────────────────────────────────────────────────────────────────────────
    bool isBlocked(int receiver_num, int sender_num)
    {
        if (!ensureConnected()) return false;

        char q[256];
        snprintf(q, sizeof(q),
            "SELECT COUNT(*) FROM BLACKLIST "
            "WHERE SELF_USER_NUM=%d AND TARGET_USER_NUM=%d",
            receiver_num, sender_num);

        if (mysql_query(db_conn, q)) {
            cerr << "[BL] 차단 확인 오류: " << mysql_error(db_conn) << endl;
            return false;
        }

        MYSQL_RES* res = mysql_store_result(db_conn);
        if (!res) return false;

        MYSQL_ROW row = mysql_fetch_row(res);
        int cnt = (row && row[0]) ? atoi(row[0]) : 0;
        mysql_free_result(res);

        return (cnt > 0);
    }
};
