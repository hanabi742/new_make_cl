#pragma once
#include <utility>
#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>
#include <map>
#include <random>
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <ctime>
#include <set>
#include <mariadb/mysql.h>

using namespace std;
using namespace std::filesystem;
using json = nlohmann::json;

class AuthManager
{
private:
    path db_file;
    json user_db;
    int next_pk;

    map<string, string>            email_auth_codes;
    map<string, pair<int, time_t>> login_attempts;
    set<string>                    verified_emails;

    MYSQL* db_conn;

    // ── DB 연결 초기화 ────────────────────────────────────────────────────────
    bool initDB()
    {
        cout << "[AuthDB] initDB() 시작... (host=10.10.20.101, user=JIHOON, db=USERS)" << endl;
        db_conn = mysql_init(NULL);
        if (!db_conn)
        {
            cerr << "[AuthDB Error] mysql_init 실패" << endl;
            return false;
        }
        if (!mysql_real_connect(db_conn, "10.10.20.101", "JIHOON", "1234", "USERS", 0, NULL, 0))
        {
            cerr << "[AuthDB Error] DB 연결 실패!" << endl;
            cerr << "[AuthDB Error] 에러 코드  : " << mysql_errno(db_conn) << endl;
            cerr << "[AuthDB Error] 에러 메시지: " << mysql_error(db_conn) << endl;
            cerr << "[AuthDB Error] 힌트) 1045=계정오류 / 1049=DB없음 / 2002=서버꺼짐" << endl;
            mysql_close(db_conn);
            db_conn = nullptr;
            return false;
        }
        mysql_set_character_set(db_conn, "utf8mb4");
        cout << "[AuthDB] USERS DB 연결 성공!" << endl;
        return true;
    }

    // ── DB 재연결 ─────────────────────────────────────────────────────────────
    bool ensureConnected()
    {
        if (!db_conn)
        {
            cerr << "[AuthDB] db_conn 없음 → 재연결 시도..." << endl;
            return initDB();
        }
        if (mysql_ping(db_conn) != 0)
        {
            cerr << "[AuthDB] ping 실패 → 재연결 시도... 에러: " << mysql_error(db_conn) << endl;
            mysql_close(db_conn);
            db_conn = nullptr;
            return initDB();
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DB MEMBERSHIP 기준으로 이메일(ID) 존재 여부 확인
    // ERD: ID VARCHAR(25) → safe 버퍼 26바이트면 충분하나 여유있게 51로 유지
    // ─────────────────────────────────────────────────────────────────────────
    bool isEmailExistsInDB(const string& id)
    {
        if (!ensureConnected())
        {
            cerr << "[AuthDB Error] isEmailExistsInDB: DB 연결 불가" << endl;
            return false;
        }

        // [수정] ERD: ID VARCHAR(25) → 최대 25자, 이스케이프 버퍼 51로 유지
        char safe_id[51];
        mysql_real_escape_string(db_conn, safe_id, id.c_str(), id.size());

        char query[256];
        snprintf(query, sizeof(query),
            "SELECT COUNT(*) FROM MEMBERSHIP WHERE ID = '%s'", safe_id);

        if (mysql_query(db_conn, query))
        {
            cerr << "[AuthDB Error] 이메일 존재 확인 실패: " << mysql_error(db_conn) << endl;
            return false;
        }

        MYSQL_RES* result = mysql_store_result(db_conn);
        if (!result)
        {
            cerr << "[AuthDB Error] store_result 실패: " << mysql_error(db_conn) << endl;
            return false;
        }

        MYSQL_ROW row = mysql_fetch_row(result);
        int count = (row && row[0]) ? atoi(row[0]) : 0;
        mysql_free_result(result);
        cout << "[AuthDB] 이메일 '" << id << "' → " << (count > 0 ? "이미 존재" : "신규") << endl;
        return (count > 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MEMBERSHIP INSERT → 생성된 실제 USER_NUM 반환
    //
    // ERD 기준 컬럼 크기:
    //   NAME  VARCHAR(5)  → safe 버퍼 11
    //   PW    VARCHAR(64) → safe 버퍼 129
    //   ID    VARCHAR(25) → safe 버퍼 51
    // ─────────────────────────────────────────────────────────────────────────
    int insertMembership(const string& id, const string& pwd_hash, const string& name)
    {
        cout << "[AuthDB] insertMembership() 호출: id=" << id << ", name=" << name << endl;

        if (!ensureConnected())
        {
            cerr << "[AuthDB Error] DB 연결 없음 → INSERT 불가 (재연결도 실패)" << endl;
            return -1;
        }

        // [수정] ERD 컬럼 크기에 맞춘 이스케이프 버퍼
        char safe_id[51];    // ID VARCHAR(25) → 이스케이프 여유 포함 51
        char safe_hash[129]; // PW VARCHAR(64) → 이스케이프 여유 포함 129
        char safe_name[11];  // [수정] NAME VARCHAR(5) → 이스케이프 여유 포함 11 (ERD 기준)

        mysql_real_escape_string(db_conn, safe_id,   id.c_str(),       id.size());
        mysql_real_escape_string(db_conn, safe_hash, pwd_hash.c_str(), pwd_hash.size());
        mysql_real_escape_string(db_conn, safe_name, name.c_str(),     name.size());

        // [수정] ERD에 GRADE DEFAULT '일반' 이 있으므로 INSERT 시 명시 불필요 (DB가 자동 설정)
        //        DEFAULT_EMAIL은 NULL 허용이므로 생략
        char query[512];
        snprintf(query, sizeof(query),
            "INSERT INTO MEMBERSHIP (ID, PW, NAME) VALUES ('%s', '%s', '%s')",
            safe_id, safe_hash, safe_name);

        cout << "[AuthDB] INSERT 쿼리 실행 중..." << endl;

        if (mysql_query(db_conn, query))
        {
            cerr << "[AuthDB Error] MEMBERSHIP INSERT 실패!" << endl;
            cerr << "[AuthDB Error] 에러 코드  : " << mysql_errno(db_conn) << endl;
            cerr << "[AuthDB Error] 에러 메시지: " << mysql_error(db_conn) << endl;
            return -1;
        }

        int inserted_num = (int)mysql_insert_id(db_conn);
        cout << "[AuthDB] MEMBERSHIP INSERT 성공! USER_NUM: " << inserted_num << endl;
        return inserted_num;
    }

    // ── DB에서 ID+PW로 실제 USER_NUM 조회 (로그인용) ─────────────────────────
    // ERD: ID VARCHAR(25), PW VARCHAR(64)
    int queryUserNumFromDB(const string& id, const string& pwd_hash)
    {
        cout << "[AuthDB] queryUserNumFromDB() 호출: id=" << id << endl;

        if (!ensureConnected())
        {
            cerr << "[AuthDB Error] DB 연결 없음 → 로그인 조회 불가" << endl;
            return -1;
        }

        char safe_id[51];    // ID VARCHAR(25)
        char safe_hash[129]; // PW VARCHAR(64)
        mysql_real_escape_string(db_conn, safe_id,   id.c_str(),       id.size());
        mysql_real_escape_string(db_conn, safe_hash, pwd_hash.c_str(), pwd_hash.size());

        char query[512];
        snprintf(query, sizeof(query),
            "SELECT USER_NUM FROM MEMBERSHIP WHERE ID='%s' AND PW='%s'",
            safe_id, safe_hash);

        if (mysql_query(db_conn, query))
        {
            cerr << "[AuthDB Error] USER_NUM 조회 실패: " << mysql_error(db_conn) << endl;
            return -1;
        }

        MYSQL_RES* result = mysql_store_result(db_conn);
        if (!result)
        {
            cerr << "[AuthDB Error] store_result 실패: " << mysql_error(db_conn) << endl;
            return -1;
        }

        MYSQL_ROW row = mysql_fetch_row(result);
        int user_num  = (row && row[0]) ? atoi(row[0]) : -1;
        mysql_free_result(result);

        if (user_num > 0)
            cout << "[AuthDB] 로그인 조회 성공: USER_NUM=" << user_num << endl;
        else
            cerr << "[AuthDB] 로그인 조회 실패: 일치하는 계정 없음" << endl;

        return user_num;
    }

    // ── libcurl 이메일 전송 ───────────────────────────────────────────────────
    struct WriteThis { const char *readptr; size_t sizeleft; };

    static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
    {
        WriteThis *upload = (WriteThis *)userp;
        size_t len = size * nmemb;
        if (upload->sizeleft)
        {
            size_t copy = upload->sizeleft;
            if (copy > len) copy = len;
            memcpy(ptr, upload->readptr, copy);
            upload->readptr  += copy;
            upload->sizeleft -= copy;
            return copy;
        }
        return 0;
    }

    bool sendMailViaCurl(const string &target_email, const string &auth_code)
    {
        string my_email     = "taehyunny0312@gmail.com";
        string app_password = "rnwz koev idvf mmna";

        string payload_text =
            "To: "   + target_email + "\r\n" +
            "From: " + my_email     + "\r\n" +
            "Subject: [4erign Cloud] Verification Code\r\n"
            "\r\n"
            "안녕하세요 4(for)eign Cloud 입니다. \n인증번호는: " + auth_code + "\r\n"
            ".\r\n";

        WriteThis upload_data = {payload_text.c_str(), payload_text.size()};
        CURL *curl = curl_easy_init();
        if (!curl) return false;

        curl_easy_setopt(curl, CURLOPT_URL,          "smtps://smtp.gmail.com:465");
        curl_easy_setopt(curl, CURLOPT_USERNAME,     my_email.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD,     app_password.c_str());
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM,    ("<" + my_email + ">").c_str());

        struct curl_slist *recipients =
            curl_slist_append(NULL, ("<" + target_email + ">").c_str());
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT,    recipients);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
        curl_easy_setopt(curl, CURLOPT_READDATA,     &upload_data);
        curl_easy_setopt(curl, CURLOPT_UPLOAD,       1L);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
        return (res == CURLE_OK);
    }

    // ── JSON 로컬 캐시 ────────────────────────────────────────────────────────
    void loadDB()
    {
        ifstream ifs(db_file);
        if (ifs.is_open())
        {
            ifs >> user_db;
            ifs.close();
            next_pk = 1;
            for (auto &[id, info] : user_db.items())
            {
                int current_pk = info["user_pk"];
                if (current_pk >= next_pk) next_pk = current_pk + 1;
            }
        }
        else
        {
            user_db = json::object();
            next_pk = 1;
        }
    }

    void saveDB()
    {
        ofstream ofs(db_file);
        ofs << user_db.dump(4);
        ofs.close();
    }

    string generateAuthCode()
    {
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(100000, 999999);
        return to_string(dis(gen));
    }

public:
    AuthManager()
    {
        db_file = "users.json";
        loadDB();
        initDB();
    }

    ~AuthManager()
    {
        if (db_conn) { mysql_close(db_conn); db_conn = nullptr; }
    }

    bool verifyEmail(const string &email, const string &input_code)
    {
        if (email_auth_codes.count(email) && email_auth_codes[email] == input_code)
        {
            cout << "[Auth] 이메일 인증 성공: " << email << endl;
            email_auth_codes.erase(email);
            verified_emails.insert(email);
            return true;
        }
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 이메일 인증 코드 발송 요청
    // ─────────────────────────────────────────────────────────────────────────
    bool requestEmailAuth(const string &email)
    {
        cout << "[Auth] 인증 메일 요청: " << email << endl;
        if (isEmailExistsInDB(email))
        {
            cerr << "[Auth] 인증 거부: DB에 이미 가입된 이메일 (" << email << ")" << endl;
            return false;
        }

        string code = generateAuthCode();
        cout << "[Auth] 인증 코드 생성 완료, 메일 발송 시도..." << endl;
        if (sendMailViaCurl(email, code))
        {
            email_auth_codes[email] = code;
            cout << "[Auth] 인증 메일 발송 성공: " << email << endl;
            return true;
        }
        cerr << "[Auth] 인증 메일 발송 실패: " << email << endl;
        return false;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 회원가입
    // 반환값: 양수=성공(DB USER_NUM), -1=이미존재, -2=DB오류, -3=인증미완료
    // ─────────────────────────────────────────────────────────────────────────
    int registerUser(const string &id, const string &pwd_hash, const string &name = "")
    {
        cout << "[Auth] registerUser() 호출: id=" << id << ", name=" << name << endl;

        if (verified_emails.find(id) == verified_emails.end())
        {
            cerr << "[Auth] 가입 실패: 인증되지 않은 이메일 (" << id << ")" << endl;
            return -3;
        }
        cout << "[Auth] 이메일 인증 확인 완료" << endl;

        if (isEmailExistsInDB(id))
        {
            cerr << "[Auth] 가입 실패: DB에 이미 존재하는 이메일 (" << id << ")" << endl;
            verified_emails.erase(id);
            return -1;
        }

        int new_db_num = insertMembership(id, pwd_hash, name);
        if (new_db_num < 0)
        {
            cerr << "[Auth] 가입 실패: DB INSERT 오류 (반환값=" << new_db_num << ")" << endl;
            verified_emails.erase(id);
            return -2;
        }

        user_db[id] = {{"user_pk", new_db_num}, {"pwd_hash", pwd_hash}};
        saveDB();
        verified_emails.erase(id);

        cout << "[Auth] 회원가입 성공: " << id << " | USER_NUM: " << new_db_num << endl;
        return new_db_num;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 로그인
    // 반환값: 양수=성공(DB USER_NUM), -1=불일치, -2=잠금
    // ─────────────────────────────────────────────────────────────────────────
    int loginUser(const string &id, const string &pwd_hash)
    {
        cout << "[Auth] loginUser() 호출: id=" << id << endl;
        time_t now = time(nullptr);

        if (login_attempts.count(id))
        {
            if (now < login_attempts[id].second)
            {
                long remain = login_attempts[id].second - now;
                cerr << "[Auth] 잠금 상태 (" << remain << "초 남음): " << id << endl;
                return -2;
            }
            else if (login_attempts[id].second != 0)
                login_attempts[id] = {0, 0};
        }

        int real_user_num = queryUserNumFromDB(id, pwd_hash);

        if (real_user_num > 0)
        {
            login_attempts[id] = {0, 0};
            cout << "[Auth] 로그인 성공! ID: " << id
                 << " | USER_NUM: " << real_user_num << endl;
            return real_user_num;
        }
        else
        {
            login_attempts[id].first++;
            int fails = login_attempts[id].first;
            cerr << "[Auth] 로그인 실패: " << fails << "회 틀림 (id=" << id << ")" << endl;

            if (fails >= 5)
            {
                login_attempts[id].second = now + 180;
                cerr << "[Auth] 5회 오류 → 3분 계정 잠금! (id=" << id << ")" << endl;
                return -2;
            }
            return -1;
        }
    }

    // =========================================================================
    // [추가] 사용자 정보 조회 (개인설정 화면 진입 시 현재 이름/기본이메일 표시)
    //
    // ERD 기준:
    //   NAME          VARCHAR(5)  → out_name 버퍼 최소 6바이트
    //   DEFAULT_EMAIL VARCHAR(64) → out_def_email 버퍼 최소 65바이트
    //
    // 파라미터:
    //   user_pk       - 조회할 USER_NUM (PK)
    //   out_name      - [출력] NAME 컬럼값
    //   out_def_email - [출력] DEFAULT_EMAIL 컬럼값 (미설정 시 빈 문자열)
    //
    // 반환값: true=성공, false=DB오류 or user_pk 없음
    // =========================================================================
    bool getUserInfo(int user_pk, string& out_name, string& out_def_email)
    {
        if (!ensureConnected())
        {
            cerr << "[AuthDB Error] getUserInfo: DB 연결 불가" << endl;
            return false;
        }

        char query[256];
        snprintf(query, sizeof(query),
            // [수정] ERD 컬럼명 그대로 사용: NAME, DEFAULT_EMAIL
            "SELECT NAME, DEFAULT_EMAIL FROM MEMBERSHIP WHERE USER_NUM = %d",
            user_pk);

        if (mysql_query(db_conn, query))
        {
            cerr << "[AuthDB Error] getUserInfo 쿼리 실패: " << mysql_error(db_conn) << endl;
            return false;
        }

        MYSQL_RES* res = mysql_store_result(db_conn);
        if (!res) return false;

        MYSQL_ROW row = mysql_fetch_row(res);
        if (!row)
        {
            mysql_free_result(res);
            cerr << "[AuthDB Error] getUserInfo: USER_NUM=" << user_pk << " 없음" << endl;
            return false;
        }

        out_name      = row[0] ? row[0] : "";
        out_def_email = row[1] ? row[1] : ""; // DEFAULT_EMAIL이 NULL이면 빈 문자열로 처리
        mysql_free_result(res);

        cout << "[Auth] getUserInfo 성공: name=" << out_name
             << ", default_email=" << (out_def_email.empty() ? "(미설정)" : out_def_email)
             << endl;
        return true;
    }

    // =========================================================================
    // [추가] 기본 이메일(발신 이메일) 설정
    //
    // ERD: DEFAULT_EMAIL VARCHAR(64) → 64자 초과 입력 차단
    //
    // 파라미터:
    //   user_pk   - 변경할 USER_NUM
    //   new_email - 새로 설정할 발신 이메일 (최대 64자)
    //
    // 반환값: true=성공, false=실패
    // =========================================================================
    bool updateDefaultEmail(int user_pk, const string& new_email)
    {
        cout << "[Auth] updateDefaultEmail() 호출: user_pk=" << user_pk
             << ", new_email=" << new_email << endl;

        // [수정] ERD: DEFAULT_EMAIL VARCHAR(64) → 64자 초과 시 거부
        if (new_email.size() > 64)
        {
            cerr << "[Auth] updateDefaultEmail: 이메일 64자 초과 (ERD 제한)" << endl;
            return false;
        }

        if (!ensureConnected())
        {
            cerr << "[AuthDB Error] updateDefaultEmail: DB 연결 불가" << endl;
            return false;
        }

        // [수정] DEFAULT_EMAIL VARCHAR(64) → 이스케이프 버퍼 129
        char safe_email[129];
        mysql_real_escape_string(db_conn, safe_email, new_email.c_str(), new_email.size());

        char query[512];
        snprintf(query, sizeof(query),
            "UPDATE MEMBERSHIP SET DEFAULT_EMAIL = '%s' WHERE USER_NUM = %d",
            safe_email, user_pk);

        if (mysql_query(db_conn, query))
        {
            cerr << "[AuthDB Error] DEFAULT_EMAIL UPDATE 실패: "
                 << mysql_error(db_conn) << endl;
            return false;
        }

        if (mysql_affected_rows(db_conn) == 0)
        {
            cerr << "[AuthDB Error] updateDefaultEmail: USER_NUM=" << user_pk << " 없음" << endl;
            return false;
        }

        cout << "[Auth] DEFAULT_EMAIL 변경 성공: USER_NUM=" << user_pk
             << " → " << new_email << endl;
        return true;
    }

    // =========================================================================
    // [추가] 비밀번호 변경
    //
    // ERD: PW VARCHAR(64) → SHA-256 hex(64자) 딱 맞음
    // 현재 비밀번호(old_pwd_hash)가 DB와 일치할 때만 새 비밀번호로 UPDATE.
    // ※ 클라이언트에서 SHA-256 해싱 후 전달 (요구사항 7)
    //
    // 파라미터:
    //   user_pk      - 변경할 USER_NUM
    //   old_pwd_hash - 현재 PW의 SHA-256 hex (64자)
    //   new_pwd_hash - 새 PW의 SHA-256 hex (64자)
    //
    // 반환값:  1=성공, 0=현재PW 불일치, -1=DB 오류
    // =========================================================================
    int updatePassword(int user_pk, const string& old_pwd_hash, const string& new_pwd_hash)
    {
        cout << "[Auth] updatePassword() 호출: user_pk=" << user_pk << endl;

        // [수정] ERD: PW VARCHAR(64) → SHA-256 hex는 정확히 64자, 초과 시 거부
        if (old_pwd_hash.size() != 64 || new_pwd_hash.size() != 64)
        {
            cerr << "[Auth] updatePassword: 해시값 길이 오류 (64자 필요)" << endl;
            return -1;
        }

        if (!ensureConnected())
        {
            cerr << "[AuthDB Error] updatePassword: DB 연결 불가" << endl;
            return -1;
        }

        // 1단계: 현재 비밀번호 일치 여부 확인
        // [수정] PW VARCHAR(64) → 이스케이프 버퍼 129
        char safe_old[129];
        mysql_real_escape_string(db_conn, safe_old, old_pwd_hash.c_str(), old_pwd_hash.size());

        char check_query[512];
        snprintf(check_query, sizeof(check_query),
            "SELECT COUNT(*) FROM MEMBERSHIP WHERE USER_NUM = %d AND PW = '%s'",
            user_pk, safe_old);

        if (mysql_query(db_conn, check_query))
        {
            cerr << "[AuthDB Error] PW 일치 확인 실패: " << mysql_error(db_conn) << endl;
            return -1;
        }

        MYSQL_RES* res = mysql_store_result(db_conn);
        if (!res) return -1;
        MYSQL_ROW row = mysql_fetch_row(res);
        int match = (row && row[0]) ? atoi(row[0]) : 0;
        mysql_free_result(res);

        if (match == 0)
        {
            cerr << "[Auth] updatePassword: 현재 비밀번호 불일치 (USER_NUM=" << user_pk << ")" << endl;
            return 0;
        }

        // 2단계: 새 비밀번호로 UPDATE
        char safe_new[129];
        mysql_real_escape_string(db_conn, safe_new, new_pwd_hash.c_str(), new_pwd_hash.size());

        char update_query[512];
        snprintf(update_query, sizeof(update_query),
            "UPDATE MEMBERSHIP SET PW = '%s' WHERE USER_NUM = %d",
            safe_new, user_pk);

        if (mysql_query(db_conn, update_query))
        {
            cerr << "[AuthDB Error] PW UPDATE 실패: " << mysql_error(db_conn) << endl;
            return -1;
        }

        cout << "[Auth] 비밀번호 변경 성공: USER_NUM=" << user_pk << endl;
        return 1;
    }

    // =========================================================================
    // [추가] 이름 변경
    //
    // ERD: NAME VARCHAR(5) → 5자 초과 입력 차단
    //
    // 파라미터:
    //   user_pk  - 변경할 USER_NUM
    //   new_name - 새 이름 (최대 5자, ERD 기준)
    //
    // 반환값: true=성공, false=실패
    // =========================================================================
    bool updateName(int user_pk, const string& new_name)
    {
        cout << "[Auth] updateName() 호출: user_pk=" << user_pk
             << ", new_name=" << new_name << endl;

        // [수정] ERD: NAME VARCHAR(5) → 5자 초과 시 거부
        if (new_name.empty())
        {
            cerr << "[Auth] updateName: 이름이 비어 있음" << endl;
            return false;
        }
        if (new_name.size() > 5)
        {
            cerr << "[Auth] updateName: 이름 5자 초과 (ERD 제한, 입력=" << new_name.size() << "자)" << endl;
            return false;
        }

        if (!ensureConnected())
        {
            cerr << "[AuthDB Error] updateName: DB 연결 불가" << endl;
            return false;
        }

        // [수정] NAME VARCHAR(5) → 이스케이프 버퍼 11
        char safe_name[11];
        mysql_real_escape_string(db_conn, safe_name, new_name.c_str(), new_name.size());

        char query[512];
        snprintf(query, sizeof(query),
            "UPDATE MEMBERSHIP SET NAME = '%s' WHERE USER_NUM = %d",
            safe_name, user_pk);

        if (mysql_query(db_conn, query))
        {
            cerr << "[AuthDB Error] NAME UPDATE 실패: " << mysql_error(db_conn) << endl;
            return false;
        }

        if (mysql_affected_rows(db_conn) == 0)
        {
            cerr << "[AuthDB Error] updateName: USER_NUM=" << user_pk << " 없음" << endl;
            return false;
        }

        cout << "[Auth] 이름 변경 성공: USER_NUM=" << user_pk << " → " << new_name << endl;
        return true;
    }
};
