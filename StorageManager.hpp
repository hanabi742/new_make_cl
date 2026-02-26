#pragma once

#include <map>
#include <random>
#include <curl/curl.h> // [추가] libcurl 헤더
#include <set>
#include <ctime>    
#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <mariadb/mysql.h>
#include <nlohmann/json.hpp> // JSON 라이브러리 추가
#include "Protocol.hpp"

using namespace std;
namespace fs = std::filesystem;
using json = nlohmann::json;

class StorageManager
{
private:
    fs::path uploading_root;
    fs::path server_root;
    std::mutex mtx;

    MYSQL* conn; // [추가] DB 연결 객체

    // [내부 함수] 특정 유저의 파일 리스트(JSON)를 가져오는 함수
    json getFileListJson(int user_pk)
    {
        fs::path db_path = server_root / std::to_string(user_pk) / "files.json";
        if (!fs::exists(db_path))
            return json::array(); // 파일이 없으면 빈 배열 반환

        std::ifstream ifs(db_path);
        json j;
        ifs >> j;
        return j;
    }

    // [내부 함수] 특정 유저의 파일 리스트(JSON)를 저장하는 함수
    void saveFileListJson(int user_pk, const json &j)
    {
        fs::path db_path = server_root / std::to_string(user_pk) / "files.json";
        std::ofstream ofs(db_path);
        ofs << j.dump(4); // 보기 좋게 저장
    }

public:
    StorageManager()
    {
        uploading_root = fs::path(STORAGE_ROOT) / "uploading";
        server_root = fs::path(STORAGE_ROOT) / "server";
        // DB 연결 초기화
        conn = mysql_init(NULL);
        if (mysql_real_connect(conn, "10.10.20.101", "JIHOON", "1234", "USERS", 0, NULL, 0) == NULL)
        {
            cerr << "[Storage DB Error] " << mysql_error(conn) << endl;
            conn = nullptr;
        }
        else
        {
            mysql_set_character_set(conn, "utf8mb4");
            cout << "[StorageDB] USERS DB 연결 성공!" << endl;
        }
    }

    ~StorageManager()
    {
        if (conn)
        {
            mysql_close(conn);
            conn = nullptr;
        }
    }

    // ── [핵심] MEMBERSHIP 테이블에서 유저 등급(GRADE) 조회 ──────────────────
    // MEMBERSHIP 테이블에 GRADE 컬럼이 없을 경우 기본값 '일반' 반환
    string getUserGrade(int user_pk)
    {
        if (!conn) return "일반";

        char query[256];
        snprintf(query, sizeof(query),
            "SELECT GRADE FROM MEMBERSHIP WHERE USER_NUM = %d", user_pk);

        if (mysql_query(conn, query))
        {
            cerr << "[DB Grade Error] " << mysql_error(conn) << endl;
            return "일반";
        }

        MYSQL_RES* result = mysql_store_result(conn);
        if (!result) return "일반";

        MYSQL_ROW row = mysql_fetch_row(result);
        string grade = (row && row[0]) ? string(row[0]) : "일반";
        mysql_free_result(result);
        return grade;
    }

    // ── [핵심] FILE_PATH 테이블에 7개 컬럼 전체 INSERT ─────────────────────
    // FILE_PK: auto_increment (자동)
    // USER_NUM, ORIGINAL_NAME, SERVER_PATH, FILE_SIZE, CREATED_AT, GRADE
    int saveFileMetadataToDB(int user_pk, const string& origin_name,
                             const string& server_path, long long file_size,
                             const string& grade)
    {
        if (!conn)
        {
            cerr << "[DB Error] DB 연결이 없어 FILE_PATH INSERT 불가" << endl;
            return -1;
        }

        // SQL Injection 방지: 각 문자열 필드 이스케이프 처리
        char safe_name[512];
        char safe_path[1025];
        char safe_grade[41];

        mysql_real_escape_string(conn, safe_name,  origin_name.c_str(),  origin_name.size());
        mysql_real_escape_string(conn, safe_path,  server_path.c_str(),  server_path.size());
        mysql_real_escape_string(conn, safe_grade, grade.c_str(),         grade.size());

        char query[2048];
        // 7개 컬럼: FILE_PK(Auto), USER_NUM, ORIGINAL_NAME, SERVER_PATH,
        //           FILE_SIZE, CREATED_AT(NOW()), GRADE
        snprintf(query, sizeof(query),
            "INSERT INTO FILE_PATH "
            "(USER_NUM, ORIGINAL_NAME, SERVER_PATH, FILE_SIZE, CREATED_AT, GRADE) "
            "VALUES (%d, '%s', '%s', %lld, NOW(), '%s')",
            user_pk, safe_name, safe_path, file_size, safe_grade);

        if (mysql_query(conn, query))
        {
            cerr << "[DB Insert Error] FILE_PATH INSERT 실패: "
                 << mysql_error(conn) << endl;
            return -1;
        }

        int new_file_pk = (int)mysql_insert_id(conn);
        cout << "[DB] FILE_PATH INSERT 성공! FILE_PK: " << new_file_pk << endl;
        return new_file_pk;
    }

    void initStorage()
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (!fs::exists(uploading_root))
            fs::create_directories(uploading_root);
        if (!fs::exists(server_root))
            fs::create_directories(server_root);
    }

    bool createUserDirectory(int user_pk)
    {
        std::lock_guard<std::mutex> lock(mtx);
        try
        {
            fs::create_directories(uploading_root / std::to_string(user_pk));
            fs::create_directories(server_root / std::to_string(user_pk));
            return true;
        }
        catch (const fs::filesystem_error &e)
        {
            return false;
        }
    }

    // [수정] 구조체 대신 개별 인자를 받아 조각 저장
    bool saveTempChunk(int user_pk, int file_pk, const char *data, size_t size)
    {
        fs::path target_path = uploading_root / std::to_string(user_pk) / (std::to_string(file_pk) + ".tmp");
        std::ofstream ofs(target_path, std::ios::binary | std::ios::app);
        if (!ofs.is_open())
            return false;

        ofs.write(data, size);
        ofs.close();
        return true;
    }

    // 파일 전송 완료 후 파일 이동 + JSON + DB(FILE_PATH) 기록
    // ※ out_db_file_pk: DB에 삽입된 FILE_PK를 돌려받을 포인터 (불필요하면 nullptr 전달)
    bool moveFileToFinal(int user_pk, int file_pk,
                         const std::string &original_name, size_t file_size,
                         int* out_db_file_pk = nullptr)
    {
        std::lock_guard<std::mutex> lock(mtx);
        fs::path src  = uploading_root / std::to_string(user_pk) / (std::to_string(file_pk) + ".tmp");
        fs::path dest = server_root    / std::to_string(user_pk) / (std::to_string(file_pk) + ".dat");

        try
        {
            // ── 1. 실제 파일 이동 ────────────────────────────────────────────
            if (fs::exists(dest))
                fs::remove(dest);
            fs::rename(src, dest);

            // ── 2. JSON 메타데이터 기록 (파일 이름·크기 등) ─────────────────
            json file_list = getFileListJson(user_pk);
            json new_file  = {
                {"file_pk",     file_pk},
                {"file_name",   original_name},
                {"file_size",   file_size},
                {"upload_date", "now"}   // 참고용, DB에는 NOW()로 들어감
            };
            file_list.push_back(new_file);
            saveFileListJson(user_pk, file_list);

            // ── 3. DB FILE_PATH 테이블 INSERT (7개 컬럼 전체) ───────────────
            // SERVER_PATH: 실제 저장된 경로를 문자열로 저장
            string server_path = dest.string();

            // GRADE: MEMBERSHIP 테이블에서 실시간 조회
            string grade = getUserGrade(user_pk);

            int db_pk = saveFileMetadataToDB(
                user_pk,
                original_name,
                server_path,
                (long long)file_size,
                grade
            );

            if (out_db_file_pk)
                *out_db_file_pk = db_pk;

            if (db_pk < 0)
                cerr << "[Warning] 파일은 저장됐지만 DB 기록 실패 (file_pk=" << file_pk << ")" << endl;

            return true;   // 파일 자체는 성공적으로 이동됐으므로 true 반환
        }
        catch (const fs::filesystem_error &e)
        {
            cerr << "[Storage Error] moveFileToFinal: " << e.what() << endl;
            return false;
        }
    }

    // [추가] 유저의 파일 리스트를 JSON 문자열로 반환 (클라이언트에게 목록 쏴줄 때 사용)
    std::string getUserFileList(int user_pk)
    {
        json j = getFileListJson(user_pk);
        return j.dump();
    }

    // [기존 유지] 실제 데이터 읽기/크기 구하기 등은 바이너리 성능을 위해 유지
    size_t getFileSize(int user_pk, int file_pk)
    {
        fs::path target_path = server_root / std::to_string(user_pk) / (std::to_string(file_pk) + ".dat");
        return fs::exists(target_path) ? fs::file_size(target_path) : 0;
    }

    size_t readFileChunk(int user_pk, int file_pk, size_t offset, char *buffer)
    {
        fs::path target_path = server_root / std::to_string(user_pk) / (std::to_string(file_pk) + ".dat");
        std::ifstream ifs(target_path, std::ios::binary);
        if (!ifs.is_open())
            return 0;
        ifs.seekg(offset);
        ifs.read(buffer, 8192);
        return ifs.gcount();
    }
    // [사용량 계산] 유저 폴더 내의 모든 .dat 파일 크기를 합산하여 현재 총 사용량을 바이트 단위로 반환합니다.
    size_t getUserTotalUsed(int user_pk)
    {
        size_t total = 0;
        // 해당 유저의 최종 저장 폴더 경로 설정 (예: ./storage/server/101)
        fs::path user_dir = server_root / std::to_string(user_pk);

        if (fs::exists(user_dir))
        {
            // 폴더 내의 모든 파일을 순회합니다.
            for (const auto &entry : fs::directory_iterator(user_dir))
            {
                // 일반 파일이면서 확장자가 .dat인 파일들의 크기만 합산합니다.
                if (fs::is_regular_file(entry) && entry.path().extension() == ".dat")
                {
                    total += fs::file_size(entry.path());
                }
            }
        }
        return total;
    }
};