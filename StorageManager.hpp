#pragma once

#include <map>
#include <random>
#include <curl/curl.h>
#include <set>
#include <ctime>
#include <iostream>
#include <filesystem>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>
#include <mariadb/mysql.h>
#include <nlohmann/json.hpp>
#include "Protocol.hpp"

using namespace std;
namespace fs = std::filesystem;
using json = nlohmann::json;

class StorageManager
{
private:
    fs::path uploading_root;
    fs::path server_root;

    std::mutex mtx;              // 물리적 파일 조작 보호용 뮤텍스
    std::recursive_mutex db_mtx; // 💡 DB 보호용 재귀 뮤텍스 (동시성 크래시 방지)
    MYSQL *conn;

    // ── [안정성 보완] DB 커넥션 유실 방지 (Ping & Reconnect) ──
    void checkConnection()
    {
        if (conn && mysql_ping(conn) != 0)
        {
            std::cout << "[Storage] DB 연결 끊김 감지. 재연결 시도..." << std::endl;
            mysql_real_connect(conn, "10.10.20.101", "JIHOON", "1234", "USERS", 0, NULL, 0);
        }
    }

    // [내부 함수] 특정 유저의 파일 리스트(JSON)를 가져오는 함수
    json getFileListJson(int user_pk)
    {
        fs::path db_path = server_root / std::to_string(user_pk) / "files.json";
        if (!fs::exists(db_path))
            return json::array();

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
        ofs << j.dump(4);
    }

    // DB에서 파일 경로 조회
    string getFilePathFromDB(int user_pk, int file_pk)
    {
        std::lock_guard<std::recursive_mutex> lock(db_mtx);
        if (!conn)
            return "";
        checkConnection();

        char query[512];
        snprintf(query, sizeof(query), "SELECT SERVER_PATH FROM FILE_PATH WHERE USER_NUM = %d AND FILE_PK = %d", user_pk, file_pk);

        if (mysql_query(conn, query))
            return "";

        MYSQL_RES *res = mysql_store_result(conn);
        if (!res)
            return "";

        MYSQL_ROW row = mysql_fetch_row(res);
        string path = (row && row[0]) ? string(row[0]) : "";
        mysql_free_result(res);

        return path;
    }

public:
    StorageManager()
    {
        uploading_root = fs::path(STORAGE_ROOT) / "uploading";
        server_root = fs::path(STORAGE_ROOT) / "server";

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

    string getUserGrade(int user_pk)
    {
        std::lock_guard<std::recursive_mutex> lock(db_mtx);
        if (!conn)
            return "일반";
        checkConnection();

        char query[256];
        snprintf(query, sizeof(query), "SELECT GRADE FROM MEMBERSHIP WHERE USER_NUM = %d", user_pk);

        if (mysql_query(conn, query))
            return "일반";

        MYSQL_RES *result = mysql_store_result(conn);
        if (!result)
            return "일반";

        MYSQL_ROW row = mysql_fetch_row(result);
        string grade = (row && row[0]) ? string(row[0]) : "일반";
        mysql_free_result(result);
        return grade;
    }

    void initStorage()
    {
        std::lock_guard<std::mutex> lock(mtx);
        if (!fs::exists(uploading_root))
            fs::create_directories(uploading_root);
        if (!fs::exists(server_root))
            fs::create_directories(server_root);
    }

    // ── [요건 1] PK값으로 고유 폴더 생성 ──
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

    // ── [요건 2 & 3] 파일 업로드 시 파일명 DB 저장 및 진짜 PK 발급 ──
    int createPendingFileRecord(int user_pk, const string &origin_name, long long file_size)
    {
        std::lock_guard<std::recursive_mutex> lock(db_mtx);
        if (!conn)
            return -1;
        checkConnection();

        char safe_name[512];
        mysql_real_escape_string(conn, safe_name, origin_name.c_str(), origin_name.size());

        string grade = getUserGrade(user_pk);
        char safe_grade[41];
        mysql_real_escape_string(conn, safe_grade, grade.c_str(), grade.size());

        char query[2048];
        snprintf(query, sizeof(query),
                 "INSERT INTO FILE_PATH (USER_NUM, ORIGINAL_NAME, SERVER_PATH, FILE_SIZE, CREATED_AT, GRADE) "
                 "VALUES (%d, '%s', 'pending', %lld, NOW(), '%s')",
                 user_pk, safe_name, file_size, safe_grade);

        if (mysql_query(conn, query))
        {
            cerr << "[DB Error] 레코드 생성 실패: " << mysql_error(conn) << endl;
            return -1;
        }

        return (int)mysql_insert_id(conn); // 이 값이 클라이언트에게 전송될 고유 PK입니다.
    }

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

    // ── [요건 4] 파일이 PK 폴더로 자동 이동되는지 ──
    bool moveFileToFinal(int user_pk, int file_pk, const std::string &original_name, size_t file_size)
    {
        std::lock_guard<std::mutex> lock(mtx);
        fs::path src = uploading_root / std::to_string(user_pk) / (std::to_string(file_pk) + ".tmp");
        fs::path dest = server_root / std::to_string(user_pk) / (std::to_string(file_pk) + ".dat");

        try
        {
            if (fs::exists(dest))
                fs::remove(dest);
            fs::rename(src, dest); // 임시 파일을 최종 PK.dat 로 이동

            // JSON 메타데이터 기록
            json file_list = getFileListJson(user_pk);
            json new_file = {
                {"file_pk", file_pk},
                {"file_name", original_name},
                {"file_size", file_size},
                {"upload_date", "now"}};
            file_list.push_back(new_file);
            saveFileListJson(user_pk, file_list);

            return true;
        }
        catch (const fs::filesystem_error &e)
        {
            cerr << "[Storage Error] moveFileToFinal: " << e.what() << endl;
            return false;
        }
    }

    // ── [요건 3] DB에 최종 경로(SERVER_PATH) 업데이트 ──
    bool finalizeFileRecord(int file_pk, const string &server_path)
    {
        std::lock_guard<std::recursive_mutex> lock(db_mtx);
        if (!conn)
            return false;
        checkConnection();

        char safe_path[1025];
        mysql_real_escape_string(conn, safe_path, server_path.c_str(), server_path.size());

        char query[512];
        snprintf(query, sizeof(query), "UPDATE FILE_PATH SET SERVER_PATH = '%s' WHERE FILE_PK = %d", safe_path, file_pk);

        return mysql_query(conn, query) == 0;
    }

    std::string getUserFileList(int user_pk)
    {
        std::lock_guard<std::mutex> lock(mtx);
        json j = getFileListJson(user_pk);
        return j.dump();
    }

    size_t getFileSize(int user_pk, int file_pk)
    {
        string path = getFilePathFromDB(user_pk, file_pk);
        if (path.empty() || path == "pending" || !fs::exists(path))
            return 0;
        return fs::file_size(path);
    }

    size_t readFileChunk(int user_pk, int file_pk, size_t offset, char *buffer)
    {
        string path = getFilePathFromDB(user_pk, file_pk);
        if (path.empty() || path == "pending" || !fs::exists(path))
            return 0;

        std::ifstream ifs(path, std::ios::binary);
        if (!ifs.is_open())
            return 0;
        ifs.seekg(offset);
        ifs.read(buffer, 8192);
        return ifs.gcount();
    }

    size_t getUserTotalUsed(int user_pk)
    {
        size_t total = 0;
        fs::path user_dir = server_root / std::to_string(user_pk);

        if (fs::exists(user_dir))
        {
            for (const auto &entry : fs::directory_iterator(user_dir))
            {
                if (fs::is_regular_file(entry) && entry.path().extension() == ".dat")
                {
                    total += fs::file_size(entry.path());
                }
            }
        }
        return total;
    }

    // ── [요건 5] 전체 제공량에서 업로드된 용량을 뺀 '남은 용량' 계산 ──
    long long getRemainingQuota(int user_pk, long long max_quota)
    {
        long long used_space = (long long)getUserTotalUsed(user_pk);
        if (max_quota > used_space)
        {
            return max_quota - used_space;
        }
        return 0; // 초과 시 0 반환
    }

    // ── [요건 6] 파일 삭제(다운로드 후 비우기 등) 시 물리 파일 + DB + JSON 제거 (용량 자동 복구) ──
    bool deleteFile(int user_pk, int file_pk)
    {
        bool file_deleted = false;

        // 1. 물리적 파일 및 JSON 데이터 삭제
        {
            std::lock_guard<std::mutex> lock(mtx);
            fs::path target_path = server_root / std::to_string(user_pk) / (std::to_string(file_pk) + ".dat");

            if (fs::exists(target_path))
            {
                fs::remove(target_path); // 디스크에서 삭제되는 순간 남은 용량 복구됨
                file_deleted = true;
            }

            // JSON 파일 갱신 (리스트에서 해당 파일 빼기)
            json file_list = getFileListJson(user_pk);
            json new_list = json::array();
            for (auto &item : file_list)
            {
                if (item["file_pk"] != file_pk)
                {
                    new_list.push_back(item);
                }
            }
            saveFileListJson(user_pk, new_list);
        }

        // 2. DB 기록 삭제
        {
            std::lock_guard<std::recursive_mutex> db_lock(db_mtx);
            if (!conn)
                return false;
            checkConnection();

            char query[256];
            snprintf(query, sizeof(query), "DELETE FROM FILE_PATH WHERE FILE_PK = %d AND USER_NUM = %d", file_pk, user_pk);
            mysql_query(conn, query);
        }

        return file_deleted;
    }

    void clearAllPhysicalFiles()
    {
        std::lock_guard<std::mutex> lock(mtx);
        try
        {
            if (fs::exists(uploading_root))
                for (const auto &entry : fs::directory_iterator(uploading_root))
                    fs::remove_all(entry.path());
            if (fs::exists(server_root))
                for (const auto &entry : fs::directory_iterator(server_root))
                    fs::remove_all(entry.path());
            initStorage();
            std::cout << "[Storage] 모든 물리 파일 초기화 완료." << std::endl;
        }
        catch (const fs::filesystem_error &e)
        {
            std::cerr << "[Storage Error] 파일 삭제 중 오류: " << e.what() << std::endl;
        }
    }
};