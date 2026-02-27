cmake_minimum_required(VERSION 3.10)
project(CloudProject LANGUAGES CXX C)

# ── [1] C++ 표준 및 옵션 설정 ──────────────────────────────
# filesystem 라이브러리 및 최신 문법 사용을 위해 C++17을 지정합니다.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 컴파일 경고 활성화 (디버깅에 유리)
if(NOT MSVC)
    add_compile_options(-Wall -Wextra)
endif()

# ── [2] 외부 의존성 패키지 찾기 ─────────────────────────────
# 1. Threads (pthread)
find_package(Threads REQUIRED)

# 2. OpenSSL (비밀번호 SHA256 해싱용)
find_package(OpenSSL REQUIRED)

# 3. CURL (이메일 전송용)
find_package(CURL REQUIRED)

# 4. MariaDB / MySQL (데이터베이스 연동용)
# 시스템에 설치된 mariadb 클라이언트 라이브러리를 찾습니다.
find_library(MARIADB_LIB NAMES mariadb mysqlclient REQUIRED)

# ── [3] 인클루드 경로 설정 ──────────────────────────────────
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${CURL_INCLUDE_DIRS}
    "/usr/include/mariadb" # 일반적인 리눅스 환경의 MariaDB 헤더 경로
)

# ── [4] 서버(Server) 타겟 생성 ─────────────────────────────
# 서버 실행 파일명: server
add_executable(server 
    server.cpp
)

# 서버가 사용하는 라이브러리 연결
target_link_libraries(server 
    PRIVATE 
    ${MARIADB_LIB}
    ${CURL_LIBRARIES}
    OpenSSL::SSL 
    OpenSSL::Crypto 
    Threads::Threads
    stdc++fs # 구형 gcc에서 filesystem 사용 시 필요
)

# ── [5] 클라이언트(Client) 타겟 생성 ──────────────────────────
# 클라이언트 실행 파일명: client
# client.c 대신 C++로 빌드하기 위해 client.cpp를 소스로 사용합니다.
add_executable(client 
    client.cpp
    msg_client.cpp
)

# 클라이언트가 사용하는 라이브러리 연결
target_link_libraries(client 
    PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    Threads::Threads
    stdc++fs
)

# ── [6] 빌드 후 알림 (선택 사항) ──────────────────────────────
message(STATUS "-----------------------------------------------")
message(STATUS "Cloud Server & Client Build System Ready")
message(STATUS "DB Host: 127.0.0.1") # DBConfig.hpp 설정 기준
message(STATUS "Admin PK: 1 (Master)") # 관리자 권한 기준
message(STATUS "-----------------------------------------------")