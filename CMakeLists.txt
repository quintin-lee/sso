cmake_minimum_required(VERSION 3.16)
project(sso_system
  VERSION 1.3.0
  DESCRIPTION "High-Performance Single Sign-On Service in C"
  LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Compiler Options ────────────────────────────────────────────────────
add_compile_options(
  -Wall
  -Wextra
  -Wpedantic
  -Wno-overlength-strings
  -D_GNU_SOURCE
  -D_POSIX_C_SOURCE=199309L
)

# ── Dependencies ────────────────────────────────────────────────────────
find_package(PkgConfig QUIET)

# Required: libsodium, SQLite3, OpenSSL, libcurl
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(LIBCURL REQUIRED libcurl)

# Optional: libmicrohttpd (preferred HTTP backend)
find_package(PkgConfig QUIET)
pkg_check_modules(MHD libmicrohttpd)
if(MHD_FOUND)
  add_compile_definitions(USE_LIBMICROHTTPD)
  message(STATUS "libmicrohttpd found — using MHD HTTP backend")
else()
  message(STATUS "libmicrohttpd not found — falling back to POSIX socket backend")
endif()

# Optional: PostgreSQL
pkg_check_modules(PQ libpq)
if(PQ_FOUND)
  message(STATUS "libpq found — building with PostgreSQL support")
else()
  message(STATUS "libpq not found — building without PostgreSQL support")
endif()

# Optional: hiredis (Redis)
pkg_check_modules(HIREDIS hiredis)
if(HIREDIS_FOUND)
  message(STATUS "hiredis found — building with Redis support")
else()
  message(STATUS "hiredis not found — building without Redis support")
endif()

# ── Include Directories ─────────────────────────────────────────────────
include_directories(
  ${CMAKE_SOURCE_DIR}/include
  ${SODIUM_INCLUDE_DIRS}
  ${SQLITE3_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIRS}
  ${LIBCURL_INCLUDE_DIRS}
  ${PQ_INCLUDE_DIRS}
  ${HIREDIS_INCLUDE_DIRS}
)

# ── Source Files ────────────────────────────────────────────────────────
set(COMMON_SOURCES
  src/arena.c
  src/config.c
  src/demo.c
  src/dpop.c
  src/group.c
  src/handlers_admin.c
  src/handlers_auth.c
  src/handlers_check.c
  src/handlers_common.c
  src/handlers_pages.c
  src/interactive.c
  src/logger.c
  src/main.c
  src/mfa.c
  src/oauth.c
  src/permission.c
  src/policy.c
  src/ratelimit.c
  src/risk.c
  src/role.c
  src/sso.c
  src/storage_memory.c
  src/storage_postgres.c
  src/storage_redis.c
  src/storage_sqlite.c
  src/token.c
  src/toml.c
  src/user.c
)

set(STRATEGY_SOURCES
  strategies/func_perm.c
  strategies/api_perm.c
  strategies/data_perm.c
  strategies/rbac_perm.c
  strategies/lbac_perm.c
  strategies/loc_perm.c
  strategies/abac_perm.c
)

# HTTP server backend — prefer MHD, fall back to POSIX
if(MHD_FOUND)
  set(SERVER_SOURCES src/server_mhd.c)
else()
  set(SERVER_SOURCES src/server.c)
endif()

set(SSO_SOURCES
  ${COMMON_SOURCES}
  ${STRATEGY_SOURCES}
  ${SERVER_SOURCES}
)

# ── Library Dependencies ────────────────────────────────────────────────
set(SSO_LIBS
  ${SODIUM_LIBRARIES}
  ${SQLITE3_LIBRARIES}
  ${OPENSSL_LIBRARIES}
  ${LIBCURL_LIBRARIES}
)

if(MHD_FOUND)
  list(APPEND SSO_LIBS ${MHD_LIBRARIES})
endif()
if(PQ_FOUND)
  list(APPEND SSO_LIBS ${PQ_LIBRARIES})
endif()
if(HIREDIS_FOUND)
  list(APPEND SSO_LIBS ${HIREDIS_LIBRARIES})
endif()

# ── Main Executable ────────────────────────────────────────────────────
add_executable(${PROJECT_NAME} ${SSO_SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE ${SSO_LIBS})
target_include_directories(${PROJECT_NAME} PRIVATE
  ${SODIUM_INCLUDE_DIRS}
  ${SQLITE3_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIRS}
  ${LIBCURL_INCLUDE_DIRS}
  ${MHD_INCLUDE_DIRS}
  ${PQ_INCLUDE_DIRS}
  ${HIREDIS_INCLUDE_DIRS}
)

# ── Object Library for Tests (all sources except main.c) ────────────────
file(GLOB TEST_SOURCES tests/test_*.c)

set(SSO_LIB_SOURCES ${SSO_SOURCES})
list(REMOVE_ITEM SSO_LIB_SOURCES "src/main.c")

add_library(sso_objects OBJECT ${SSO_LIB_SOURCES})
target_link_libraries(sso_objects PUBLIC ${SSO_LIBS})
target_include_directories(sso_objects PUBLIC
  ${SODIUM_INCLUDE_DIRS}
  ${SQLITE3_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIRS}
  ${LIBCURL_INCLUDE_DIRS}
  ${MHD_INCLUDE_DIRS}
  ${PQ_INCLUDE_DIRS}
  ${HIREDIS_INCLUDE_DIRS}
)

# ── Test Executables ───────────────────────────────────────────────────
foreach(TEST_SRC ${TEST_SOURCES})
  get_filename_component(TEST_NAME ${TEST_SRC} NAME_WE)
  add_executable(${TEST_NAME} ${TEST_SRC} $<TARGET_OBJECTS:sso_objects>)
  target_link_libraries(${TEST_NAME} PRIVATE sso_objects)
endforeach()

# ── Custom Targets ──────────────────────────────────────────────────────
# Test runner
add_custom_target(test
  COMMAND ${CMAKE_COMMAND} -E echo "Running unit tests..."
  COMMAND ${CMAKE_COMMAND} -E echo "---"
  COMMAND for f in ${CMAKE_BINARY_DIR}/test_*\\; do if [ -x "$$f" ]\\; then echo "  $$(basename $$f)" && "$$f" || exit 1\\; fi\\; done
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
  USES_TERMINAL
  COMMENT "Run unit tests"
  VERBATIM
)

# Demo smoke test
add_custom_target(run
  COMMAND ./${PROJECT_NAME}
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

# ── Installation ────────────────────────────────────────────────────────
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
install(FILES sso.toml DESTINATION etc/${PROJECT_NAME})
