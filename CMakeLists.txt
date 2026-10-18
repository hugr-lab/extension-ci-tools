# kista SDK for C++ DuckDB extensions (spec 0012). Two ways in:
#
# - From an extension built with DuckDB's CMake (the extension template, or DuckDB's own tree):
#   add_subdirectory(<this directory> kista_sdk) and link kista_sdk; DuckDB's include directories
#   and its duckdb_mbedtls target are already there.
# - Standalone, for the SDK's own tests: -DKISTA_DUCKDB_DEPS=<dir>, the directory build-duckdb.sh
#   fills with DuckDB's headers and libraries at e2e/DUCKDB_PIN (e2e/.build/sdk).
#
# Two libraries: kista_sdk trusts the issuer's keys only, and is what an extension links;
# kista_sdk_testkey also trusts the licence vectors' test-only key, whose private half is in this
# repository, so it exists for tests only (built only when a target links it). No option or cache
# setting puts the test key into kista_sdk.
cmake_minimum_required(VERSION 3.16)
project(kista_sdk CXX)

set(KISTA_DUCKDB_DEPS "" CACHE PATH "DuckDB's headers and libraries, for a standalone build")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(KISTA_SDK_SOURCES src/json.cpp src/license.cpp src/crypto.cpp src/keys.cpp)
add_library(kista_sdk STATIC ${KISTA_SDK_SOURCES})
add_library(kista_sdk_testkey STATIC EXCLUDE_FROM_ALL ${KISTA_SDK_SOURCES})
target_compile_definitions(kista_sdk_testkey PRIVATE KISTA_SDK_TEST_KEY)

foreach(lib kista_sdk kista_sdk_testkey)
  target_include_directories(${lib} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
  if(KISTA_DUCKDB_DEPS)
    target_include_directories(${lib} PUBLIC ${KISTA_DUCKDB_DEPS}/include ${KISTA_DUCKDB_DEPS}/third_party/mbedtls/include)
    find_library(KISTA_DUCKDB_MBEDTLS duckdb_mbedtls PATHS ${KISTA_DUCKDB_DEPS}/lib NO_DEFAULT_PATH REQUIRED)
    find_library(KISTA_DUCKDB duckdb PATHS ${KISTA_DUCKDB_DEPS}/lib NO_DEFAULT_PATH REQUIRED)
    # the wrapper's object refers to DuckDB itself (its encryption state): the library resolves it
    target_link_libraries(${lib} PUBLIC ${KISTA_DUCKDB_MBEDTLS} ${KISTA_DUCKDB})
  elseif(TARGET duckdb_mbedtls)
    target_link_libraries(${lib} PUBLIC duckdb_mbedtls)
  else()
    message(FATAL_ERROR "kista SDK: build it from an extension built with DuckDB's CMake, or set KISTA_DUCKDB_DEPS")
  endif()
endforeach()

if(KISTA_DUCKDB_DEPS)
  enable_testing()
  add_executable(kista_sdk_vectors test/vectors_test.cpp)
  target_link_libraries(kista_sdk_vectors PRIVATE kista_sdk_testkey)
  add_test(NAME vectors COMMAND kista_sdk_vectors ${CMAKE_CURRENT_SOURCE_DIR}/../../internal/license/testdata/vectors.json)
  # the library an extension links trusts no test key
  add_executable(kista_sdk_trust test/trust_test.cpp)
  target_link_libraries(kista_sdk_trust PRIVATE kista_sdk)
  add_test(NAME trust COMMAND kista_sdk_trust)
endif()
