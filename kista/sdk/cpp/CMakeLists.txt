# kista SDK for C++ DuckDB extensions (spec 0012). Two ways in:
#
# - From an extension built with DuckDB's CMake (the extension template, or DuckDB's own tree):
#   add_subdirectory(<this directory> kista_sdk) and link kista_sdk; DuckDB's include directories
#   and its duckdb_mbedtls target are already there.
# - Standalone, for the SDK's own tests: -DKISTA_DUCKDB_DEPS=<dir>, the directory build-duckdb.sh
#   fills with DuckDB's headers and libraries at e2e/DUCKDB_PIN (e2e/.build/sdk).
#
# kista_sdk holds no licence keys: each target that links it names its own with
# kista_sdk_license_keys(<target> <pem>...) (cmake/KistaLicenseKeys.cmake, spec 0021), or, for tests,
# links kista_sdk_testkey instead: the key block of the licence vectors' test-only key, whose private
# half is in this repository.
cmake_minimum_required(VERSION 3.16)
project(kista_sdk CXX)

set(KISTA_DUCKDB_DEPS "" CACHE PATH "DuckDB's headers and libraries, for a standalone build")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/KistaLicenseKeys.cmake)

add_library(kista_sdk STATIC src/json.cpp src/license.cpp src/crypto.cpp src/keys.cpp src/sdk.cpp)
target_include_directories(kista_sdk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# hidden: an extension's SDK (its keys, its state) is its own, never bound to another module's copy
set_target_properties(kista_sdk PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
if(KISTA_DUCKDB_DEPS)
  target_include_directories(kista_sdk PUBLIC ${KISTA_DUCKDB_DEPS}/include ${KISTA_DUCKDB_DEPS}/third_party/mbedtls/include)
  find_library(KISTA_DUCKDB_MBEDTLS duckdb_mbedtls PATHS ${KISTA_DUCKDB_DEPS}/lib NO_DEFAULT_PATH REQUIRED)
  find_library(KISTA_DUCKDB duckdb PATHS ${KISTA_DUCKDB_DEPS}/lib NO_DEFAULT_PATH REQUIRED)
  # the wrapper's object refers to DuckDB itself (its encryption state): the library resolves it
  target_link_libraries(kista_sdk PUBLIC ${KISTA_DUCKDB_MBEDTLS} ${KISTA_DUCKDB})
elseif(COMMAND build_loadable_extension)
  # in DuckDB's tree (its include directories are global; duckdb_mbedtls is defined later on)
  target_link_libraries(kista_sdk PUBLIC duckdb_mbedtls)
else()
  message(FATAL_ERROR "kista SDK: build it from an extension built with DuckDB's CMake, or set KISTA_DUCKDB_DEPS")
endif()

# kista_sdk_testkey: kista_sdk with the test key's block, compiled into each target that links it
add_library(kista_sdk_testkey INTERFACE)
target_link_libraries(kista_sdk_testkey INTERFACE kista_sdk)
kista_sdk_license_keys(kista_sdk_testkey ${CMAKE_CURRENT_SOURCE_DIR}/test/keys/test-only-2048.pub.pem)

if(KISTA_DUCKDB_DEPS)
  enable_testing()
  add_executable(kista_sdk_vectors test/vectors_test.cpp)
  target_link_libraries(kista_sdk_vectors PRIVATE kista_sdk_testkey)
  add_test(NAME vectors COMMAND kista_sdk_vectors ${CMAKE_CURRENT_SOURCE_DIR}/../../internal/license/testdata/vectors.json)
  # a build with keys of its own trusts them, and no test key; built in the same tree as the vectors'
  add_executable(kista_sdk_trust test/trust_test.cpp)
  target_link_libraries(kista_sdk_trust PRIVATE kista_sdk)
  kista_sdk_license_keys(kista_sdk_trust ${CMAKE_CURRENT_SOURCE_DIR}/test/keys/test-only-untrusted-2048.pub.pem)
  add_test(NAME trust COMMAND kista_sdk_trust)
  # a static target with keys (an extension's static library) links into a binary: its block is
  # pulled in though nothing of its own refers to it
  add_library(kista_sdk_static_ext STATIC test/static_ext.cpp)
  target_link_libraries(kista_sdk_static_ext PUBLIC kista_sdk)
  kista_sdk_license_keys(kista_sdk_static_ext ${CMAKE_CURRENT_SOURCE_DIR}/test/keys/test-only-untrusted-2048.pub.pem)
  add_executable(kista_sdk_static test/static_test.cpp)
  target_link_libraries(kista_sdk_static PRIVATE kista_sdk_static_ext)
  add_test(NAME static COMMAND kista_sdk_static)
  # a target that links kista_sdk without keys does not link, and the error names the function: an
  # executable, and a shared library (on Linux it may leave symbols undefined, but not a hidden one)
  add_executable(kista_sdk_nokeys EXCLUDE_FROM_ALL test/trust_test.cpp)
  target_link_libraries(kista_sdk_nokeys PRIVATE kista_sdk)
  add_library(kista_sdk_nokeys_shared SHARED EXCLUDE_FROM_ALL test/nokeys_shared.cpp)
  target_link_libraries(kista_sdk_nokeys_shared PRIVATE kista_sdk)
  foreach(t kista_sdk_nokeys kista_sdk_nokeys_shared)
    add_test(NAME ${t} COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target ${t})
    set_tests_properties(${t} PROPERTIES PASS_REGULAR_EXPRESSION "kista_sdk_license_keys")
  endforeach()
  # the key files' checks at configure time
  set(keys ${CMAKE_CURRENT_SOURCE_DIR}/test/keys)
  set(i 0)
  foreach(case
      "ok|${keys}/test-only-2048.pub.pem"
      "ok|${keys}/test-only-2048.pub.pem,${keys}/test-only-untrusted-2048.pub.pem"
      "ok|${keys}/crlf.pub.pem"
      "bad|${keys}/wrapped76.pub.pem"
      "bad|${keys}/two-blocks.pub.pem"
      "bad|${CMAKE_CURRENT_SOURCE_DIR}/../../internal/license/testdata/test-only-2048.pem"
      "bad|${keys}/missing.pem"
      "bad|${keys}/test-only-2048.pub.pem,${keys}/crlf.pub.pem"
      "bad|${keys}/big.pub.pem"
      "bad|${keys}/a.pem,${keys}/b.pem,${keys}/c.pem,${keys}/d.pem,${keys}/e.pem"
      "bad|")
    string(REPLACE "|" ";" case "${case}")
    list(GET case 0 want)
    list(GET case 1 pems)
    add_test(NAME keyfiles_${i} COMMAND ${CMAKE_COMMAND} -S ${CMAKE_CURRENT_SOURCE_DIR}/test/cmake
             -B ${CMAKE_CURRENT_BINARY_DIR}/keyfiles_${i} "-DPEMS=${pems}")
    if(want STREQUAL "bad")
      set_tests_properties(keyfiles_${i} PROPERTIES PASS_REGULAR_EXPRESSION "kista_sdk_license_keys\\(keys\\)")
    endif()
    math(EXPR i "${i} + 1")
  endforeach()
endif()
