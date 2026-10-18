# kista_demo: a C++ extension built with the kista SDK and the test key, for the e2e cases (spec
# 0012 phase 2). It is built in DuckDB's tree at the pin (e2e/build-duckdb.sh, through config.cmake).
cmake_minimum_required(VERSION 3.16)
project(KistaDemoExtension CXX)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../.. kista_sdk)

build_static_extension(kista_demo kista_demo.cpp)
build_loadable_extension(kista_demo "" kista_demo.cpp)
target_link_libraries(kista_demo_loadable_extension kista_sdk_testkey)
target_link_libraries(kista_demo_extension kista_sdk_testkey)
