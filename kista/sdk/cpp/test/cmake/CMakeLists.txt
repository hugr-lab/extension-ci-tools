# kista_sdk_license_keys' configure checks (the SDK's ctests keyfiles_*): configures with
# -DPEMS=<file>[,<file>...] and fails as the function does.
cmake_minimum_required(VERSION 3.16)
project(kista_sdk_keyfiles NONE)
include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/KistaLicenseKeys.cmake)
add_library(keys INTERFACE)
string(REPLACE "," ";" PEMS "${PEMS}")
kista_sdk_license_keys(keys ${PEMS})
