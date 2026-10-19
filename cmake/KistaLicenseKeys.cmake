# kista_sdk_license_keys(<target> <pem>...) (spec 0021): the licence keys of an extension built with
# the kista SDK. It takes one to four files, each one public key as `openssl pkey -pubout` writes it
# (a PUBLIC KEY PEM block: SubjectPublicKeyInfo, 64-column base64), and adds to <target> a generated
# source holding them as the key block: the keys the SDK verifies licences with, which kista reads
# from the binary. Call it once for each target that links kista_sdk (the loadable extension and the
# static one); a target that links kista_sdk without it fails to link on the undefined symbol
# kista_sdk_license_keys: hidden, so resolved at link time even in a shared library. (macOS's
# `-undefined dynamic_lookup`, in DuckDB's non-static extension builds, does not see the visibility of
# an undefined symbol: such a build fails to load instead, since no module exports the symbol.) An INTERFACE library takes the source as an interface source, for
# each target that links it to compile (kista_sdk_testkey).
#
# The key block, one constant byte array:
#   "KISTA-LICENSE-KEYS/1\0"   the magic
#   count                      1 byte, 1 to 4
#   per key: length            2 bytes, big-endian, 1 to 2048
#            the key           the PEM, length bytes
#   "\0KISTA-END\0"            the end marker
# This configure step checks the files' form; the SDK at run time and kista at intake check the keys
# themselves (RSA-2048, e = 65537).

function(_kista_sdk_hex_byte value out)
  set(digits "0123456789abcdef")
  math(EXPR hi "${value} / 16")
  math(EXPR lo "${value} % 16")
  string(SUBSTRING "${digits}" ${hi} 1 h)
  string(SUBSTRING "${digits}" ${lo} 1 l)
  set(${out} "${h}${l}" PARENT_SCOPE)
endfunction()

function(kista_sdk_license_keys target)
  set(pems ${ARGN})
  list(LENGTH pems count)
  if(count LESS 1 OR count GREATER 4)
    message(FATAL_ERROR "kista_sdk_license_keys(${target}): takes 1 to 4 PEM files, got ${count}")
  endif()
  if(NOT TARGET ${target})
    message(FATAL_ERROR "kista_sdk_license_keys(${target}): no such target")
  endif()
  get_property(done GLOBAL PROPERTY KISTA_SDK_LICENSE_KEYS_TARGETS)
  list(FIND done ${target} seen)
  if(NOT seen EQUAL -1)
    message(FATAL_ERROR "kista_sdk_license_keys(${target}): called twice for the target")
  endif()
  set_property(GLOBAL APPEND PROPERTY KISTA_SDK_LICENSE_KEYS_TARGETS ${target})

  set(dir ${CMAKE_CURRENT_BINARY_DIR}/kista_sdk_license_keys/${target})
  file(MAKE_DIRECTORY ${dir})
  string(REPEAT "[A-Za-z0-9+/]" 64 full_line)
  # the magic and the count
  set(hex "4b495354412d4c4943454e53452d4b4559532f3100")
  _kista_sdk_hex_byte(${count} b)
  string(APPEND hex "${b}")
  set(names "")
  set(i 0)
  foreach(pem IN LISTS pems)
    get_filename_component(path "${pem}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    if(NOT EXISTS "${path}")
      message(FATAL_ERROR "kista_sdk_license_keys(${target}): ${path} does not exist")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${path}")
    get_filename_component(name "${path}" NAME)
    list(APPEND names "${name}")
    set(bad "kista_sdk_license_keys(${target}): ${path} must hold exactly one public key, as `openssl pkey -pubout` writes it (a PUBLIC KEY PEM block)")

    file(READ "${path}" text)
    string(REPLACE "\r\n" "\n" text "${text}")
    string(STRIP "${text}" text)
    string(REPLACE "\n" ";" lines "${text}")
    list(LENGTH lines n)
    if(n LESS 3)
      message(FATAL_ERROR "${bad}")
    endif()
    math(EXPR last "${n} - 1")
    math(EXPR last_data "${n} - 2")
    list(GET lines 0 first_line)
    list(GET lines ${last} end_line)
    if(NOT first_line STREQUAL "-----BEGIN PUBLIC KEY-----" OR NOT end_line STREQUAL "-----END PUBLIC KEY-----")
      message(FATAL_ERROR "${bad}")
    endif()
    foreach(k RANGE 1 ${last_data})
      list(GET lines ${k} line)
      string(LENGTH "${line}" len)
      if(k LESS last_data)
        if(NOT line MATCHES "^${full_line}$")
          message(FATAL_ERROR "${bad}")
        endif()
      elseif(len GREATER 64 OR NOT line MATCHES "^[A-Za-z0-9+/]+=?=?$")
        message(FATAL_ERROR "${bad}")
      endif()
    endforeach()

    set(key "${text}\n")
    if("${key}" IN_LIST seen_keys)
      message(FATAL_ERROR "kista_sdk_license_keys(${target}): ${path} holds a key given already")
    endif()
    list(APPEND seen_keys "${key}")
    string(LENGTH "${key}" len)
    if(len GREATER 2048)
      message(FATAL_ERROR "kista_sdk_license_keys(${target}): ${path} is longer than 2048 bytes")
    endif()
    file(WRITE "${dir}/key${i}.pem" "${key}")
    file(READ "${dir}/key${i}.pem" key_hex HEX)
    math(EXPR len_hi "${len} / 256")
    math(EXPR len_lo "${len} % 256")
    _kista_sdk_hex_byte(${len_hi} h)
    _kista_sdk_hex_byte(${len_lo} l)
    string(APPEND hex "${h}${l}${key_hex}")
    math(EXPR i "${i} + 1")
  endforeach()
  # the end marker
  string(APPEND hex "004b495354412d454e4400")

  string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," bytes "${hex}")
  string(REPLACE ";" ", " names "${names}")
  set(src "${dir}/license_keys.cpp")
  file(WRITE "${src}.tmp"
"// Generated by kista_sdk_license_keys(${target}) from ${names}: the target's licence keys, the
// key block that the kista SDK verifies licences with and that kista reads from the binary
// (spec 0021). Do not edit; change the key files and reconfigure.
// Hidden: the block is the target's own, never exported, never bound to another module's. Used and
// retained: no linker drops it, so kista finds it in the binary.
#if defined(__has_attribute)
#if __has_attribute(retain)
#define KISTA_SDK_RETAIN __attribute__((retain))
#endif
#endif
#ifndef KISTA_SDK_RETAIN
#define KISTA_SDK_RETAIN
#endif
#if defined(__GNUC__) || defined(__clang__)
#define KISTA_SDK_HIDDEN __attribute__((visibility(\"hidden\")))
#define KISTA_SDK_KEYS __attribute__((used)) KISTA_SDK_RETAIN KISTA_SDK_HIDDEN
#else
#define KISTA_SDK_HIDDEN
#define KISTA_SDK_KEYS
#endif
extern \"C\" {
extern KISTA_SDK_HIDDEN const unsigned char kista_sdk_license_keys[];
KISTA_SDK_KEYS const unsigned char kista_sdk_license_keys[] = {${bytes}};
}
")
  configure_file("${src}.tmp" "${src}" COPYONLY)

  get_target_property(type ${target} TYPE)
  if(type STREQUAL "INTERFACE_LIBRARY")
    target_sources(${target} INTERFACE "${src}")
  else()
    target_sources(${target} PRIVATE "${src}")
  endif()
  if(type STREQUAL "STATIC_LIBRARY")
    # The block is an archive member nothing in the extension's own objects refers to: a linker that
    # scans each archive once (GNU ld) would pass it before kista_sdk asks for it. Whatever links the
    # static target pulls it in by name (and two keyed extensions in one binary then clash, loudly).
    if(MSVC)
      target_link_options(${target} INTERFACE "/INCLUDE:kista_sdk_license_keys")
    elseif(APPLE)
      target_link_options(${target} INTERFACE "LINKER:-u,_kista_sdk_license_keys")
    else()
      target_link_options(${target} INTERFACE "LINKER:-u,kista_sdk_license_keys")
    endif()
  endif()
endfunction()
