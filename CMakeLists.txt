#
## libdrop-cpp: a C++ client for the DROP connectivity checker
#

cmake_minimum_required(VERSION 3.16)

project(libdrop-cpp
    VERSION 0.1.0
    DESCRIPTION "C++ client for DROP, the Diagnostic Reachability & Obstacle Probe"
    LANGUAGES CXX)

option(DROP_BUILD_TOOLS "Build the dropcheck command line tool" ON)
option(DROP_BUILD_TESTS "Build the test suite" ON)

# ---------------------------------------------------------------------------
# Samurai supplies the sockets, the TLS, the HTTP client, the UPnP gateway and
# now the JSON. Either an installed package or a source tree beside this one.
# ---------------------------------------------------------------------------
find_package(samurai QUIET)

if(NOT samurai_FOUND)
    set(SAMURAI_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../samurai"
        CACHE PATH "Path to a Samurai source tree, when it is not installed")
    if(EXISTS "${SAMURAI_SOURCE_DIR}/CMakeLists.txt")
        message(STATUS "libdrop-cpp: building Samurai from ${SAMURAI_SOURCE_DIR}")
        add_subdirectory("${SAMURAI_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/samurai"
            EXCLUDE_FROM_ALL)
    else()
        message(FATAL_ERROR
            "libdrop-cpp: Samurai was not found. Install it, or set "
            "SAMURAI_SOURCE_DIR to a checkout of "
            "ssh://git@gitea.extatic.org:2222/janvidar/samurai.git")
    endif()
endif()

# HMAC-SHA1 and HMAC-SHA256, which STUN short-term credentials need and which
# Samurai's crypto does not yet offer. Samurai links OpenSSL PUBLIC for its TLS,
# so this is already present rather than a dependency of our own; see
# src/hmac.h for the shim that keeps the swap to a future Samurai API local.
find_package(OpenSSL REQUIRED)

# crc32 for the STUN FINGERPRINT attribute. Samurai already requires zlib.
find_package(ZLIB REQUIRED)

set(DROP_SOURCES
    src/types.cpp
    src/decide.cpp
    src/wire.cpp
    src/client.cpp
    src/hmac.cpp
    src/stun.cpp
    src/responder.cpp)

add_library(drop STATIC ${DROP_SOURCES})
add_library(drop::drop ALIAS drop)

target_include_directories(drop
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(drop
    PUBLIC samurai::samurai
    PRIVATE OpenSSL::Crypto ZLIB::ZLIB)

target_compile_features(drop PUBLIC cxx_std_20)
set_target_properties(drop PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(drop PRIVATE -Wall -Wextra)
endif()

# Gated on the sources existing so that a partially populated tree still
# configures; both become unconditional once they are written.
if(DROP_BUILD_TOOLS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/dropcheck/main.cpp"
                   AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/check.cpp")
    add_executable(dropcheck tools/dropcheck/main.cpp)
    target_link_libraries(dropcheck PRIVATE drop::drop)
    set_target_properties(dropcheck PROPERTIES
        CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON CXX_EXTENSIONS OFF)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(dropcheck PRIVATE -Wall -Wextra)
    endif()
endif()

if(DROP_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test/CMakeLists.txt")
    enable_testing()
    add_subdirectory(test)
endif()

install(TARGETS drop EXPORT dropTargets ARCHIVE DESTINATION lib)
install(DIRECTORY include/drop DESTINATION include)
