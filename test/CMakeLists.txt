#
## Tests for libdrop-cpp
#
# The exotic suite, the same framework Samurai and uhub use. It arrives one of
# three ways: already defined, because Samurai was added as a subdirectory and
# brought it in; from a Samurai source tree beside this one; or as an installed
# package. When none of those works the suite is skipped rather than failing
# the build, since a checkout without it can still produce the library.
#

if(NOT COMMAND exotic_add_tests)
    if(DEFINED SAMURAI_SOURCE_DIR AND
       EXISTS "${SAMURAI_SOURCE_DIR}/third_party/exotic/CMakeLists.txt")
        add_subdirectory("${SAMURAI_SOURCE_DIR}/third_party/exotic"
            "${CMAKE_CURRENT_BINARY_DIR}/exotic")
    else()
        find_package(Exotic QUIET)
    endif()
endif()

if(NOT COMMAND exotic_add_tests)
    message(STATUS
        "libdrop-cpp: exotic not found - skipping the test suite. Point "
        "SAMURAI_SOURCE_DIR at a Samurai checkout with its submodules, or "
        "install exotic.")
    return()
endif()

# MODE AUTO compiles each .tcc as its own translation unit and lets the tests
# register themselves, so nothing is generated.
exotic_add_tests(droptest
    LANGUAGE CXX
    SOURCES
        exotic/decide.tcc
        exotic/responder.tcc
        exotic/stun.tcc
        exotic/types.tcc
        exotic/wire.tcc
    LIBRARIES drop::drop
    INCLUDE_DIRECTORIES
        ${CMAKE_CURRENT_SOURCE_DIR}/../src)   # wire.h and pump.h are private

set_target_properties(droptest PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(droptest PRIVATE -Wall -Wextra)
endif()

set_tests_properties(droptest PROPERTIES
    # The responder cases bind listening sockets on the loopback interface;
    # give them room on a loaded machine.
    TIMEOUT 120)
