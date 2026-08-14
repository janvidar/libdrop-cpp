#
## Tests for libdrop-cpp
#
# The exotic suite, the same framework Samurai and QuickDC build theirs through.
# It arrives one of three ways: already defined, because whoever is building
# added it; from a checkout beside this one; or as an installed package. When
# none of those works the suite is skipped rather than failing the build, since
# a checkout without it can still produce the library.
#
# Beside this one rather than inside Samurai. Exotic belongs to whoever is
# building rather than to any one of the libraries built through it, so a copy
# owned by one of them would be a copy the others reach inside a sibling's
# vendor directory for.
#

set(EXOTIC_SOURCE_DIR "${PROJECT_SOURCE_DIR}/../exotic" CACHE PATH
    "Where the exotic test framework is checked out, when it is not installed")

if(NOT COMMAND exotic_add_tests)
    if(EXISTS "${EXOTIC_SOURCE_DIR}/CMakeLists.txt")
        add_subdirectory("${EXOTIC_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}/exotic")
    else()
        find_package(Exotic QUIET)
    endif()
endif()

if(NOT COMMAND exotic_add_tests)
    message(STATUS
        "libdrop-cpp: exotic not found - skipping the test suite. Clone it beside "
        "this checkout, from the same host this came from, or set "
        "EXOTIC_SOURCE_DIR, or install it.")
    return()
endif()

# MODE AUTO compiles each .tcc as its own translation unit and lets the tests
# register themselves, so nothing is generated.
exotic_add_tests(droptest
    LANGUAGE CXX
    SOURCES
        exotic/decide.tcc
        exotic/natdisc.tcc
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
