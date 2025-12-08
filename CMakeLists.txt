cmake_minimum_required(VERSION 3.20)
project(tiny_hmac_test C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include directories
include_directories(
    tiny-sha/src
)

# Source files
set(SRC
    src/tiny_hmac.c
    tiny-sha/src/tiny_sha.c
    test/hmac_test.c
)

# Output executable
add_executable(hmac_test ${SRC})

# Compiler flags
if(MSVC)
    target_compile_options(hmac_test PRIVATE /W3 /O2 /wd4054 /wd4055)
else()
    target_compile_options(hmac_test PRIVATE -Wall -Wextra -O2 -Wno-cast-function-type)
endif()

# output directory for the binary
set_target_properties(hmac_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
