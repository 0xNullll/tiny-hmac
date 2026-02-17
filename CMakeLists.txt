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

# Create executable
add_executable(hmac_test ${SRC})

# Tiny-SHA feature flags
target_compile_definitions(hmac_test PRIVATE
    ENABLE_SHA1=1
    ENABLE_SHA224=1
    ENABLE_SHA256=1
    ENABLE_SHA384=1
    ENABLE_SHA512=1
    ENABLE_SHA512_224=1
    ENABLE_SHA512_256=1

    ENABLE_SHA3_224=1
    ENABLE_SHA3_256=1
    ENABLE_SHA3_384=1
    ENABLE_SHA3_512=1

    TSHASH_PREFIX=MyLib_
)

# Compiler flags
if(MSVC)
    target_compile_options(hmac_test PRIVATE /W3 /O2 /wd4054 /wd4055)
    # Strip debug symbols in release build
    target_link_options(hmac_test PRIVATE
        $<$<CONFIG:Release>:/DEBUG:NONE /OPT:REF /OPT:ICF>
    )
else()
    target_compile_options(hmac_test PRIVATE -Wall -Wextra -O2 -Wno-cast-function-type)
    # Strip symbols in release build
    target_link_options(hmac_test PRIVATE
        $<$<CONFIG:Release>:-s>
    )
endif()

# Output directory for the binary
set_target_properties(hmac_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
)