# ============================================================
# CMakeLists.txt - JWTTokenLib Build Configuration
# ============================================================
#
# Builds JWTTokenLib for both Windows (DLL) and Linux (SO).
#
# WINDOWS BUILD (Developer Command Prompt for VS 2019/2022):
#   mkdir build && cd build
#   cmake .. -G "Visual Studio 17 2022" -A x64 ^
#             -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
#   cmake --build . --config Release
#   Output: build\bin\Release\JWTTokenLib.dll
#
# LINUX BUILD (RedHat / Amazon Linux):
#   Install: sudo dnf install openssl-devel cmake gcc
#   mkdir build && cd build
#   cmake .. -DCMAKE_BUILD_TYPE=Release
#   make -j$(nproc)
#   Output: build/lib/libJWTTokenLib.so
#
# STATIC OPENSSL (Windows, zero-dependency DLL):
#   cmake .. -DOPENSSL_USE_STATIC_LIBS=ON ...
# ============================================================

cmake_minimum_required(VERSION 3.15)

project(JWTTokenLib
    VERSION     1.0.0
    DESCRIPTION "JWT Token Generation Library for LoadRunner Enterprise"
    LANGUAGES   C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ============================================================
# OpenSSL Configuration
# ============================================================
if(WIN32)
    # Default installation path from https://slproweb.com/products/Win32OpenSSL.html
    if(NOT OPENSSL_ROOT_DIR)
        set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64"
            CACHE PATH "OpenSSL installation root directory")
    endif()

    # On Windows, prefer static linking for a self-contained zero-dependency DLL
    option(OPENSSL_USE_STATIC_LIBS "Link OpenSSL statically (Windows)" ON)
    if(OPENSSL_USE_STATIC_LIBS)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
    endif()
endif()

find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL version:  ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include:  ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL SSL lib:  ${OPENSSL_SSL_LIBRARY}")
message(STATUS "OpenSSL crypto:   ${OPENSSL_CRYPTO_LIBRARY}")

# ============================================================
# Source Files
# ============================================================
set(JWTLIB_SOURCES
    src/jwt_core.c
    src/algorithms/hs256.c
    src/algorithms/rs256.c
    src/algorithms/ps256.c
    src/algorithms/es256.c
    src/utils/base64url.c
    src/utils/key_manager.c
    src/bindings/c_exports.c
)

# ============================================================
# Shared Library Target (DLL on Windows, .so on Linux)
# ============================================================
add_library(JWTTokenLib SHARED ${JWTLIB_SOURCES})

target_include_directories(JWTTokenLib
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include    # public jwtlib.h
        ${CMAKE_SOURCE_DIR}/src        # internal jwt_core.h
        ${OPENSSL_INCLUDE_DIR}
)

# JWTLIB_EXPORTS enables __declspec(dllexport) on Windows
target_compile_definitions(JWTTokenLib PRIVATE JWTLIB_EXPORTS)

# ============================================================
# Platform-Specific Settings
# ============================================================
if(WIN32)
    # Output: JWTTokenLib.dll
    set_target_properties(JWTTokenLib PROPERTIES
        OUTPUT_NAME             "JWTTokenLib"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    )

    target_link_libraries(JWTTokenLib
        PRIVATE
            OpenSSL::SSL
            OpenSSL::Crypto
            ws2_32      # Windows sockets (required by OpenSSL)
            crypt32     # Windows crypto API (required by OpenSSL)
    )

    # MSVC compiler flags
    if(MSVC)
        target_compile_options(JWTTokenLib PRIVATE
            /W3         # Warning level 3
            /WX-        # Don't treat warnings as errors
            /O2         # Full optimization
            /GL         # Whole-program optimization
        )
        # Link-time code generation
        target_link_options(JWTTokenLib PRIVATE /LTCG)
    endif()

else()
    # Linux: Output: libJWTTokenLib.so
    set_target_properties(JWTTokenLib PROPERTIES
        OUTPUT_NAME             "JWTTokenLib"
        PREFIX                  "lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        # Embed SONAME for proper runtime linking
        VERSION                 "1.0.0"
        SOVERSION               "1"
    )

    target_link_libraries(JWTTokenLib
        PRIVATE
            OpenSSL::SSL
            OpenSSL::Crypto
    )

    # GCC compiler flags
    target_compile_options(JWTTokenLib PRIVATE
        -Wall
        -Wextra
        -O2
        -fvisibility=hidden    # Hide symbols by default; JWTLIB_API makes them visible
    )

    # Enable position-independent code (required for .so)
    set_target_properties(JWTTokenLib PROPERTIES
        POSITION_INDEPENDENT_CODE ON
    )
endif()

# ============================================================
# Standalone Test Executable
# ============================================================
add_executable(test_jwt tests/test_standalone.c)

target_include_directories(test_jwt
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(test_jwt
    PRIVATE
        JWTTokenLib
)

if(WIN32)
    set_target_properties(test_jwt PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
    target_link_libraries(test_jwt PRIVATE OpenSSL::SSL OpenSSL::Crypto ws2_32 crypt32)
else()
    set_target_properties(test_jwt PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif()

# ============================================================
# Install Rules (for dist/ folder)
# ============================================================
install(TARGETS JWTTokenLib
    RUNTIME DESTINATION dist   # DLL on Windows
    LIBRARY DESTINATION dist   # .so on Linux
)

install(FILES include/jwtlib.h DESTINATION dist/include)

# ============================================================
# Build Summary
# ============================================================
message(STATUS "")
message(STATUS "=== JWTTokenLib Build Configuration ===")
message(STATUS "  Platform:       ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Build type:     ${CMAKE_BUILD_TYPE}")
message(STATUS "  C Compiler:     ${CMAKE_C_COMPILER}")
message(STATUS "  OpenSSL:        ${OPENSSL_VERSION}")
if(WIN32)
    message(STATUS "  Static OpenSSL: ${OPENSSL_USE_STATIC_LIBS}")
    message(STATUS "  Output DLL:     ${CMAKE_BINARY_DIR}/bin/Release/JWTTokenLib.dll")
else()
    message(STATUS "  Output SO:      ${CMAKE_BINARY_DIR}/lib/libJWTTokenLib.so")
endif()
message(STATUS "========================================")
