cmake_minimum_required(VERSION 3.16)
project(piqaso_sdk C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(OPTEE          "Build for OP-TEE trusted world (disables host entropy)" OFF)
option(BUILD_SHARED   "Also build piqaso_sdk as a host-side shared library"   OFF)
option(BUILD_BINDINGS "Build SWIG language bindings (implies BUILD_SHARED)"   OFF)
set(BINDINGS_LANGUAGE "python" CACHE STRING "SWIG target language (python, java, ruby, ...)")

if(BUILD_BINDINGS)
    set(BUILD_SHARED ON CACHE BOOL "" FORCE)
endif()

if((BUILD_SHARED OR BUILD_BINDINGS) AND OPTEE)
    message(FATAL_ERROR "BUILD_SHARED / BUILD_BINDINGS cannot be combined with OPTEE: "
                        "OP-TEE TAs require static linking only.")
endif()

# Optional: point at an already-built WolfSSL installation.
# If not set, CMake will search system paths and then fall back to cloning
# WolfSSL from GitHub and building it automatically.
#   cmake -DWOLFSSL_ROOT=/path/to/wolfssl ..
set(WOLFSSL_ROOT "" CACHE PATH "Root of an existing WolfSSL installation (optional)")

# WolfSSL git tag to use when cloning. Pin to a release for reproducibility.
set(WOLFSSL_GIT_TAG "v5.7.6-stable" CACHE STRING "WolfSSL git tag to clone when not found locally")

# ---------------------------------------------------------------------------
# Single compile definition that triggers our user_settings.h.
# All PQC feature flags live in user_settings.h so that both the CMake
# (FetchContent) build and the OP-TEE sub.mk build share the same config.
# ---------------------------------------------------------------------------
set(PIQASO_WOLFSSL_DEFS WOLFSSL_USER_SETTINGS)

# ---------------------------------------------------------------------------
# 1. Try an explicit WOLFSSL_ROOT first
# ---------------------------------------------------------------------------
set(_wolfssl_found FALSE)

if(WOLFSSL_ROOT)
    find_library(_wssl_lib NAMES wolfssl HINTS "${WOLFSSL_ROOT}/lib" NO_DEFAULT_PATH)
    if(_wssl_lib)
        message(STATUS "WolfSSL found at WOLFSSL_ROOT: ${WOLFSSL_ROOT}")
        add_library(wolfssl_imported STATIC IMPORTED)
        set_target_properties(wolfssl_imported PROPERTIES
            IMPORTED_LOCATION             "${_wssl_lib}"
            INTERFACE_INCLUDE_DIRECTORIES "${WOLFSSL_ROOT}/include"
        )
        target_include_directories(wolfssl_imported INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
        set(_wolfssl_found TRUE)
    else()
        message(WARNING "WOLFSSL_ROOT set to '${WOLFSSL_ROOT}' but libwolfssl not found there — falling through")
    endif()
endif()

# ---------------------------------------------------------------------------
# 2. Try pkg-config / system paths
# ---------------------------------------------------------------------------
if(NOT _wolfssl_found)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(_pc_wolfssl QUIET wolfssl)
    endif()

    find_library(_wssl_lib
        NAMES wolfssl
        HINTS ${_pc_wolfssl_LIBRARY_DIRS} /usr/local/lib /usr/lib
    )
    find_path(_wssl_inc wolfssl/wolfcrypt/dilithium.h
        HINTS ${_pc_wolfssl_INCLUDE_DIRS} /usr/local/include /usr/include
    )

    if(_wssl_lib AND _wssl_inc)
        message(STATUS "WolfSSL found on system: ${_wssl_lib}")
        add_library(wolfssl_imported STATIC IMPORTED)
        set_target_properties(wolfssl_imported PROPERTIES
            IMPORTED_LOCATION             "${_wssl_lib}"
            INTERFACE_INCLUDE_DIRECTORIES "${_wssl_inc}"
        )
        target_include_directories(wolfssl_imported INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
        set(_wolfssl_found TRUE)
    endif()
endif()

# ---------------------------------------------------------------------------
# 3. Fall back: clone + build WolfSSL with FetchContent
# ---------------------------------------------------------------------------
if(NOT _wolfssl_found)
    message(STATUS "WolfSSL not found locally — cloning ${WOLFSSL_GIT_TAG} from GitHub")

    include(FetchContent)

    FetchContent_Declare(wolfssl
        GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
        GIT_TAG        ${WOLFSSL_GIT_TAG}
        GIT_SHALLOW    TRUE
    )

    # Configure WolfSSL's own CMake build.
    # WOLFSSL_USER_SETTINGS=ON causes WolfSSL's cmake/functions.cmake to set
    # BUILD_DILITHIUM / BUILD_FALCON / BUILD_SPHINCS so those sources are
    # compiled into libwolfssl.a.  Feature flags themselves come from our
    # user_settings.h (included via WOLFSSL_USER_SETTINGS define).
    set(WOLFSSL_USER_SETTINGS  ON  CACHE BOOL "" FORCE)
    set(WOLFSSL_KYBER          ON  CACHE BOOL "" FORCE)
    set(WOLFSSL_EXPERIMENTAL   ON  CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS      OFF CACHE BOOL "" FORCE)
    set(WOLFSSL_EXAMPLES       OFF CACHE BOOL "" FORCE)
    set(WOLFSSL_TESTS          OFF CACHE BOOL "" FORCE)
    set(WOLFSSL_CRYPT_TESTS    OFF CACHE BOOL "" FORCE)

    FetchContent_MakeAvailable(wolfssl)

    # user_settings.h lives at the project source root.
    # CMake rejects adding source/build-tree paths to a sub-project's
    # INTERFACE_INCLUDE_DIRECTORIES, so pass the path as a raw -I compiler
    # flag via COMPILE_OPTIONS (not validated by CMake's path checks).
    target_compile_options(wolfssl PRIVATE "-I${CMAKE_CURRENT_SOURCE_DIR}")

    # WolfSSL's CMake exposes a target called 'wolfssl'
    add_library(wolfssl_imported ALIAS wolfssl)

    # WolfSSL's CMake does not add LMS/XMSS native sources to its build.
    # Add them explicitly so they are compiled with the same flags/includes.
    target_sources(wolfssl PRIVATE
        ${wolfssl_SOURCE_DIR}/wolfcrypt/src/wc_lms.c
        ${wolfssl_SOURCE_DIR}/wolfcrypt/src/wc_lms_impl.c
        ${wolfssl_SOURCE_DIR}/wolfcrypt/src/wc_xmss.c
        ${wolfssl_SOURCE_DIR}/wolfcrypt/src/wc_xmss_impl.c
    )
    set(_wolfssl_found TRUE)
endif()

if(NOT _wolfssl_found)
    message(FATAL_ERROR "Could not find or build WolfSSL")
endif()

# ---------------------------------------------------------------------------
# piqaso_sdk static library
# ---------------------------------------------------------------------------
add_library(piqaso_sdk STATIC
    src/mldsa.c
    src/mlkem.c
    src/lms.c
    src/xmss.c
    src/aes.c
)

target_include_directories(piqaso_sdk PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(piqaso_sdk PRIVATE
    ${PIQASO_WOLFSSL_DEFS}
    $<$<BOOL:${OPTEE}>:OPTEE>
)

target_link_libraries(piqaso_sdk PUBLIC wolfssl_imported)

# ---------------------------------------------------------------------------
# Optional host-side shared library and SWIG bindings
# ---------------------------------------------------------------------------
if(BUILD_SHARED AND NOT OPTEE)
    # PIC required for either a SHARED build of piqaso_sdk itself or for
    # linking the static archive into the SWIG-generated module.
    set_property(TARGET piqaso_sdk PROPERTY POSITION_INDEPENDENT_CODE ON)
    if(TARGET wolfssl)
        set_property(TARGET wolfssl PROPERTY POSITION_INDEPENDENT_CODE ON)
    endif()

    add_library(piqaso_sdk_shared SHARED
        src/mldsa.c
        src/mlkem.c
        src/lms.c
        src/xmss.c
        src/aes.c
    )
    set_target_properties(piqaso_sdk_shared PROPERTIES
        OUTPUT_NAME piqaso_sdk
        POSITION_INDEPENDENT_CODE ON
    )
    target_include_directories(piqaso_sdk_shared PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_compile_definitions(piqaso_sdk_shared PRIVATE ${PIQASO_WOLFSSL_DEFS})
    target_link_libraries(piqaso_sdk_shared PUBLIC wolfssl_imported)
endif()

if(BUILD_BINDINGS AND NOT OPTEE)
    find_package(SWIG 4.0 REQUIRED)
    include(UseSWIG)

    set_property(SOURCE bindings/piqaso.i PROPERTY CPLUSPLUS OFF)
    set_property(SOURCE bindings/piqaso.i PROPERTY SWIG_FLAGS "-Wall")
    set_property(SOURCE bindings/piqaso.i PROPERTY
        INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include")

    # Target name must match the SWIG %module name so the loadable module
    # ends up as _piqaso.<ext> which the generated piqaso.py imports.
    if(BINDINGS_LANGUAGE STREQUAL "python")
        find_package(Python3 REQUIRED COMPONENTS Interpreter Development)
        swig_add_library(piqaso
            LANGUAGE python
            SOURCES  bindings/piqaso.i
            OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/python
        )
        target_include_directories(piqaso PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${Python3_INCLUDE_DIRS}
        )
        target_link_libraries(piqaso PRIVATE
            piqaso_sdk_shared
            ${Python3_LIBRARIES}
        )
    elseif(BINDINGS_LANGUAGE STREQUAL "java")
        find_package(JNI REQUIRED)
        find_package(Java REQUIRED COMPONENTS Development)
        include(UseJava)

        set(_java_pkg "com.piqaso")
        set(_java_out "${CMAKE_CURRENT_BINARY_DIR}/java")

        # Tell SWIG where to drop the generated .java files and which package
        # to declare in them.
        set_property(SOURCE bindings/piqaso.i APPEND PROPERTY
                     SWIG_FLAGS "-package" "${_java_pkg}")

        swig_add_library(piqaso
            LANGUAGE java
            SOURCES  bindings/piqaso.i
            OUTPUT_DIR ${_java_out}
        )
        target_include_directories(piqaso PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${JNI_INCLUDE_DIRS}
        )
        target_link_libraries(piqaso PRIVATE piqaso_sdk_shared)

        # Compile generated .java + any test sources into piqaso.jar.
        # We collect the .java files post-configure via a custom target.
        add_custom_target(piqaso_jar ALL
            DEPENDS piqaso
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMAND ${CMAKE_COMMAND} -E make_directory java_classes
            COMMAND sh -c "${Java_JAVAC_EXECUTABLE} -d java_classes ${_java_out}/*.java"
            COMMAND ${Java_JAR_EXECUTABLE} cf piqaso.jar -C java_classes .
            COMMENT "Compiling generated Java sources into piqaso.jar"
            VERBATIM
        )
    elseif(BINDINGS_LANGUAGE STREQUAL "javascript")
        # Locate node and resolve the include dirs for node-addon-api and
        # node-api-headers from the helper package under bindings/js/.
        find_program(NODE_EXECUTABLE NAMES node nodejs REQUIRED)
        set(_js_helper "${CMAKE_CURRENT_SOURCE_DIR}/bindings/js")
        if(NOT EXISTS "${_js_helper}/node_modules/node-addon-api/napi.h")
            message(FATAL_ERROR
                "node-addon-api not installed.  Run:\n"
                "  (cd ${_js_helper} && npm install)\n"
                "before reconfiguring with BINDINGS_LANGUAGE=javascript.")
        endif()
        execute_process(
            COMMAND ${NODE_EXECUTABLE} -p "require('node-addon-api').include_dir"
            WORKING_DIRECTORY ${_js_helper}
            OUTPUT_VARIABLE NAPI_CPP_INCLUDE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
            COMMAND_ERROR_IS_FATAL ANY)
        execute_process(
            COMMAND ${NODE_EXECUTABLE} -p "require('node-api-headers').include_dir"
            WORKING_DIRECTORY ${_js_helper}
            OUTPUT_VARIABLE NAPI_C_INCLUDE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
            COMMAND_ERROR_IS_FATAL ANY)
        # node -p prints paths relative to cwd; resolve to absolutes.
        get_filename_component(NAPI_CPP_INCLUDE_DIR
            "${NAPI_CPP_INCLUDE_DIR}" ABSOLUTE BASE_DIR "${_js_helper}")
        get_filename_component(NAPI_C_INCLUDE_DIR
            "${NAPI_C_INCLUDE_DIR}"   ABSOLUTE BASE_DIR "${_js_helper}")
        message(STATUS "node-addon-api include: ${NAPI_CPP_INCLUDE_DIR}")
        message(STATUS "node-api-headers include: ${NAPI_C_INCLUDE_DIR}")

        # SWIG -napi requires C++ output.  Override the global CPLUSPLUS=OFF
        # property and append the -napi engine flag.
        set_property(SOURCE bindings/piqaso.i PROPERTY CPLUSPLUS ON)
        set_property(SOURCE bindings/piqaso.i APPEND PROPERTY SWIG_FLAGS "-napi")

        swig_add_library(piqaso
            LANGUAGE javascript
            SOURCES  bindings/piqaso.i
            OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/javascript)

        set_target_properties(piqaso PROPERTIES
            PREFIX ""
            SUFFIX ".node"
            LINKER_LANGUAGE CXX
            CXX_STANDARD 17
            CXX_STANDARD_REQUIRED ON)

        target_include_directories(piqaso PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${NAPI_CPP_INCLUDE_DIR}
            ${NAPI_C_INCLUDE_DIR})

        # NAPI_VERSION pins the ABI; 8 is supported by Node 16+.  -fexceptions
        # is required because the SWIG-generated wrapper uses C++ throw.
        target_compile_definitions(piqaso PRIVATE
            NAPI_VERSION=8
            NAPI_CPP_EXCEPTIONS
            BUILDING_NODE_EXTENSION)
        target_compile_options(piqaso PRIVATE -fexceptions)
        # Node addons resolve napi_* symbols at dlopen() time from the Node
        # binary, so they must remain unresolved here; do not pass
        # --no-undefined.

        target_link_libraries(piqaso PRIVATE piqaso_sdk_shared)
    else()
        swig_add_library(piqaso
            LANGUAGE ${BINDINGS_LANGUAGE}
            SOURCES  bindings/piqaso.i
            OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/${BINDINGS_LANGUAGE}
        )
        target_include_directories(piqaso PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(piqaso PRIVATE piqaso_sdk_shared)
    endif()
endif()

# ---------------------------------------------------------------------------
# Tests (host only — not built when cross-compiling for OP-TEE)
# ---------------------------------------------------------------------------
if(NOT OPTEE AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()

    add_executable(test_mldsa test/test_mldsa.c)
    target_compile_definitions(test_mldsa PRIVATE ${PIQASO_WOLFSSL_DEFS})
    target_link_libraries(test_mldsa PRIVATE piqaso_sdk)
    add_test(NAME mldsa_all_levels COMMAND test_mldsa)

    add_executable(test_mlkem test/test_mlkem.c)
    target_compile_definitions(test_mlkem PRIVATE ${PIQASO_WOLFSSL_DEFS})
    target_link_libraries(test_mlkem PRIVATE piqaso_sdk)
    add_test(NAME mlkem_all_levels COMMAND test_mlkem)

    add_executable(test_lms test/test_lms.c)
    target_compile_definitions(test_lms PRIVATE ${PIQASO_WOLFSSL_DEFS})
    target_link_libraries(test_lms PRIVATE piqaso_sdk)
    add_test(NAME lms_all COMMAND test_lms)

    add_executable(test_xmss test/test_xmss.c)
    target_compile_definitions(test_xmss PRIVATE ${PIQASO_WOLFSSL_DEFS})
    target_link_libraries(test_xmss PRIVATE piqaso_sdk)
    add_test(NAME xmss_all COMMAND test_xmss)

    add_executable(test_aes test/test_aes.c)
    target_compile_definitions(test_aes PRIVATE ${PIQASO_WOLFSSL_DEFS})
    target_link_libraries(test_aes PRIVATE piqaso_sdk)
    add_test(NAME aes_all COMMAND test_aes)

    # ---- benchmarks (not registered as ctest tests) ------------------
    foreach(_b mlkem mldsa aes lms xmss)
        add_executable(bench_${_b} test/bench_${_b}.c)
        target_compile_definitions(bench_${_b} PRIVATE ${PIQASO_WOLFSSL_DEFS})
        target_link_libraries(bench_${_b} PRIVATE piqaso_sdk)
    endforeach()
endif()
