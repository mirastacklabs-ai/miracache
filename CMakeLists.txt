cmake_minimum_required(VERSION 3.28)
project(miracache VERSION 0.0.1 LANGUAGES CXX
        DESCRIPTION "Remote KV-cache tier over RDMA")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---- Options ----------------------------------------------------------------
# verbs: default ON on Linux when libibverbs and librdmacm are found.
find_package(PkgConfig QUIET)
set(_verbs_default OFF)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND PkgConfig_FOUND)
  pkg_check_modules(IBVERBS IMPORTED_TARGET libibverbs)
  pkg_check_modules(RDMACM IMPORTED_TARGET librdmacm)
  if(IBVERBS_FOUND AND RDMACM_FOUND)
    set(_verbs_default ON)
  endif()
endif()
option(MIRACACHE_WITH_VERBS "Build the verbs/rdma_cm fabric backend" ${_verbs_default})
option(MIRACACHE_SIM "Build the deterministic simulation harness (sim/)" ON)
option(MIRACACHE_FUZZ "Build libFuzzer targets (requires clang)" OFF)
option(MIRACACHE_WERROR "Treat compiler warnings as errors (CI forces ON)" ON)
option(MIRACACHE_WITH_CUDA "GPU-direct support (stub: option only)" OFF)
option(MIRACACHE_WITH_ROCM "GPU-direct support (stub: option only)" OFF)
set(MIRACACHE_SANITIZE "" CACHE STRING "Sanitizers, e.g. address;undefined or thread")
set(MIRACACHE_SIM_SEEDS 200 CACHE STRING "Seeds run by the sim_smoke test")
set(MIRACACHE_STORE_SEEDS 200 CACHE STRING "Seeds run by the sim_store test (sim preset: 2000)")
# Compiles the BUGGIFY teeth hooks (util/buggify.h) into the store so the sim can prove it
# detects them. Off in production builds, where the hooks fold to constant false.
option(MIRACACHE_TEETH "Compile store teeth hooks for the simulator (sim preset only)" OFF)

if(MIRACACHE_WITH_VERBS AND NOT (IBVERBS_FOUND AND RDMACM_FOUND))
  message(FATAL_ERROR "MIRACACHE_WITH_VERBS=ON but libibverbs/librdmacm were not found")
endif()

# ---- Common compile options -------------------------------------------------
# core/ is built without exceptions: contract violations trap (util/check.h) and
# errors travel as Expected/Status. Future pybind11 targets must NOT link this
# interface target (or must add -fexceptions) since pybind11 requires exceptions.
add_library(miracache_options INTERFACE)
target_compile_options(miracache_options INTERFACE -Wall -Wextra -fno-exceptions)
if(MIRACACHE_WERROR)
  target_compile_options(miracache_options INTERFACE -Werror)
endif()
if(MIRACACHE_SANITIZE)
  list(JOIN MIRACACHE_SANITIZE "," _san)
  # -fno-sanitize-recover=all makes every sanitizer finding fatal (UBSan otherwise
  # prints and carries on, which CI would not notice).
  target_compile_options(miracache_options INTERFACE
    -fsanitize=${_san} -fno-sanitize-recover=all -fno-omit-frame-pointer)
  target_link_options(miracache_options INTERFACE
    -fsanitize=${_san} -fno-sanitize-recover=all)
endif()
if(MIRACACHE_TEETH)
  target_compile_definitions(miracache_options INTERFACE MIRACACHE_TEETH=1)
endif()
if(MIRACACHE_FUZZ)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "MIRACACHE_FUZZ requires clang (libFuzzer); got ${CMAKE_CXX_COMPILER_ID}")
  endif()
  # Instrument every library so coverage feedback reaches the fuzz targets.
  target_compile_options(miracache_options INTERFACE -fsanitize=fuzzer-no-link)
  target_link_options(miracache_options INTERFACE -fsanitize=fuzzer-no-link)
endif()

# Must precede every add_subdirectory that calls add_test; otherwise
# those tests are silently never registered.
enable_testing()

# libmiracache.so (client/) links the static libraries below, so they must be PIC.
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# toml++ pinned by exact tag and URL hash (header-only; SYSTEM so -Werror ignores its headers).
# Declared once here; core/control, core/fabric, client/ and server/ link tomlplusplus::tomlplusplus.
include(FetchContent)
FetchContent_Declare(tomlplusplus
  URL https://github.com/marzer/tomlplusplus/archive/refs/tags/v3.4.0.tar.gz
  URL_HASH SHA256=8517f65938a4faae9ccf8ebb36631a38c1cadfb5efa85d9a72e15b9e97d25155
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
  SYSTEM)
FetchContent_MakeAvailable(tomlplusplus)

add_subdirectory(core/util)
add_subdirectory(core/control)
add_subdirectory(core/crypto)
add_subdirectory(core/proto)
add_subdirectory(core/telemetry)
add_subdirectory(core/fabric)
add_subdirectory(core/store)
add_subdirectory(core/placement)
add_subdirectory(core/client)
add_subdirectory(client)
add_subdirectory(server)

# The public source tree ships without the simulator and the test suites: build them only where they exist.
if(MIRACACHE_SIM AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/sim/CMakeLists.txt")
  add_subdirectory(sim)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
  add_subdirectory(tests)
endif()
