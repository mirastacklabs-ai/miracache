# Memory-node server. The library is deterministic (injected Clock/Random/Executor);
# threads live only in runtime/ (lint marker `// lint:server-runtime`).
find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)
add_library(miracache_server STATIC server.cpp tickets.cpp lab_tickets.cpp node_config.cpp dyn_config.cpp runtime/store_executor.cpp runtime/metrics_http.cpp
  runtime/admin_https.cpp runtime/bundle_store.cpp runtime/rbac.cpp)
target_include_directories(miracache_server PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(miracache_server PUBLIC miracache_control miracache_store miracache_proto miracache_fabric miracache_util
  Threads::Threads OpenSSL::SSL OpenSSL::Crypto PRIVATE tomlplusplus::tomlplusplus)

# build_info labels. The git sha is best effort (a source tarball has no .git).
execute_process(COMMAND git rev-parse --short=12 HEAD
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  OUTPUT_VARIABLE MIRACACHE_GIT_SHA OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
if(NOT MIRACACHE_GIT_SHA)
  set(MIRACACHE_GIT_SHA "unknown")
endif()
target_compile_definitions(miracache_server PRIVATE
  MIRACACHE_VERSION_STR="${PROJECT_VERSION}" MIRACACHE_GIT_SHA="${MIRACACHE_GIT_SHA}")

# A MIRACACHE_TEETH tree (sim preset) has fault hooks compiled in: no production binary there
# (main.cpp also static_asserts it).
if(NOT MIRACACHE_TEETH)
  add_executable(mira-memnode main.cpp)
  target_link_libraries(mira-memnode PRIVATE miracache_server miracache_options)
endif()
