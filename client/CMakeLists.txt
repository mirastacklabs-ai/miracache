# toml++ (tomlplusplus::tomlplusplus) is declared in the root CMakeLists.txt.
find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto SSL)
add_library(miracache_client STATIC src/config.cpp runtime/runtime.cpp runtime/thread_pool_executor.cpp scope/engine_native.cpp
  src/client_core.cpp src/client.cpp src/loopback_port.cpp src/wire_port.cpp src/wire_open.cpp src/rail_pairing.cpp src/admin_http.cpp src/admin_tickets.cpp
  src/bundle_watcher.cpp src/dyn_config.cpp src/cred_watch.cpp)
target_include_directories(miracache_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR})
# toml++ is an implementation detail: PRIVATE, never in a public header.
target_link_libraries(miracache_client PUBLIC miracache_util miracache_crypto miracache_placement miracache_core_client miracache_store miracache_telemetry miracache_control Threads::Threads OpenSSL::SSL PRIVATE tomlplusplus::tomlplusplus)

# ---- C ABI (A1.6 L4): libmiracache.so exports only mira_* (version script) -----------------
# Static deps are built PIC (top-level CMAKE_POSITION_INDEPENDENT_CODE). c_abi.cpp alone is
# compiled with exceptions so each entry point can end in a catch-all.
# Not built in the fuzz preset (libFuzzer coverage symbols have no runtime in a plain .so).
if(NOT MIRACACHE_FUZZ)
  add_library(miracache_shared SHARED src/c_abi.cpp)
  set_target_properties(miracache_shared PROPERTIES OUTPUT_NAME miracache)
  set_source_files_properties(src/c_abi.cpp PROPERTIES COMPILE_OPTIONS -fexceptions)
  target_include_directories(miracache_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_link_libraries(miracache_shared PRIVATE miracache_client miracache_options)
  target_link_options(miracache_shared PRIVATE -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libmiracache.map)
  set_target_properties(miracache_shared PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libmiracache.map)
endif()
