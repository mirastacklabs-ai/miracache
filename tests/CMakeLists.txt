include(FetchContent)
FetchContent_Declare(googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
  URL_HASH SHA256=7b42b4d6ed48810c5362c265a17faebe90dc2373c885e5216439d37927f02926
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
include(GoogleTest)

# Q14: discover tests when ctest starts (PRE_TEST), not as a POST_BUILD step. The Mac<->VM mount sometimes lands a freshly
# linked binary without its exec bit; POST_BUILD discovery then fails ("Permission denied") and stops the build before
# the build script can delete and relink it. Its `ctest -N` runs after that workaround. Nothing here reads the
# TEST_LIST variables (they only name the discovery calls), so no test list is needed at configure time.
set(CMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)

add_executable(miracache_tests
  util/expected_test.cpp
  util/clock_random_test.cpp
  util/crc32c_test.cpp
  util/log_test.cpp
  proto/server_header_test.cpp
  proto/extent_header_test.cpp
  proto/frame_test.cpp
  proto/messages_test.cpp
  proto/messages_b_test.cpp
  proto/storage_layout_test.cpp
  proto/scope_record_test.cpp
  fabric/sim_fabric_test.cpp
  fabric/nic_probe_test.cpp
  fabric/nic_profile_test.cpp
  fabric/qp_readback_test.cpp)
target_link_libraries(miracache_tests PRIVATE miracache_proto miracache_fabric GTest::gtest_main Threads::Threads)
target_compile_definitions(miracache_tests PRIVATE
  MIRACACHE_GOLDEN_DIR="${PROJECT_SOURCE_DIR}/proto/golden"
  MIRACACHE_PROFILES_FILE="${PROJECT_SOURCE_DIR}/profiles/nic-profiles.toml")
gtest_discover_tests(miracache_tests)

add_executable(miracache_store_tests store/restart_test.cpp store/layout_test.cpp store/arena_test.cpp store/slab_test.cpp store/store_test.cpp store/put_test.cpp store/reclaim_test.cpp store/sweep_test.cpp store/retention_test.cpp store/put_quota_test.cpp store/live_limits_test.cpp store/scrub_test.cpp)
target_link_libraries(miracache_store_tests PRIVATE miracache_store GTest::gtest_main)
gtest_discover_tests(miracache_store_tests)

find_package(Threads REQUIRED)
add_executable(miracache_telemetry_tests telemetry/metrics_test.cpp)
target_link_libraries(miracache_telemetry_tests PRIVATE miracache_telemetry GTest::gtest_main Threads::Threads)
gtest_discover_tests(miracache_telemetry_tests)

add_executable(miracache_client_tests client/config_test.cpp client/runtime_test.cpp
  client/landing_pool_test.cpp client/pipeline_test.cpp client/thread_pool_test.cpp
  client/engine_native_test.cpp client/client_loopback_test.cpp client/placement_test.cpp)
target_link_libraries(miracache_client_tests PRIVATE miracache_client miracache_core_client GTest::gtest_main)
target_compile_definitions(miracache_client_tests PRIVATE
  MIRACACHE_GOLDEN_DIR="${PROJECT_SOURCE_DIR}/proto/golden"
  MIRACACHE_PROFILES_FILE="${PROJECT_SOURCE_DIR}/profiles/nic-profiles.toml")
gtest_discover_tests(miracache_client_tests)

# Crypto KATs (A1.5 S1). Registered twice: default (hardware AES where available) and
# with hardware AES off so OpenSSL's generic code path runs too. OPENSSL_armcap=0 takes
# effect on aarch64; OPENSSL_ia32cap masks the AES-NI/PCLMUL bits on x86.
find_package(Threads REQUIRED)
add_executable(miracache_crypto_tests crypto/kat_test.cpp crypto/block_codec_test.cpp
  crypto/single_fetch_test.cpp)
target_link_libraries(miracache_crypto_tests PRIVATE miracache_crypto GTest::gtest_main Threads::Threads)
target_include_directories(miracache_crypto_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(miracache_crypto_tests PRIVATE
  MIRACACHE_GOLDEN_DIR="${PROJECT_SOURCE_DIR}/proto/golden"
  MIRACACHE_PROFILES_FILE="${PROJECT_SOURCE_DIR}/profiles/nic-profiles.toml")
gtest_discover_tests(miracache_crypto_tests)
gtest_discover_tests(miracache_crypto_tests TEST_SUFFIX _softaes
  PROPERTIES ENVIRONMENT "OPENSSL_armcap=0;OPENSSL_ia32cap=~0x200000000000000")

# Real-RDMA tests (label `rdma`). Built with the verbs backend; every test skips cleanly
# when no RDMA device is usable. Run them once per device with `ctest -L rdma`.
if(MIRACACHE_WITH_VERBS)
  find_package(Threads REQUIRED)
  add_executable(miracache_rdma_tests fabric/verbs_cm_rdma_test.cpp fabric/nic_probe_rdma_test.cpp)
  target_link_libraries(miracache_rdma_tests PRIVATE miracache_fabric PkgConfig::IBVERBS PkgConfig::RDMACM GTest::gtest_main
                        Threads::Threads)
  gtest_discover_tests(miracache_rdma_tests
    PROPERTIES LABELS rdma RUN_SERIAL TRUE SKIP_REGULAR_EXPRESSION "\\[  SKIPPED \\]" TIMEOUT 240
    DISCOVERY_TIMEOUT 30)
endif()

# ---- C ABI (A1.6 L4) ----------------------------------------------------------------------
# c_abi_test is plain C against libmiracache.so; abi_symbols_test checks `nm -D` exports only
# mira_*; python_roundtrip runs tests/python/test_roundtrip.py against the built .so (not under
# sanitizers: a sanitized .so cannot be dlopen'ed by a plain interpreter).
if(NOT MIRACACHE_FUZZ)
  enable_language(C)
  add_executable(c_abi_test client/c_abi_test.c)
  target_link_libraries(c_abi_test PRIVATE miracache_shared)
  # Link with the C++ driver so UBSan's C++ runtime (vptr checks inside the .so) resolves.
  set_target_properties(c_abi_test PROPERTIES LINKER_LANGUAGE CXX)
  if(MIRACACHE_SANITIZE)
    list(JOIN MIRACACHE_SANITIZE "," _csan)
    target_compile_options(c_abi_test PRIVATE -fsanitize=${_csan} -fno-sanitize-recover=all)
    target_link_options(c_abi_test PRIVATE -fsanitize=${_csan})
  endif()
  add_test(NAME c_abi_test COMMAND c_abi_test)
  add_test(NAME abi_symbols_test
    COMMAND ${CMAKE_COMMAND} -DLIB=$<TARGET_FILE:miracache_shared>
            -P ${PROJECT_SOURCE_DIR}/tests/client/check_exports.cmake)
  find_program(MIRA_PYTHON3 python3)
  if(MIRA_PYTHON3 AND NOT MIRACACHE_SANITIZE)
    add_test(NAME python_roundtrip
      COMMAND ${CMAKE_COMMAND} -E env MIRACACHE_LIB=$<TARGET_FILE:miracache_shared>
              PYTHONPATH=${PROJECT_SOURCE_DIR}/python
              ${MIRA_PYTHON3} -m unittest discover -s ${PROJECT_SOURCE_DIR}/tests/python -p test_roundtrip.py -v)
  endif()
endif()

if(MIRACACHE_FUZZ)
  add_executable(fuzz_block_headers fuzz/fuzz_block_headers.cpp)
  # Libraries already carry -fsanitize=fuzzer-no-link via miracache_options.
  target_compile_options(fuzz_block_headers PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(fuzz_block_headers PRIVATE -fsanitize=fuzzer)
  target_link_libraries(fuzz_block_headers PRIVATE miracache_proto miracache_options)

  add_executable(fuzz_block_open fuzz/fuzz_block_open.cpp)
  target_compile_options(fuzz_block_open PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(fuzz_block_open PRIVATE -fsanitize=fuzzer)
  target_link_libraries(fuzz_block_open PRIVATE miracache_crypto miracache_options)

  add_executable(fuzz_wire fuzz/fuzz_wire.cpp)
  target_compile_options(fuzz_wire PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(fuzz_wire PRIVATE -fsanitize=fuzzer)
  target_link_libraries(fuzz_wire PRIVATE miracache_proto miracache_options)

  add_executable(fuzz_bundle_envelope fuzz/fuzz_bundle_envelope.cpp)
  target_compile_options(fuzz_bundle_envelope PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(fuzz_bundle_envelope PRIVATE -fsanitize=fuzzer)
  target_link_libraries(fuzz_bundle_envelope PRIVATE miracache_control miracache_options)

  add_executable(fuzz_audit_verify fuzz/fuzz_audit_verify.cpp)
  target_compile_options(fuzz_audit_verify PRIVATE -fsanitize=fuzzer-no-link)
  target_link_options(fuzz_audit_verify PRIVATE -fsanitize=fuzzer)
  target_link_libraries(fuzz_audit_verify PRIVATE miracache_control miracache_options)
endif()

add_executable(miracache_server_tests server/server_test.cpp server/store_executor_test.cpp server/bundle_routes_test.cpp server/bundle_apply_test.cpp server/epoch_test.cpp server/rbac_test.cpp server/dyn_config_test.cpp server/multirail_test.cpp)
target_link_libraries(miracache_server_tests PRIVATE miracache_server miracache_control miracache_client GTest::gtest_main)
target_include_directories(miracache_server_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# The admin mTLS tests generate their PKI with the lab script (openssl CLI) into a temp dir.
target_compile_definitions(miracache_server_tests PRIVATE MIRACACHE_GOLDEN_DIR="${PROJECT_SOURCE_DIR}/proto/golden" MIRACACHE_LAB_CERTS_SH="${PROJECT_SOURCE_DIR}/deploy/examples/lab-certs.sh")
gtest_discover_tests(miracache_server_tests)

# Deploy examples must load through the real parsers (review r4 D01). The two-host and benchmark examples it reads are
# private, so the public tree omits the test file and skips it here.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/deploy/deploy_examples_test.cpp")
  add_executable(miracache_deploy_tests deploy/deploy_examples_test.cpp)
  target_link_libraries(miracache_deploy_tests PRIVATE miracache_client miracache_server GTest::gtest_main)
  target_compile_definitions(miracache_deploy_tests PRIVATE MIRACACHE_DEPLOY_DIR="${PROJECT_SOURCE_DIR}/deploy")
  gtest_discover_tests(miracache_deploy_tests)
endif()

# Client wire port against the real memory-node server over SimFabric (A1.6 L4+).
add_executable(miracache_wire_tests client/wire_port_test.cpp client/admin_tickets_test.cpp)
target_link_libraries(miracache_wire_tests PRIVATE miracache_client miracache_server miracache_core_client GTest::gtest_main)
target_compile_definitions(miracache_wire_tests PRIVATE MIRACACHE_LAB_CERTS_SH="${PROJECT_SOURCE_DIR}/deploy/examples/lab-certs.sh")
# J02: the keepalive-thread tests are timing-sensitive (real-time ping rate): RUN_SERIAL, like the other
# timing-sensitive suites (reload_walk_tests, bundle_watcher, cred_watch, WireClient/WireFailure *Keepalive*).
gtest_discover_tests(miracache_wire_tests TEST_LIST wire_keepalive_tests
  TEST_FILTER "*Keepalive*" PROPERTIES RUN_SERIAL TRUE)
gtest_discover_tests(miracache_wire_tests TEST_LIST wire_other_tests
  TEST_FILTER "-*Keepalive*")

# Live RDMA: Client::open (production wiring) against an in-process memory node over verbs_cm.
if(MIRACACHE_WITH_VERBS)
  add_executable(miracache_wire_rdma_tests client/wire_rdma_test.cpp)
  target_link_libraries(miracache_wire_rdma_tests PRIVATE miracache_client miracache_server miracache_fabric miracache_core_client GTest::gtest_main Threads::Threads)
  if(TARGET miracache_shared)  # not built in the fuzz preset
    target_link_libraries(miracache_wire_rdma_tests PRIVATE miracache_shared)
    target_compile_definitions(miracache_wire_rdma_tests PRIVATE MIRA_WITH_SHARED=1)
  endif()
  gtest_discover_tests(miracache_wire_rdma_tests
    PROPERTIES LABELS rdma RUN_SERIAL TRUE SKIP_REGULAR_EXPRESSION "\\[  SKIPPED \\]" TIMEOUT 240
    DISCOVERY_TIMEOUT 30)
endif()

# Two-process end to end (label `rdma`): the real mira-memnode binary with [admin] mTLS and a
# Client::open with only nodes[].admin. Needs verbs; run once per device with `ctest -L rdma`.
if(MIRACACHE_WITH_VERBS AND TARGET mira-memnode)
  add_executable(miracache_e2e_rdma_tests e2e/admin_two_process_rdma_test.cpp e2e/multi_node_rdma_test.cpp e2e/reconnect_traffic_rdma_test.cpp e2e/membership_rdma_test.cpp e2e/rolling_upgrade_rdma_test.cpp e2e/reload_rdma_test.cpp e2e/multirail_rdma_test.cpp)
  target_link_libraries(miracache_e2e_rdma_tests PRIVATE miracache_client miracache_fabric GTest::gtest_main Threads::Threads)
  target_compile_definitions(miracache_e2e_rdma_tests PRIVATE
    MIRACACHE_LAB_CERTS_SH="${PROJECT_SOURCE_DIR}/deploy/examples/lab-certs.sh" MIRA_MEMNODE_BIN="$<TARGET_FILE:mira-memnode>"
    MIRA_RAIL_FAULT_DIR="${CMAKE_BINARY_DIR}/rail-fault")
  # MB11 (membership_rdma_test.cpp) also runs the real Go binaries mira-controller and mirctl. They are built by the
  # pinned toolchain (deploy/docker/go.sh, inside the container) into <build>/go-bin; the test finds them by these paths.
  add_custom_target(mira_go_tools
    COMMAND ${PROJECT_SOURCE_DIR}/deploy/docker/go.sh -C controller build -o ${CMAKE_BINARY_DIR}/go-bin/mira-controller ./cmd/mira-controller
    COMMAND ${PROJECT_SOURCE_DIR}/deploy/docker/go.sh -C controller build -o ${CMAKE_BINARY_DIR}/go-bin/mirctl ./cmd/mirctl
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    COMMENT "Building mira-controller and mirctl (deploy/docker/go.sh)"
    VERBATIM)
  target_compile_definitions(miracache_e2e_rdma_tests PRIVATE
    MIRA_CONTROLLER_BIN="${CMAKE_BINARY_DIR}/go-bin/mira-controller" MIRCTL_BIN="${CMAKE_BINARY_DIR}/go-bin/mirctl")
  target_include_directories(miracache_e2e_rdma_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  add_dependencies(miracache_e2e_rdma_tests mira-memnode mira_go_tools)
  # H04: MultiRailE2e has its own TIMEOUT. Worst-case waits in the test body: rails up 30 + fill 60 + 2+8 + del ack 30 +
  # rail down 30 + 8 + add ack 30 + rail back 60 + 2+8 = 268 s, plus bring-up (3 nodes x 15 s plus controller tool runs) and
  # teardown; 600 s covers it with margin. All of these tests use fixed ports/devices: RUN_SERIAL.
  gtest_discover_tests(miracache_e2e_rdma_tests TEST_LIST e2e_rdma_multirail_tests
    TEST_FILTER "*MultiRailE2e*"
    PROPERTIES LABELS rdma RUN_SERIAL TRUE SKIP_REGULAR_EXPRESSION "\\[  SKIPPED \\]" TIMEOUT 600
    DISCOVERY_TIMEOUT 30)
  gtest_discover_tests(miracache_e2e_rdma_tests TEST_LIST e2e_rdma_other_tests
    TEST_FILTER "-*MultiRailE2e*"
    PROPERTIES LABELS rdma RUN_SERIAL TRUE SKIP_REGULAR_EXPRESSION "\\[  SKIPPED \\]" TIMEOUT 240
    DISCOVERY_TIMEOUT 30)
endif()

# Signed cluster bundle, C++ side (membership plan MB2): envelope, trust keys, floor.
add_executable(miracache_control_tests control/bundle_test.cpp control/floor_state_test.cpp control/view_test.cpp control/audit_test.cpp)
target_link_libraries(miracache_control_tests PRIVATE miracache_control GTest::gtest_main Threads::Threads)
target_include_directories(miracache_control_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(miracache_control_tests PRIVATE MIRACACHE_GOLDEN_DIR="${PROJECT_SOURCE_DIR}/proto/golden")
gtest_discover_tests(miracache_control_tests)

# owner_set (MB2p)
add_executable(miracache_placement_tests placement/owner_set_test.cpp)
target_link_libraries(miracache_placement_tests PRIVATE miracache_placement GTest::gtest_main Threads::Threads)
gtest_discover_tests(miracache_placement_tests)

# MB5: the client bundle watcher against fake HTTPS admin endpoints (also run under the tsan preset).
add_executable(miracache_bundle_watcher_tests client/bundle_watcher_test.cpp)
target_link_libraries(miracache_bundle_watcher_tests PRIVATE miracache_client miracache_control GTest::gtest_main Threads::Threads)
target_include_directories(miracache_bundle_watcher_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(miracache_bundle_watcher_tests PRIVATE MIRACACHE_LAB_CERTS_SH="${PROJECT_SOURCE_DIR}/deploy/examples/lab-certs.sh")
gtest_discover_tests(miracache_bundle_watcher_tests PROPERTIES RUN_SERIAL TRUE)

# MB6a: client node slots driven by bundles (real memory nodes over SimFabric; also run under the tsan preset).
add_executable(miracache_membership_tests client/membership_test.cpp)
target_link_libraries(miracache_membership_tests PRIVATE miracache_client miracache_server miracache_core_client miracache_control GTest::gtest_main Threads::Threads)
target_include_directories(miracache_membership_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
gtest_discover_tests(miracache_membership_tests)

# HR2: client live configuration (ClientDyn): the key table, and class A keys under traffic (also run under tsan).
add_executable(miracache_reload_tests client/reload_test.cpp)
target_link_libraries(miracache_reload_tests PRIVATE miracache_client miracache_server miracache_core_client miracache_control GTest::gtest_main Threads::Threads)
target_include_directories(miracache_reload_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# G11: only the class B rebuild walk waits on sim progress (until_sim, wall backstop 1200 s): its own TIMEOUT above that.
# Every other test here ran under 12 s in the last gate; a hang costs 10 min, not 25 (H08c).
gtest_discover_tests(miracache_reload_tests TEST_LIST reload_walk_tests
  TEST_FILTER "ClientRebuild.ClassBChange*" PROPERTIES TIMEOUT 1500 RUN_SERIAL TRUE)
gtest_discover_tests(miracache_reload_tests TEST_LIST reload_fast_tests
  TEST_FILTER "-ClientRebuild.ClassBChange*" PROPERTIES TIMEOUT 600)

# HR4: client credential and secret rotation (cert/key/ca stat check, secret kver switch; also run under tsan).
add_executable(miracache_cred_watch_tests client/cred_watch_test.cpp)
target_link_libraries(miracache_cred_watch_tests PRIVATE miracache_client GTest::gtest_main Threads::Threads)
target_include_directories(miracache_cred_watch_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(miracache_cred_watch_tests PRIVATE MIRACACHE_LAB_CERTS_SH="${PROJECT_SOURCE_DIR}/deploy/examples/lab-certs.sh")
gtest_discover_tests(miracache_cred_watch_tests PROPERTIES RUN_SERIAL TRUE)

# RL2: client rails and connections (sim, RL1 multi-rail servers): per-rail endpoint sets, rail loss, suspect, return.
add_executable(miracache_multirail_client_tests client/multirail_test.cpp)
target_link_libraries(miracache_multirail_client_tests PRIVATE miracache_client miracache_server miracache_core_client GTest::gtest_main)
target_include_directories(miracache_multirail_client_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
gtest_discover_tests(miracache_multirail_client_tests)
