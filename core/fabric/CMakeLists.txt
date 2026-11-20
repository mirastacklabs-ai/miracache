# toml++ (NIC profile registry) is declared once, in the top-level CMakeLists.txt.

# profiles/nic-profiles.toml is compiled into the binaries (A3.3); a profiles_file overrides it.
file(READ ${PROJECT_SOURCE_DIR}/profiles/nic-profiles.toml MIRA_PROFILES_TOML)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/profiles/nic-profiles.toml)
configure_file(profile/nic_profiles_embedded.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/nic_profiles_embedded.cpp @ONLY)

add_library(miracache_fabric STATIC verbs_cm/qp_readback.cpp sim/sim_network.cpp sim/sim_fabric.cpp probe/nic_probe.cpp
  profile/nic_profile.cpp ${CMAKE_CURRENT_BINARY_DIR}/nic_profiles_embedded.cpp)
target_include_directories(miracache_fabric PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(miracache_fabric PUBLIC miracache_util miracache_telemetry PRIVATE tomlplusplus::tomlplusplus)

if(MIRACACHE_WITH_VERBS)
  target_sources(miracache_fabric PRIVATE verbs_cm/verbs_cm_fabric.cpp verbs_cm/protocol_rules.cpp probe/nic_probe_verbs.cpp
    profile/nic_profile_verbs.cpp)
  target_link_libraries(miracache_fabric PRIVATE PkgConfig::IBVERBS PkgConfig::RDMACM)
  target_compile_definitions(miracache_fabric PUBLIC MIRACACHE_WITH_VERBS=1)
  # mira-nicprobe [--json] [device...]: NIC facts, capability trials, usable verdict, matched profile (A1.3, A3.3).
  add_executable(mira-nicprobe probe/nicprobe_main.cpp)
  target_link_libraries(mira-nicprobe PRIVATE miracache_fabric)
endif()
