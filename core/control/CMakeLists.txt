find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
add_library(miracache_control STATIC audit.cpp sha256.cpp toml_guard.cpp trust_keys.cpp bundle.cpp floor_state.cpp view.cpp)
target_include_directories(miracache_control PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
# toml++ is an implementation detail: PRIVATE, never in a public header.
target_link_libraries(miracache_control PUBLIC miracache_util miracache_placement OpenSSL::Crypto PRIVATE tomlplusplus::tomlplusplus)
