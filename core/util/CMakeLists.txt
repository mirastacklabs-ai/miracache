find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
add_library(miracache_util STATIC error.cpp clock.cpp random.cpp crc32c.cpp nonce_source.cpp log.cpp)
target_include_directories(miracache_util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(miracache_util PUBLIC miracache_options OpenSSL::Crypto)
