find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
add_library(miracache_crypto STATIC hkdf.cpp hmac.cpp gcm.cpp block_codec.cpp)
target_include_directories(miracache_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(miracache_crypto PUBLIC miracache_proto miracache_util OpenSSL::Crypto miracache_options)
