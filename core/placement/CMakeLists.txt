find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
add_library(miracache_placement STATIC placement.cpp)
target_include_directories(miracache_placement PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(miracache_placement PUBLIC miracache_util OpenSSL::Crypto miracache_options)
