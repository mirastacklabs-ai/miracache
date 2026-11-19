add_library(miracache_telemetry STATIC metrics.cpp)
target_include_directories(miracache_telemetry PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(miracache_telemetry PUBLIC miracache_util)
