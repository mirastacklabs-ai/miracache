add_library(miracache_proto STATIC server_header.cpp extent_header.cpp frame.cpp messages.cpp storage_layout.cpp scope_record.cpp)
target_include_directories(miracache_proto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(miracache_proto PUBLIC miracache_util)
