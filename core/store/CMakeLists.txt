add_library(miracache_store STATIC backing.cpp arena.cpp scope_table.cpp restart.cpp node_state.cpp slab.cpp store.cpp mr_manager.cpp put.cpp reclaim.cpp scrub.cpp)
target_include_directories(miracache_store PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(miracache_store PUBLIC miracache_util miracache_telemetry miracache_proto miracache_fabric)
