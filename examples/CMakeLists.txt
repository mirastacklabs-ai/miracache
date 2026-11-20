# Minimal programs that store and fetch one block. Built when MIRACACHE_EXAMPLES is ON (the default
# when miracache is the top-level project). They compile anywhere; running them needs RDMA and memory nodes.
add_subdirectory(cpp)
if(TARGET miracache_shared)
  add_subdirectory(c)
endif()
