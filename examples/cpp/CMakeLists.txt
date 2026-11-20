add_executable(example_cpp_put_fetch put_fetch.cpp)
# miracache_client brings its include paths and dependencies; miracache_options sets the project's flags.
target_link_libraries(example_cpp_put_fetch PRIVATE miracache_client miracache_options)
