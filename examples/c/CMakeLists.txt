# The C ABI: include <miracache/miracache.h> and link libmiracache.so (target miracache_shared).
include(CheckLanguage)
check_language(C)
if(CMAKE_C_COMPILER)
  enable_language(C)
  add_executable(example_c_put_fetch put_fetch.c)
  # LINKER_LANGUAGE CXX: libmiracache.so is C++, and under UBSan it needs the C++ UBSan runtime
  # (__ubsan_vptr_type_cache), which only the clang++ link driver adds; the source stays C.
  set_target_properties(example_c_put_fetch PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
                                                       LINKER_LANGUAGE CXX)
  # miracache_options carries the sanitizer link options too; without it the tsan/asan presets
  # fail to link (libmiracache.so references __tsan_* / __asan_*). The fuzz preset builds no
  # libmiracache.so, so it has no C example (client/CMakeLists.txt).
  target_link_libraries(example_c_put_fetch PRIVATE miracache_shared miracache_options)
else()
  message(STATUS "no C compiler: skipping examples/c")
endif()
