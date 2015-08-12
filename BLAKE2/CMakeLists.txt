
cmake_minimum_required (VERSION 3.0)

include_directories ("${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library (BLAKE2 src/BLAKE2.cpp)
target_compile_features (BLAKE2 PRIVATE cxx_nonstatic_member_init cxx_constexpr)
