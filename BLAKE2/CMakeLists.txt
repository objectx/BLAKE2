
cmake_minimum_required (VERSION 3.0)

add_library (BLAKE2 src/BLAKE2.cpp)
target_include_directories (BLAKE2 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features (BLAKE2 PRIVATE cxx_nonstatic_member_init cxx_constexpr)
