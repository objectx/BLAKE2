
cmake_minimum_required (VERSION 3.0)

include (TestBigEndian)
include (CheckCXXSourceRuns)
include (CheckCXXCompilerFlag)

check_cxx_compiler_flag ("-mavx" TARGET_HAVE_AVX)

if (${HAVE_AVX})
    add_compile_options ("-mavx")
endif ()

if (NOT CMAKE_CROSSCOMPILING)
    # Self hosted
    TEST_BIG_ENDIAN (IS_BIG_ENDIAN)
    if (NOT IS_BIG_ENDIAN)
        set (TARGET_IS_LITTLE_ENDIAN 1)
    endif ()
    CHECK_CXX_SOURCE_RUNS ([=[
#include <cstdint>
int main () {
    char tmp [9] = { 0, 4, 3, 2, 1 } ;
    uint32_t v = *((const uint32_t *)&tmp [1]) ;
    if (v == 0x01020304u) {
        return 0 ;
    }
    return 1 ;
}
        ]=] TARGET_ALLOWS_UNALIGNED_ACCESS)
endif ()

configure_file (${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
add_definitions ("-DHAVE_CONFIG_H")

include_directories (${CMAKE_CURRENT_BINARY_DIR})

add_library (BLAKE2 BLAKE2.cpp)
target_include_directories (BLAKE2 PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features (BLAKE2 PRIVATE cxx_nonstatic_member_init cxx_constexpr cxx_generic_lambdas)
