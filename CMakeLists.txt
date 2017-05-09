
cmake_minimum_required (VERSION 3.8)

project (BLAKE2
    LANGUAGES CXX C
    VERSION 1.0.3.0)

function (setvar_default var_)
    if (NOT DEFINED ${var_})
        set (${var_} ${ARGN} PARENT_SCOPE)
    endif ()
endfunction ()

list (INSERT CMAKE_MODULE_PATH 0 "${CMAKE_SOURCE_DIR}/CMake")
setvar_default (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
setvar_default (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
setvar_default (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

option (USE_AVX2 "Compile with AVX2 instruction")

include (cotire)

# set (COTIRE_VERBOSE TRUE)
enable_testing ()

add_subdirectory (src)
add_subdirectory (test)
