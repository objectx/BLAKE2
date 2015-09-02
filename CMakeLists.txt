
cmake_minimum_required (VERSION 3.0)

project (BLAKE2
    LANGUAGES CXX C
    VERSION 1.0.0.0)

function (setvar_default var_)
    if (NOT DEFINED ${var_})
        set (${var_} ${ARGN} PARENT_SCOPE)
    endif ()
endfunction ()

setvar_default (CMAKE_MODULE_PATH              "${CMAKE_SOURCE_DIR}/CMake")
setvar_default (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
setvar_default (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
setvar_default (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

include (cotire)

# set (COTIRE_VERBOSE TRUE)
enable_testing ()

add_subdirectory (BLAKE2)
add_subdirectory (TestBLAKE2)
