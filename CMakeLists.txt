
cmake_minimum_required (VERSION 3.0)

project (BLAKE2 VERSION 1.0.0.0)

set (CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/CMake")

set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

include (cotire)

set (COTIRE_VERBOSE TRUE)
enable_testing ()

add_subdirectory (BLAKE2)
add_subdirectory (TestBLAKE2)