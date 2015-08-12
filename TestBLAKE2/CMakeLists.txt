
cmake_minimum_required (VERSION 3.0)

include_directories ("${CMAKE_SOURCE_DIR}/BLAKE2/include")

add_executable (TestBLAKE2 src/main.cpp src/TestVector.cpp)
target_link_libraries (TestBLAKE2 BLAKE2)

add_test (NAME TestBLAKE2
          COMMAND TestBLAKE2)
target_compile_features (TestBLAKE2 PRIVATE cxx_auto_type)