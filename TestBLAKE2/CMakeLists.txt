
cmake_minimum_required (VERSION 3.0)

include_directories ("${CMAKE_SOURCE_DIR}/BLAKE2/include"
                     "${CMAKE_SOURCE_DIR}/Catch/include")

add_executable (TestBLAKE2 src/main.cpp src/test-blake2.cpp src/TestVector.cpp)
target_link_libraries (TestBLAKE2 BLAKE2)
set_source_files_properties (src/main.cpp PROPERTIES COTIRE_EXCLUDED TRUE)

add_test (NAME TestBLAKE2
          COMMAND TestBLAKE2)
target_compile_features (TestBLAKE2 PRIVATE cxx_auto_type)
set_target_properties (TestBLAKE2 PROPERTIES COTIRE_CXX_PREFIX_HEADER_INIT "src/common.h")

cotire (TestBLAKE2)
