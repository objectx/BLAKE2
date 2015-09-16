
cmake_minimum_required (VERSION 3.0)

include_directories ("${PROJECT_SOURCE_DIR}/Catch/include")

set_source_files_properties (main.cpp PROPERTIES COTIRE_EXCLUDED TRUE)

set (TARGET_NAME "test-blake2")
add_executable (${TARGET_NAME} main.cpp test-blake2.cpp TestVector.cpp)
    target_link_libraries (${TARGET_NAME} BLAKE2)

add_test (NAME ${TARGET_NAME}
          COMMAND ${TARGET_NAME} "-r" "compact")
    target_compile_features (${TARGET_NAME} PRIVATE cxx_auto_type)
    set_target_properties (${TARGET_NAME} PROPERTIES COTIRE_CXX_PREFIX_HEADER_INIT "common.h")

cotire (${TARGET_NAME})
