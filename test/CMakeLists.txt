
cmake_minimum_required (VERSION 3.0)

include_directories ("${PROJECT_SOURCE_DIR}/Catch/include")

set_source_files_properties (main.cpp PROPERTIES COTIRE_EXCLUDED TRUE)

set (SOURCE_FILES test-blake2.cpp TestVector.cpp main.cpp)
set (HEADER_FILES common.h manips.h)
set (TARGET_NAME "test-blake2")

add_executable (${TARGET_NAME} ${SOURCE_FILES} ${HEADER_FILES})
    target_link_libraries (${TARGET_NAME} BLAKE2)

add_test (NAME ${TARGET_NAME}
          COMMAND ${TARGET_NAME} "-r" "compact")
    target_compile_features (${TARGET_NAME} PRIVATE cxx_auto_type)
    set_target_properties (${TARGET_NAME} PROPERTIES COTIRE_CXX_PREFIX_HEADER_INIT "common.h")

cotire (${TARGET_NAME})
