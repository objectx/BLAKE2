
cmake_minimum_required (VERSION 3.8)

include_directories ("${PROJECT_SOURCE_DIR}/ext"
                     $<TARGET_PROPERTY:BLAKE2,INTERFACE_INCLUDE_DIRECTORIES>)

set (SOURCE_FILES test-blake2.cpp TestVector.cpp main.cpp)
set (HEADER_FILES common.h manips.h)
set (TARGET_NAME "test-blake2")

add_executable (${TARGET_NAME} ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries (${TARGET_NAME} PRIVATE BLAKE2 rapidcheck rapidcheck_catch)
target_compile_features (${TARGET_NAME} PRIVATE cxx_std_14)
set_target_properties (${TARGET_NAME} PROPERTIES
        COTIRE_CXX_PREFIX_HEADER_INIT "common.h")
set_source_files_properties ("main.cpp" PROPERIES COTIRE_EXCLUDED YES)

add_test (NAME ${TARGET_NAME}
          COMMAND ${TARGET_NAME} "-r" "compact")

if (COMMAND cotire)
    # cotire (${TARGET_NAME})
endif ()
