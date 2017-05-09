
cmake_minimum_required (VERSION 3.8)

include_directories ("${PROJECT_SOURCE_DIR}/Catch/include"
                     $<TARGET_PROPERTY:BLAKE2,INTERFACE_INCLUDE_DIRECTORIES>)

set (SOURCE_FILES test-blake2.cpp TestVector.cpp)
set (HEADER_FILES common.h manips.h)
set (TARGET_NAME "test-blake2")

add_library (${TARGET_NAME}_obj OBJECT ${SOURCE_FILES} ${HEADER_FILES})
target_compile_features (${TARGET_NAME}_obj PRIVATE cxx_std_14)
set_target_properties (${TARGET_NAME}_obj PROPERTIES COTIRE_CXX_PREFIX_HEADER_INIT "common.h")

add_executable (${TARGET_NAME} main.cpp $<TARGET_OBJECTS:${TARGET_NAME}_obj>)
target_link_libraries (${TARGET_NAME} BLAKE2)
target_compile_features (${TARGET_NAME} PRIVATE cxx_std_14)

add_test (NAME ${TARGET_NAME}
          COMMAND ${TARGET_NAME} "-r" "compact")

if (COMMAND cotire)
    cotire (${TARGET_NAME}_obj)
endif ()

