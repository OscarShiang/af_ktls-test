cmake_minimum_required(VERSION 2.8)

# Locate GTest
find_package(GTest REQUIRED)
add_subdirectory(${CMAKE_SOURCE_DIR}/cases)
include_directories(${GTEST_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/cases)
link_directories(${CMAKE_SOURCE_DIR}/cases)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

# Link runTests with what we want to test and the GTest and pthread library
add_executable(runTests main.cpp tests.cpp lib.c tls.c)
target_link_libraries(runTests ${GTEST_LIBRARIES} pthread ssl crypto cases)

add_custom_command(TARGET runTests PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy
                   ${CMAKE_SOURCE_DIR}/ca* $<TARGET_FILE_DIR:runTests>)
add_custom_command(TARGET runTests PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy
                   ${CMAKE_SOURCE_DIR}/small.txt $<TARGET_FILE_DIR:runTests>)
