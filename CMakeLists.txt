cmake_minimum_required(VERSION 2.8)

# Locate GTest
find_package(GTest REQUIRED)
add_subdirectory(${CMAKE_SOURCE_DIR}/cases)
include_directories(${GTEST_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/cases /home/lancerchao/openssl/include)
link_directories(${CMAKE_SOURCE_DIR}/cases)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive -std=c++11")

# Link runTests with what we want to test and the GTest and pthread library
# add imported target
add_library(sl STATIC IMPORTED)
# point the imported target at the real file
set_property(TARGET sl PROPERTY
             IMPORTED_LOCATION /home/lancerchao/openssl/libssl.a)
# add imported target
add_library(crypt STATIC IMPORTED)
# point the imported target at the real file
set_property(TARGET crypt PROPERTY
             IMPORTED_LOCATION /home/lancerchao/openssl/libcrypto.a)
add_executable(runTests main.cpp tests.cpp lib.cpp tls.cpp server.cpp)
target_link_libraries(runTests ${GTEST_LIBRARIES} pthread sl crypt dl cases)

add_custom_command(TARGET runTests PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy
                   ${CMAKE_SOURCE_DIR}/ca* $<TARGET_FILE_DIR:runTests>)
add_custom_command(TARGET runTests PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy
                   ${CMAKE_SOURCE_DIR}/small.txt $<TARGET_FILE_DIR:runTests>)
