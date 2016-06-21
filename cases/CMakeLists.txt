set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
include_directories(${GTEST_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}
                    ${CMAKE_SOURCE_DIR}/cases)
add_library(cases sockopt.cpp unbinded.cpp)
