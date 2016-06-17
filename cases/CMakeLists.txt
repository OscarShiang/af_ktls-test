include_directories(${GTEST_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}
                    ${CMAKE_SOURCE_DIR}/cases)
add_library(cases sockopt.cpp unbinded.cpp)
