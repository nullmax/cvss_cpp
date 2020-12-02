cmake_minimum_required(VERSION 3.0.0)
project(cvss_cpp VERSION 0.1.0)

include(CTest)
enable_testing()

include_directories("${PROJECT_SOURCE_DIR}/cvss")
add_subdirectory(cvss)

add_executable(cvss_cpp main.cpp)
target_link_libraries(cvss_cpp cvss)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
