cmake_minimum_required(VERSION 3.0)

set(CMAKE_CXX_STANDARD 14)

project(rdg LANGUAGES CXX)

file(GLOB_RECURSE SOURCES "*.cc" "*.h")

include_directories("src")

add_executable(${PROJECT_NAME} ${SOURCES})

set_target_properties(${PROJECT_NAME}
  PROPERTIES
    OUTPUT_NAME "rdg"
)