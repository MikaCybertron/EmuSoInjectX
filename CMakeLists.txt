cmake_minimum_required(VERSION 3.20)

project(EmuSoInjextX)
set(CMAKE_CXX_STANDARD 17)

include_directories(include)

set(RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(vendor)
add_subdirectory(src)