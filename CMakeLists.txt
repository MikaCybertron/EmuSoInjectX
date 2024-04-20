cmake_minimum_required(VERSION 3.20)

project(EmuSoInjextX)
set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_subdirectory(vendor)
add_subdirectory(src)