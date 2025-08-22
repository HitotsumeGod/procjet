cmake_minimum_required(VERSION 3.10)
project(procjet)
add_executable(procjet ${CMAKE_SOURCE_DIR}/src/main/pilot.c ${CMAKE_SOURCE_DIR}/src/main/mem.c)
target_include_directories(procjet PRIVATE ${CMAKE_SOURCE_DIR}/src/include)
