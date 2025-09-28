cmake_minimum_required(VERSION 3.15...4.00)
project(procjet LANGUAGES C)
set(SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/main)
set(PHDRS ${CMAKE_CURRENT_SOURCE_DIR}/src/include)
set(DEPS ${CMAKE_CURRENT_SOURCE_DIR}/vendors)
add_subdirectory(${DEPS}/ptools ${DEPS}/ptools/build)
add_executable(procjet 
          ${SRC}/pilot.c 
          ${SRC}/mem.c
          ${SRC}/jet.c
          ${SRC}/stub.c)
target_include_directories(procjet PRIVATE ${PHDRS})
target_link_libraries(procjet ptools)
