cmake_minimum_required(VERSION 3.15...4.00)
project(procjet)
add_executable(procjet 
	${CMAKE_SOURCE_DIR}/src/main/pilot.c 
	${CMAKE_SOURCE_DIR}/src/main/mem.c
	${CMAKE_SOURCE_DIR}/src/main/jet.c
	${CMAKE_SOURCE_DIR}/src/main/stub.c
)
target_include_directories(procjet PRIVATE ${CMAKE_SOURCE_DIR}/src/include)
