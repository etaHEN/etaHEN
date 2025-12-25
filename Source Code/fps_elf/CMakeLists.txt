cmake_minimum_required (VERSION 3.20)

set(basename "fps_elf")
project(${basename} C CXX ASM)

# Language Standard Defaults
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_EXTENSIONS ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)

# Check for sub-project as part of main build or external build
if (NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	set(IS_SUBPROJECT TRUE)
else()
	set(IS_SUBPROJECT FALSE)
endif()

message("IS_SUBPROJECT: ${IS_SUBPROJECT}")

set(D_CWD "${CMAKE_CURRENT_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${D_CWD}/../daemon/assets)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${D_CWD}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${D_CWD}/bin)	# static libs are archive
set(D_SRC ${D_CWD}/src)

# Headers
include_directories	(SYSTEM "${PS5_PAYLOAD_SDK}")
include_directories	(SYSTEM "${PS5_PAYLOAD_SDK}/include")

add_executable(${PROJECT_NAME})
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "${PROJECT_NAME}.elf")

# Must build with clang
if ("${CMAKE_CXX_COMPILER_ID}" MATCHES "[Cc]lang")
	set(IS_CLANG 1)
else()
	message(FATAL_ERROR "${PROJECT_NAME} is meant to be built with clang! CompilerID: ${CMAKE_CXX_COMPILER_ID}")
endif()

# Finalize main target sources
target_compile_options(${PROJECT_NAME} PUBLIC
	$<$<COMPILE_LANGUAGE:C>:${C_DEFS} ${C_FLAGS}>
	$<$<COMPILE_LANGUAGE:CXX>:${CXX_DEFS} ${CXX_FLAGS}>
	$<$<COMPILE_LANGUAGE:ASM>:${ASM_FLAGS}>
)

message("========== build: ${PROJECT_NAME} ==========")


file(GLOB SrcFiles ${D_SRC}/*.c ${D_SRC}/*.cpp ${D_SRC}/../include/*.h ${D_SRC}/../include/*.hpp ${D_SRC}/*.s ${D_SRC}/../../extern/tiny-json/*.cpp ${D_SRC}/../../extern/tiny-json/*.hpp ${D_SRC}/../../extern/cJSON/*.cpp ${D_SRC}/../../extern/cJSON/*.hpp ${D_SRC}/../../lib/backtrace.cpp)

set(CMAKE_C_FLAGS "--target=x86_64-sie-ps5 -DPPR -DPS5 -DPS5_FW_VERSION=${V_FW} ")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-nested-anon-types -Wno-gnu-anonymous-struct -Wno-zero-length-array -Wno-keyword-macro -fPIC -fPIE -march=znver2 -Wall -Werror -fstack-protector-all")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -DDEBUG -gfull -gdwarf-2 -O0 -pedantic -pedantic-errors")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 ")

target_sources(${PROJECT_NAME} PRIVATE ${SrcFiles})
target_include_directories(${PROJECT_NAME} PRIVATE "${D_CWD}/include")
target_link_directories	(${PROJECT_NAME} PUBLIC "${PROJECT_ROOT}/lib")
target_link_libraries	(${PROJECT_NAME} PUBLIC kernel SceGnmDriver)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Add post-build command
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} --remove-section .debug_info --remove-section .debug_abbrev --remove-section .debug_line --remove-section .debug_str --remove-section .debug_loc --remove-section .debug_aranges --remove-section .debug_ranges --remove-section .debug_pubnames --remove-section .debug_pubtypes --remove-section .debug_frame --strip-unneeded $<TARGET_FILE:${PROJECT_NAME}>
    COMMENT "Stripping debugging information from ${PROJECT_NAME}.elf"
)

