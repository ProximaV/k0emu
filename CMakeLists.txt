cmake_minimum_required(VERSION 3.16)
project(k0emu LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(K0EMU_CORE_SOURCES
    src/cpu.cpp
    src/debugger.cpp
    src/disasm.cpp
    src/kx2_peripherals.cpp
    src/log.cpp
    src/machine.cpp
    src/memory.cpp
)

add_library(k0emu_core STATIC ${K0EMU_CORE_SOURCES})

target_include_directories(k0emu_core
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

if(WIN32)
    target_compile_definitions(k0emu_core PUBLIC _CRT_SECURE_NO_WARNINGS NOMINMAX)
    target_link_libraries(k0emu_core PUBLIC ws2_32)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(k0emu_core PUBLIC Threads::Threads)
endif()

if(MSVC)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}" K0EMU_SRC_PREFIX_NATIVE)
    target_compile_options(k0emu_core PUBLIC
        "/d1trimfile:${K0EMU_SRC_PREFIX_NATIVE}\\"
    )
    add_link_options($<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>)
else()
    target_compile_options(k0emu_core PUBLIC
        "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}/="
    )
endif()

add_executable(k0emu src/main.cpp)
target_link_libraries(k0emu PRIVATE k0emu_core)

add_executable(k0emu_tests tests/k0emu_tests.cpp)
target_link_libraries(k0emu_tests PRIVATE k0emu_core)
enable_testing()
add_test(NAME k0emu_tests COMMAND k0emu_tests)

if(DEFINED ENV{IDA_SDK_DIR})
    set(_DEFAULT_IDA_SDK_DIR "$ENV{IDA_SDK_DIR}")
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../include/idd.hpp")
    set(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../..")
else()
    set(_DEFAULT_IDA_SDK_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../ida-sdk-main/src")
endif()
set(IDA_SDK_DIR "${_DEFAULT_IDA_SDK_DIR}" CACHE PATH "Path to IDA SDK src directory")

set(_IDA_LIB_PATH "")
if(EXISTS "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib")
elseif(EXISTS "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
    set(_IDA_LIB_PATH "${IDA_SDK_DIR}/lib/x64_win_64/ida.lib")
endif()

if(EXISTS "${IDA_SDK_DIR}/include/idd.hpp" AND _IDA_LIB_PATH)
    add_library(k0dbg SHARED src/ida_dbg_plugin.cpp)
    set_target_properties(k0dbg PROPERTIES
        PREFIX ""
        OUTPUT_NAME "k0dbg"
    )
    target_include_directories(k0dbg PRIVATE "${IDA_SDK_DIR}/include")
    if(MSVC)
        get_filename_component(_IDA_SDK_DIR_ABS "${IDA_SDK_DIR}" ABSOLUTE)
        file(TO_NATIVE_PATH "${_IDA_SDK_DIR_ABS}" _IDA_SDK_DIR_NATIVE)
        target_compile_options(k0dbg PRIVATE
            "/d1trimfile:${_IDA_SDK_DIR_NATIVE}\\"
        )
    else()
        target_compile_options(k0dbg PRIVATE
            "-ffile-prefix-map=${IDA_SDK_DIR}/=ida-sdk/"
        )
    endif()
    target_compile_definitions(k0dbg PRIVATE
        __NT__
        __EA64__
        __X64__
        _CRT_SECURE_NO_WARNINGS
        NOMINMAX
    )
    target_link_libraries(k0dbg PRIVATE
        k0emu_core
        "${_IDA_LIB_PATH}"
    )
endif()
