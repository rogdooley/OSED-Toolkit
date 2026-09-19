cmake_minimum_required(VERSION 3.24)
project(osed_format_string_labs C)

if(NOT MSVC)
  message(FATAL_ERROR "These labs require the 32-bit Microsoft C runtime and MSVC.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "Configure with -A Win32. The exercises assume x86 pointers and cdecl.")
endif()

set(CMAKE_C_STANDARD 11)

function(add_format_lab target source)
  add_executable(${target} ${source} src/lab_io.c)
  target_include_directories(${target} PRIVATE include)
  target_compile_definitions(${target} PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_compile_options(${target} PRIVATE /W4 /Od /Oy- /GS- /Zi)
  target_link_options(${target} PRIVATE /DEBUG /INCREMENTAL:NO /DYNAMICBASE:NO /NXCOMPAT)
endfunction()

add_format_lab(fmt01_stack_leak src/fmt01_stack_leak.c)
add_format_lab(fmt02_string_read src/fmt02_string_read.c)
add_format_lab(fmt03_controlled_write src/fmt03_controlled_write.c)
add_format_lab(fmt04_function_pointer src/fmt04_function_pointer.c)

add_executable(fmt05_service src/fmt05_service.c)
target_compile_definitions(fmt05_service PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
target_compile_options(fmt05_service PRIVATE /W4 /Od /Oy- /GS- /Zi)
target_link_libraries(fmt05_service PRIVATE ws2_32)
target_link_options(fmt05_service PRIVATE /DEBUG /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT)
