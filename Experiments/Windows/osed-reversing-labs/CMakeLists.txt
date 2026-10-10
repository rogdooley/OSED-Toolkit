cmake_minimum_required(VERSION 3.21)
project(osed_reversing_labs C)

if(NOT MSVC)
  message(FATAL_ERROR "The Visual Studio build requires MSVC. Use the Makefile for Linux MinGW-w64 cross-compilation.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "Configure this project with -A Win32; the labs require PE32 x86 binaries.")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

function(add_lab target source aslr_enabled)
  add_executable(${target} ${source})
  target_compile_options(${target} PRIVATE /W4 /Od /Oy- /GS-)
  if(aslr_enabled)
    target_link_options(${target} PRIVATE /INCREMENTAL:NO /NXCOMPAT /DYNAMICBASE)
  else()
    target_link_options(${target} PRIVATE /INCREMENTAL:NO /NXCOMPAT /DYNAMICBASE:NO)
  endif()
endfunction()

add_lab(target01 src/target01/main.c FALSE)
target_link_libraries(target01 PRIVATE ws2_32)

add_lab(target02 src/target02/main.c TRUE)
target_link_libraries(target02 PRIVATE ws2_32)

add_lab(target03 src/target03/main.c FALSE)
