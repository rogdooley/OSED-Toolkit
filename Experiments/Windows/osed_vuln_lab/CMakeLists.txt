cmake_minimum_required(VERSION 3.24)
project(osed_vuln_lab C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

option(TARGET_X86 "Build 32-bit binaries" ON)
set(LAB_PROFILE "easy" CACHE STRING "Lab profile: easy dep aslr_dep seh")
set_property(CACHE LAB_PROFILE PROPERTY STRINGS easy dep aslr_dep seh)
set(HELPER_ASLR "OFF" CACHE STRING "Build helper DLL with ASLR: ON/OFF")

if(MSVC)
  if(TARGET_X86)
    add_compile_options(/arch:IA32)
  endif()

  # Shared compiler defaults for lab reproducibility.
  add_compile_options(/W4 /Zi /GS-)

  if(LAB_PROFILE STREQUAL "easy")
    set(LAB_LINK_FLAGS "/DYNAMICBASE:NO /NXCOMPAT:NO /SAFESEH:NO")
  elseif(LAB_PROFILE STREQUAL "dep")
    set(LAB_LINK_FLAGS "/DYNAMICBASE:NO /NXCOMPAT /SAFESEH:NO")
  elseif(LAB_PROFILE STREQUAL "aslr_dep")
    set(LAB_LINK_FLAGS "/DYNAMICBASE /NXCOMPAT /SAFESEH:NO")
  elseif(LAB_PROFILE STREQUAL "seh")
    set(LAB_LINK_FLAGS "/DYNAMICBASE:NO /NXCOMPAT:NO /SAFESEH:NO")
  else()
    message(FATAL_ERROR "Unknown LAB_PROFILE: ${LAB_PROFILE}")
  endif()

  if(HELPER_ASLR STREQUAL "ON")
    set(HELPER_LINK_FLAGS "/DYNAMICBASE /NXCOMPAT")
  else()
    set(HELPER_LINK_FLAGS "/DYNAMICBASE:NO /NXCOMPAT:NO")
  endif()
endif()

add_library(osedhelper SHARED
  src/osedhelper.c
)
target_include_directories(osedhelper PRIVATE include)
target_compile_definitions(osedhelper PRIVATE WIN32_LEAN_AND_MEAN)
if(MSVC)
  target_link_options(osedhelper PRIVATE ${HELPER_LINK_FLAGS})
endif()

add_executable(osed_vulnsvc
  src/osed_vulnsvc.c
)
target_include_directories(osed_vulnsvc PRIVATE include)
target_compile_definitions(osed_vulnsvc PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
target_link_libraries(osed_vulnsvc PRIVATE ws2_32 osedhelper)
if(MSVC)
  target_link_options(osed_vulnsvc PRIVATE ${LAB_LINK_FLAGS})
endif()

message(STATUS "LAB_PROFILE=${LAB_PROFILE}")
message(STATUS "HELPER_ASLR=${HELPER_ASLR}")
