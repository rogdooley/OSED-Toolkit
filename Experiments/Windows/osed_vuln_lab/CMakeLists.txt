cmake_minimum_required(VERSION 3.12)
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

  # Preserve simple function boundaries and stack frames for beginner IDA work.
  # Release controls the runtime/link layout; this lab intentionally stays unoptimized.
  add_compile_options(/W4 /Zi /GS- /Od /Ob0 /Oy-)

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
  set_property(TARGET osedhelper APPEND_STRING PROPERTY LINK_FLAGS " ${HELPER_LINK_FLAGS}")
endif()

add_executable(osed_vulnsvc
  src/osed_vulnsvc.c
)
target_include_directories(osed_vulnsvc PRIVATE include)
target_compile_definitions(osed_vulnsvc PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
target_link_libraries(osed_vulnsvc PRIVATE ws2_32 osedhelper)
if(MSVC)
  set_property(TARGET osed_vulnsvc APPEND_STRING PROPERTY LINK_FLAGS " ${LAB_LINK_FLAGS}")
endif()

set(STUDENT_BUNDLE_DIR "${CMAKE_BINARY_DIR}/student_bundle")
add_custom_target(student_bundle
  COMMAND ${CMAKE_COMMAND} -E make_directory "${STUDENT_BUNDLE_DIR}"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "$<TARGET_FILE:osed_vulnsvc>"
          "${STUDENT_BUNDLE_DIR}/osed_vulnsvc.exe"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "$<TARGET_FILE:osedhelper>"
          "${STUDENT_BUNDLE_DIR}/osedhelper.dll"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/student/START_HERE.md"
          "${STUDENT_BUNDLE_DIR}/START_HERE.md"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/student/protocol_notes.md"
          "${STUDENT_BUNDLE_DIR}/protocol_notes.md"
  DEPENDS osed_vulnsvc osedhelper
  COMMENT "Creating spoiler-free student bundle"
)

message(STATUS "LAB_PROFILE=${LAB_PROFILE}")
message(STATUS "HELPER_ASLR=${HELPER_ASLR}")
