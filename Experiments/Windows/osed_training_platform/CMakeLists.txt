cmake_minimum_required(VERSION 3.24)
project(osed_training_platform C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(TRAINING_X86 "Build 32-bit binaries" ON)
set(TRAINING_PROFILE "analysis" CACHE STRING "Build profile: analysis dep aslr_dep")
set_property(CACHE TRAINING_PROFILE PROPERTY STRINGS analysis dep aslr_dep)

if(MSVC)
  add_compile_options(/W4 /GS /Zi)
  if(TRAINING_X86)
    add_compile_options(/arch:IA32)
  endif()

  if(TRAINING_PROFILE STREQUAL "analysis")
    set(TRAINING_LINK_FLAGS /DYNAMICBASE:NO /NXCOMPAT:NO)
  elseif(TRAINING_PROFILE STREQUAL "dep")
    set(TRAINING_LINK_FLAGS /DYNAMICBASE:NO /NXCOMPAT)
  elseif(TRAINING_PROFILE STREQUAL "aslr_dep")
    set(TRAINING_LINK_FLAGS /DYNAMICBASE /NXCOMPAT)
  else()
    message(FATAL_ERROR "Unknown TRAINING_PROFILE: ${TRAINING_PROFILE}")
  endif()
endif()

add_library(osedtp_protocol STATIC
  protocol/protocol.c
)
target_include_directories(osedtp_protocol PUBLIC protocol)

add_library(osedtp_helper SHARED
  helper/helper.c
)
target_include_directories(osedtp_helper PRIVATE helper protocol)
target_compile_definitions(osedtp_helper PRIVATE WIN32_LEAN_AND_MEAN OSEDTP_HELPER_EXPORTS)

add_library(gadgetlib SHARED
  gadgetlib/gadgetlib.c
)
target_include_directories(gadgetlib PRIVATE gadgetlib protocol)
target_compile_definitions(gadgetlib PRIVATE WIN32_LEAN_AND_MEAN GADGETLIB_EXPORTS)

add_executable(osedtp_service
  service/main.c
  service/config.c
  service/network.c
  service/session.c
  service/dispatch.c
  service/handlers.c
  service/logging.c
)
target_include_directories(osedtp_service PRIVATE service protocol helper gadgetlib)
target_compile_definitions(osedtp_service PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
target_link_libraries(osedtp_service PRIVATE ws2_32 osedtp_protocol osedtp_helper gadgetlib)

add_executable(osedtp_client
  client/client.c
)
target_include_directories(osedtp_client PRIVATE client protocol)
target_compile_definitions(osedtp_client PRIVATE WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
target_link_libraries(osedtp_client PRIVATE ws2_32 osedtp_protocol)

if(MSVC)
  target_link_options(osedtp_helper PRIVATE ${TRAINING_LINK_FLAGS})
  target_link_options(gadgetlib PRIVATE ${TRAINING_LINK_FLAGS})
  target_link_options(osedtp_service PRIVATE ${TRAINING_LINK_FLAGS})
  target_link_options(osedtp_client PRIVATE ${TRAINING_LINK_FLAGS})
endif()

message(STATUS "TRAINING_PROFILE=${TRAINING_PROFILE}")
message(STATUS "TRAINING_X86=${TRAINING_X86}")
