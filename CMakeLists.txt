cmake_minimum_required(VERSION 3.28)

project(klint LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(STATIC_BUILD "Build a fully static binary" OFF)
option(ENABLE_SANITIZERS "Enable ASan/UBSan" OFF)
option(WERROR "Treat warnings as errors" OFF)

add_executable(klint
  src/main.cpp
  src/cli.cpp
  src/output.cpp
  src/util.cpp
  src/kcore_reader.cpp
  src/scanners/hidden_lkm.cpp
  src/scanners/hidden_processes.cpp
  src/scanners/hidden_network_sockets.cpp
  src/scanners/ftrace_redirection.cpp
  src/scanners/unknown_kprobes.cpp
  src/scanners/syscall_table_integrity.cpp
  src/scanners/kernel_entrypoint_integrity.cpp
  src/scanners/bpf_rootkit_detection.cpp
)

target_include_directories(klint PRIVATE src)

find_package(nlohmann_json REQUIRED)
target_link_libraries(klint PRIVATE nlohmann_json::nlohmann_json)

target_compile_options(klint PRIVATE
  -Wall
  -Wextra
  -Wpedantic
  $<$<CONFIG:Release>:-O2>
  $<$<CONFIG:Debug>:-Og>
  $<$<CONFIG:Debug>:-g>
)

if (WERROR)
  target_compile_options(klint PRIVATE -Werror)
endif()

if (ENABLE_SANITIZERS)
  target_compile_options(klint PRIVATE -fsanitize=address,undefined)
  target_link_options(klint PRIVATE -fsanitize=address,undefined)
endif()

if (STATIC_BUILD)
  target_link_options(klint PRIVATE -static)
endif()
