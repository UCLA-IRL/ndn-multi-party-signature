# cmake version to be used
cmake_minimum_required(VERSION 3.12)
include(ExternalProject)
include(FetchContent)

if(NOT "${CMAKE_SOURCE_DIR}/external/bls/lib/libbls384_256.a")
   execute_process(COMMAND make lib/libmcl.a
   WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/external/mcl)
   execute_process(COMMAND make BLS_ETH=1 MCL_USE_GMP=0 lib/libbls384_256.a
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/external/bls)
endif(NOT "${CMAKE_SOURCE_DIR}/external/bls/lib/libbls384_256.a")

FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.7.3)

FetchContent_GetProperties(json)
if(NOT json_POPULATED)
  FetchContent_Populate(json)
  add_subdirectory(${json_SOURCE_DIR} ${json_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# project name
project(ndnmps)

# flags
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

# dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(NDN_CXX REQUIRED IMPORTED_TARGET libndn-cxx)

set(BLS_ROOT ${CMAKE_SOURCE_DIR}/external/bls)
set(MCL_ROOT ${CMAKE_SOURCE_DIR}/external/mcl)

# files
file(GLOB NDN_MPS_SRC
    "./src/*.hpp"
    "./src/*.cpp"
    "./include/ndnmps/*.hpp")

# include
include_directories(${NDN_CXX_INCLUDE_DIRS})
include_directories(${MCL_ROOT}/include)
include_directories(${BLS_ROOT}/include)

# link
link_directories(${NDN_CXX_LIBRARY_DIRS})

# target
add_library(ndnmps SHARED "")
target_sources(ndnmps PRIVATE ${NDN_MPS_SRC})
target_include_directories(ndnmps PUBLIC ./include)
target_include_directories(ndnmps PRIVATE ./src)
target_link_libraries(ndnmps PUBLIC
PkgConfig::NDN_CXX
${CMAKE_SOURCE_DIR}/external/mcl/lib/libmcl.a
${CMAKE_SOURCE_DIR}/external/bls/lib/libbls384_256.a
nlohmann_json::nlohmann_json)

add_executable(unit-test ./tests/unit-test.cpp)
target_include_directories(unit-test PRIVATE ./src)
target_link_libraries(unit-test PUBLIC ndnmps)

install(TARGETS ndnmps
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})