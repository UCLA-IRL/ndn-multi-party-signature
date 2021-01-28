# cmake version to be used
cmake_minimum_required(VERSION 3.12)
include(ExternalProject)
include(FetchContent)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/CMake/Modules)
set(BLS_ROOT ${CMAKE_SOURCE_DIR}/external/bls)
set(MCL_ROOT ${CMAKE_SOURCE_DIR}/external/mcl)

message("Check dependency: MCL")
if((NOT EXISTS "${MCL_ROOT}/lib/libmcl.a") OR (NOT EXISTS "${MCL_ROOT}/lib/libmclbn384_256.a"))
   message("Build dependency from MCL: libmcl.a, lib/libmclbn384_256.a")
   execute_process(COMMAND make lib/libmcl.a lib/libmclbn384_256.a
   WORKING_DIRECTORY ${MCL_ROOT})
endif((NOT EXISTS "${MCL_ROOT}/lib/libmcl.a") OR (NOT EXISTS "${MCL_ROOT}/lib/libmclbn384_256.a"))

message("Check dependency: BLS")
if(NOT EXISTS "${BLS_ROOT}/lib/libbls384_256.a")
   message("Build dependency from BLS: libbls384_256.a")
   execute_process(COMMAND make BLS_ETH=1 MCL_USE_GMP=0 lib/libbls384_256.a
    WORKING_DIRECTORY ${BLS_ROOT})
endif(NOT EXISTS "${BLS_ROOT}/lib/libbls384_256.a")

# project name
project(ndnmps
        VERSION 0.1
        DESCRIPTION "A multi-signature library for NDN")

# flags
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

# dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(NDN_CXX REQUIRED libndn-cxx)
find_package(GMP REQUIRED)

# files
file(GLOB NDNMPS_SRC
    "./src/*.hpp"
    "./src/*.cpp")

# include
include_directories(${NDN_CXX_INCLUDE_DIRS})
include_directories(${GMP_INCLUDES})
include_directories(${MCL_ROOT}/include)
include_directories(${BLS_ROOT}/include)

# link
link_directories(${NDN_CXX_LIBRARY_DIRS})

# target
add_library(ndnmps SHARED "")
target_sources(ndnmps PRIVATE ${NDNMPS_SRC})
target_include_directories(ndnmps PUBLIC ./include)
target_include_directories(ndnmps PRIVATE ./src)
target_compile_options(ndnmps PUBLIC ${NDN_CXX_CFLAGS})
target_link_libraries(ndnmps PUBLIC
${NDN_CXX_LIBRARIES}
${GMP_LIBRARIES}
${CMAKE_SOURCE_DIR}/external/bls/lib/libbls384_256.a
${CMAKE_SOURCE_DIR}/external/mcl/lib/libmclbn384_256.a
${CMAKE_SOURCE_DIR}/external/mcl/lib/libmcl.a)

if (HAVE_TESTS)
    message("Added Unit Tests")
    add_compile_definitions(NDNMPS_HAVE_TESTS)
    add_subdirectory(tests)
endif(HAVE_TESTS)

#configure
set(PKG_CONFIG_REQUIRES
        "libndn-cxx >= ${NDN_CXX_VERSION}"
        )
set(PKG_CONFIG_LIBS
        "-L\${libdir} -l${PROJECT_NAME}"
        )
set(PKG_CONFIG_CFLAGS
        "-I\${includedir} -I\${includedir}/${PROJECT_NAME}/external"
        )
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake-pkgconfig.pc.in"
        "${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.pc")

include(GNUInstallDirs)
install(TARGETS ndnmps
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ndnmps DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h*")
install(DIRECTORY external/bls/include/bls DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ndnmps/external
        FILES_MATCHING PATTERN "*.h*")
install(DIRECTORY external/mcl/include/mcl DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ndnmps/external
        FILES_MATCHING PATTERN "*.h*")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/lib${PROJECT_NAME}.pc"
        DESTINATION lib/pkgconfig)