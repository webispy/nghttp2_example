cmake_minimum_required(VERSION 2.6)
project(ghttp2)

include(GNUInstallDirs)
include(FindPkgConfig)

pkg_check_modules(pkgs REQUIRED
  glib-2.0
  openssl
  libnghttp2
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -g -Wall -Wextra -fvisibility=hidden -fPIC -fdata-sections -ffunction-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wswitch-default -Wunreachable-code -Wpointer-arith -Waggregate-return -Wconversion")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter -Wno-missing-field-initializers -Wdeclaration-after-statement -Wcast-align")

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-as-needed -pie")
set(CMAKE_INSTALL_RPATH "${CMAKE_BINARY_DIR}")

foreach(flag ${pkgs_CFLAGS})
  set(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
endforeach(flag)

set(pkgs_LDFLAGS "${pkgs_LDFLAGS} -lhttp_parser")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -O2 -fPIE")

add_definitions("-DEXPORT_API=__attribute__((visibility(\"default\")))")
add_definitions("-DCONFIG_VERBOSE")
include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include)

set(SRCS
  src/verbose.c
  src/ghttp2.c
  src/request.c
  src/uri.c
  src/connection.c
  src/fdsource.c
)

add_library(${PROJECT_NAME} SHARED ${SRCS})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(${PROJECT_NAME} ${pkgs_LDFLAGS})
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION 0.1.0 SOVERSION 0 OUTPUT_NAME ${PROJECT_NAME})
install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

add_executable(ghttp2client main.c)
add_dependencies(ghttp2client ${PROJECT_NAME})
target_link_libraries(ghttp2client ${pkgs_LDFLAGS} "-L${CMAKE_BINARY_DIR} -l${PROJECT_NAME}")
install(TARGETS ghttp2client RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_subdirectory(test)

