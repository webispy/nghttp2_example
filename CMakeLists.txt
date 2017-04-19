cmake_minimum_required(VERSION 2.6)
project(client)

include(FindPkgConfig)

pkg_check_modules(pkgs REQUIRED
  glib-2.0
  openssl
  libnghttp2
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -g -Wall -Wextra -fPIC -fdata-sections -ffunction-sections -Wl,--gc-sections")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wswitch-default -Wunreachable-code -Wpointer-arith -Waggregate-return -Wconversion")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-parameter -Wno-missing-field-initializers -Wdeclaration-after-statement -Wcast-align")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -O2 -fPIE")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-as-needed -pie")

add_definitions("-DNGHTTP2_NORETURN=")

foreach(flag ${pkgs_CFLAGS})
  set(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
endforeach(flag)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src)

add_executable(${PROJECT_NAME} main.c src/verbose.c src/http2.c)
target_link_libraries(${PROJECT_NAME} ${pkgs_LDFLAGS} "-lhttp_parser")

