cmake_minimum_required(VERSION 2.6)
project(client)

include(FindPkgConfig)

pkg_check_modules(pkgs REQUIRED
  glib-2.0
  openssl
  libnghttp2
)

add_definitions("-DNGHTTP2_NORETURN=")

foreach(flag ${pkgs_CFLAGS})
  set(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
endforeach(flag)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")

include_directories(${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/src)

add_executable(${PROJECT_NAME} main.c client.c sockutil.c verbose.c src/http2.c)
target_link_libraries(${PROJECT_NAME} ${pkgs_LDFLAGS} "-lhttp_parser")

