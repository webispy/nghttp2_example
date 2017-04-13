cmake_minimum_required(VERSION 2.6)
project(client)

include(FindPkgConfig)

pkg_check_modules(pkgs REQUIRED
  openssl
  libnghttp2
)

add_definitions("-DNGHTTP2_NORETURN=")

foreach(flag ${pkgs_CFLAGS})
  set(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
endforeach(flag)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(${PROJECT_NAME} main.c client.c sockutil.c verbose.c)
target_link_libraries(${PROJECT_NAME} ${pkgs_LDFLAGS})

