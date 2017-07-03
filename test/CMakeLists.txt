set(TESTAPP ghttp2cli)
set(TESTAPP_SRCS
	menu.c
	main.c
	avs.c
  mnu_auth.c
  mnu_avs.c
)

add_executable(${TESTAPP} ${TESTAPP_SRCS})
add_dependencies(${TESTAPP} ${PROJECT_NAME})
target_link_libraries(${TESTAPP} ${pkgs_LDFLAGS} "-L${CMAKE_BINARY_DIR} -l${PROJECT_NAME}")
install(TARGETS ${TESTAPP} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
