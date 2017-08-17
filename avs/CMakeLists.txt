set(AVS_SRCS
	avs.c
	amic.c
	anet.c
	areq.c
	autil.c
)

add_library(avs SHARED ${AVS_SRCS})
add_dependencies(avs ${PROJECT_NAME})
target_link_libraries(avs ${pkgs_LDFLAGS} "-L${CMAKE_BINARY_DIR} -l${PROJECT_NAME} -pthread -Wl,--rpath=${CMAKE_BINARY_DIR}")
set_target_properties(avs PROPERTIES VERSION 0.1.0 SOVERSION 0 OUTPUT_NAME avs)
install(TARGETS avs LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

set(TESTAPP ghttp2cli)
set(TESTAPP_SRCS
	menu.c
	main.c
	mnu_auth.c
	mnu_avs.c
	mnu_record.c
)

add_executable(${TESTAPP} ${TESTAPP_SRCS})
add_dependencies(${TESTAPP} avs)
target_link_libraries(${TESTAPP} ${pkgs_LDFLAGS} "-L${CMAKE_CURRENT_BINARY_DIR} -lavs -Wl,--rpath=${CMAKE_CURRENT_BINARY_DIR}")
install(TARGETS ${TESTAPP} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

set(UNIT_TESTS
	unit-autil
)

foreach(tc ${UNIT_TESTS})
	add_executable(${tc} ${tc}.c)
	add_dependencies(${tc} avs)
	target_link_libraries(${tc} ${pkgs_LDFLAGS} "-L${CMAKE_CURRENT_BINARY_DIR} -lavs -Wl,--rpath=${CMAKE_CURRENT_BINARY_DIR}")
	add_test(NAME ${tc} COMMAND ${tc})
endforeach(tc)

