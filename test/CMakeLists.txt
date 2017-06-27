SET(TESTAPP cli)
SET(TESTAPP_SRCS
	menu.c
	main.c
	avs.c
  mnu_auth.c
  mnu_avs.c
  ../src/verbose.c
  ../src/http2.c
  ../src/fdsource.c
)

ADD_EXECUTABLE(${TESTAPP} ${TESTAPP_SRCS})
TARGET_LINK_LIBRARIES(${TESTAPP} ${pkgs_LDFLAGS} "-lhttp_parser")

