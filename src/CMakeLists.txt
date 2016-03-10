project(libnsspem C)
cmake_minimum_required(VERSION 2.8)

# use pkg-config to detect CFLAGS and LDFLAGS
find_package(PkgConfig REQUIRED)
pkg_check_modules(NSS REQUIRED "nss")
include_directories(${NSS_INCLUDE_DIRS})
link_directories(${NSS_LIBRARY_DIRS})

# modules used to build libnsspem.so
set(MODULES
    anchor.c
    ckpemver.c
    constants.c
    pargs.c
    pfind.c
    pinst.c
    pobject.c
    prsa.c
    psession.c
    pslot.c
    ptoken.c
    rsawrapr.c
    util.c)

# rules to create libnsspem.so
# FIXME: should we really link nssckfw.a, nssb.a and freebl.a static libs?
add_library(nsspem SHARED ${MODULES})
target_link_libraries(nsspem nssckfw nssb freebl ${NSS_LIBRARIES})
set_target_properties(nsspem PROPERTIES LINK_FLAGS -Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/nsspem.def)
install(TARGETS nsspem DESTINATION lib)
