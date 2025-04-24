cmake_minimum_required(VERSION 3.5)
project(libnsspem C)
enable_testing()

# use pkg-config to detect CFLAGS and LDFLAGS
find_package(PkgConfig REQUIRED)
pkg_check_modules(NSS REQUIRED "nss")
include_directories(${NSS_INCLUDE_DIRS})
link_directories(${NSS_LIBRARY_DIRS})

# some distros (e.g. Gentoo Linux) put <blapi.h> to a separate directory
if(EXISTS "${NSS_INCLUDEDIR}/private/")
    include_directories("${NSS_INCLUDEDIR}/private")
endif()

# some distros (e.g. Fedora) put <nssck.api> to a separate directory
if(EXISTS "${NSS_INCLUDEDIR}/templates/")
    include_directories("${NSS_INCLUDEDIR}/templates")
endif()

include(CheckIncludeFile)
set(CMAKE_REQUIRED_INCLUDES ${NSS_INCLUDE_DIRS})
check_include_file(lowkeyti.h LOWKEYTI_H)
if(LOWKEYTI_H)
    add_definitions(-DHAVE_LOWKEYTI_H)
endif()

include(CheckFunctionExists)
set(CMAKE_REQUIRED_LIBRARIES nsspem nssckfw nssb freebl ${NSS_LIBRARIES})
check_function_exists(NSSCKFWSlot_GetSlotID GETSLOTID_FN)
if(GETSLOTID_FN)
    add_definitions(-DHAVE_GETSLOTID_FN)
endif()

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
add_library(nsspem SHARED ${MODULES})
target_link_libraries(${CMAKE_REQUIRED_LIBRARIES})
set_target_properties(nsspem PROPERTIES LINK_FLAGS -Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/nsspem.def)

# install libnsspem.so
include(GNUInstallDirs)
install(TARGETS nsspem DESTINATION ${CMAKE_INSTALL_LIBDIR})
