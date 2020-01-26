cmake_minimum_required(VERSION 3.0)

project(libgpg-error VERSION 1.36.0 LANGUAGES C)

find_package(iconv NO_MODULE REQUIRED)

if(MSVC)
  set(CMAKE_DEBUG_POSTFIX "d")
endif()

# find_program(AWK awk)
# include(FindPackageHandleStandardArgs)
# find_package_handle_standard_args(AWK REQUIRED_VARS AWK)
# if(NOT ${AWK_FOUND})
#   message(FATAL_ERROR "AWK not found, can't generate error codes")
# endif()

add_library(libgpg-error
  cmake/libgpg-error.def
  src/argparse.c
  src/b64dec.c
  src/b64enc.c
  src/code-from-errno.c
  src/code-from-errno.h
  src/code-to-errno.c
  src/code-to-errno.h
  src/err-codes-sym.h
  src/err-codes.h
  src/err-sources-sym.h
  src/err-sources.h
  src/errnos-sym.h
  src/estream-printf.c
  src/estream-printf.h
  src/estream.c
  src/gettext.h
  # src/gpg-error.c
  src/gpg-error.h
  src/gpgrt-int.h
  src/init.c
  src/init.h
  src/lock.h
  src/logging.c
  src/strerror-sym.c
  src/strerror.c
  src/strsource-sym.c
  src/strsource.c
  src/syscall-clamp.c
  src/sysutils.c
  src/syscfg/lock-obj-pub.mingw32.h
  src/thread.h
  src/version.c
  src/visibility.c
  src/visibility.h
  src/w32-add.h
  src/w32-estream.c
  src/w32-gettext.c
  src/w32-lock-obj.h
  src/w32-lock.c
  src/w32-thread.c
)

if (WINDOWS_STORE)
  target_compile_definitions(libgpg-error PRIVATE MS_APP)
else()
  target_sources(libgpg-error
    PRIVATE
      src/w32-reg.c
  )
endif()

target_compile_definitions(libgpg-error
  PRIVATE
  HAVE_CONFIG_H
  PKGDATADIR=""
  _CRT_SECURE_NO_WARNINGS
  _CRT_NONSTDC_NO_WARNINGS)

target_include_directories(libgpg-error
  PRIVATE
  $<BUILD_INTERFACE:.;cmake;src;src/syscfg;${CMAKE_CURRENT_BINARY_DIR}>
  INTERFACE
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(libgpg-error
  PRIVATE Ws2_32.lib
  PUBLIC iconv::iconv
)

# add_custom_command(
#   TARGET libgpg-error
#   PRE_BUILD
#   COMMAND ${AWK} -f ${CMAKE_CURRENT_SOURCE_DIR}/src/mkstrtable.awk -v textidx=3 ${CMAKE_CURRENT_SOURCE_DIR}/src/err-sources.h.in > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/err-sources.h
#   COMMAND ${AWK} -f ${CMAKE_CURRENT_SOURCE_DIR}/src/mkstrtable.awk -v textidx=2 -v nogettext=1 ${CMAKE_CURRENT_SOURCE_DIR}/src/err-sources.h.in > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/err-sources-sym.h
#   COMMAND ${AWK} -f ${CMAKE_CURRENT_SOURCE_DIR}/src/mkstrtable.awk -v textidx=3 ${CMAKE_CURRENT_SOURCE_DIR}/src/err-codes.h.in > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/err-codes.h
#   COMMAND ${AWK} -f ${CMAKE_CURRENT_SOURCE_DIR}/src/mkstrtable.awk -v textidx=2 -v nogettext=1 ${CMAKE_CURRENT_SOURCE_DIR}/src/err-codes.h.in > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/err-codes-sym.h
#   COMMAND ${AWK} -f ${CMAKE_CURRENT_SOURCE_DIR}/src/mkerrnos.awk ${CMAKE_CURRENT_SOURCE_DIR}/src/errnos.in > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/code-to-errno.h
#   COMMAND ${AWK} -f ${CMAKE_CURRENT_SOURCE_DIR}/src/mkstrtable.awk -v textidx=2 -v nogettext=1 -v prefix=GPG_ERR_ -v namespace=errnos_ ${CMAKE_CURRENT_SOURCE_DIR}/src/errnos.in > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/errnos-sym.h
# )


# ADD_EXECUTABLE(mkheader src/mkheader.c)
# target_compile_definitions(mkheader
#   PRIVATE
#   HAVE_CONFIG_H
#   _CRT_SECURE_NO_WARNINGS
#   _CRT_NONSTDC_NO_WARNINGS)
  
# target_include_directories(mkheader
#   PRIVATE
#   $<BUILD_INTERFACE:.;cmake;src;${CMAKE_CURRENT_BINARY_DIR}>
#   INTERFACE
#   $<INSTALL_INTERFACE:include>
# )
  
# add_custom_command(TARGET mkheader
#   POST_BUILD
#   COMMAND ${CMAKE_COMMAND} -E chdir ${CMAKE_CURRENT_SOURCE_DIR}/src $<TARGET_FILE:mkheader> "mingw32" "win32-msvc" "gpg-error.h.in" ${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.h "1.27" "0x011b00" > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/gpg-error.h
# )

# ADD_EXECUTABLE(mkerrcodes src/mkerrcodes.c)
# target_compile_definitions(mkerrcodes
#   PRIVATE
#   HAVE_CONFIG_H
#   _CRT_SECURE_NO_WARNINGS
#   _CRT_NONSTDC_NO_WARNINGS)
  
# target_include_directories(mkerrcodes
#   PRIVATE
#   $<BUILD_INTERFACE:.;cmake;src;${CMAKE_CURRENT_BINARY_DIR}>
#   INTERFACE
#   $<INSTALL_INTERFACE:include>
# )

# add_custom_command(
#   TARGET mkerrcodes
#   PRE_BUILD 
#   COMMAND ${AWK} -f ${CMAKE_CURRENT_SOURCE_DIR}/src/mkerrcodes1.awk ${CMAKE_CURRENT_SOURCE_DIR}/src/errnos.in > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/_mkerrcodes.h
#   COMMAND cl -E ${CMAKE_CURRENT_SOURCE_DIR}/cmake/_mkerrcodes.h | findstr GPG_ERR_ | \"${AWK}\" -f ${CMAKE_CURRENT_SOURCE_DIR}/src/mkerrcodes.awk > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/mkerrcodes.h
#   COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_CURRENT_SOURCE_DIR}/cmake/_mkerrcodes.h
# )

# add_custom_command(
#   TARGET mkerrcodes
#   POST_BUILD 
#   COMMAND $<TARGET_FILE:mkerrcodes> | \"${AWK}\" -f ${CMAKE_CURRENT_SOURCE_DIR}/src/mkerrcodes2.awk > ${CMAKE_CURRENT_SOURCE_DIR}/cmake/code-from-errno.h
# )

# add_dependencies(libgpg-error mkheader)
# add_dependencies(libgpg-error mkerrcodes)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion
)

install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

install(FILES src/gpg-error.h DESTINATION include/)

if(MSVC)
  set_target_properties(libgpg-error
    PROPERTIES
      COMPILE_PDB_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
      COMPILE_PDB_NAME libgpg-error
      COMPILE_PDB_NAME_DEBUG libgpg-errord
  )
  install(FILES
    ${PROJECT_BINARY_DIR}/RelWithDebInfo/libgpg-error.pdb
    DESTINATION lib
    CONFIGURATIONS RelWithDebInfo
  )
  install(FILES
    ${PROJECT_BINARY_DIR}/Debug/libgpg-errord.pdb
    DESTINATION lib
    CONFIGURATIONS Debug
  )
endif()

install(EXPORT ${PROJECT_NAME}
  FILE
    ${PROJECT_NAME}.cmake
  NAMESPACE
    ${PROJECT_NAME}::
  DESTINATION
    lib/cmake/${PROJECT_NAME}
)

install(
  FILES
    cmake/${PROJECT_NAME}-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
  DESTINATION
    lib/cmake/${PROJECT_NAME}
)