cmake_minimum_required(VERSION 3.5)

project(DNS-Proxy LANGUAGES C)

add_executable(DNS-Proxy main.c)

include(GNUInstallDirs)
install(TARGETS DNS-Proxy
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
