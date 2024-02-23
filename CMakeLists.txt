cmake_minimum_required(VERSION 3.5)

project(DNS-Proxy LANGUAGES C)

add_executable(DNS-Proxy main.c)

target_link_libraries(DNS-Proxy config)

include(GNUInstallDirs)
install(
  TARGETS DNS-Proxy
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
