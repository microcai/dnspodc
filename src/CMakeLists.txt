
include(CheckIncludeFile)

include(CheckSymbolExists)

CHECK_SYMBOL_EXISTS(MSG_DONTWAIT "sys/socket.h" HAVE_MSG_DONTWAIT)
if (HAVE_MSG_DONTWAIT)
	add_definitions(-DHAVE_MSG_DONTWAIT)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_executable(dnspodc dnspodc.cpp )

target_link_libraries(dnspodc Boost::program_options Boost::thread)

target_link_libraries(dnspodc utility Boost::thread)

if(NOT WIN32)
target_link_libraries(dnspodc iproute2)
endif()

install(TARGETS dnspodc DESTINATION bin)