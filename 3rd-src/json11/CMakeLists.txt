cmake_minimum_required(VERSION 2.8)

add_library(json11 json11.cpp)
target_include_directories(json11 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(json11 Boost::system)

if (MSVC)
	# boost::Xpressive does not support msvc in c++17 mode
	set_source_files_properties(json11.cpp PROPERTIES COMPILE_FLAGS /std:c++14)
endif()
