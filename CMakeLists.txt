cmake_minimum_required(VERSION 3.0)
project(dnspodc)
cmake_policy(SET CMP0058 NEW)
include(CheckCXXCompilerFlag)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

option(USE_SYSTEM_OPENSSL "use system supplied openssl" OFF)
option(Boost_USE_STATIC_LIBS "use static Boost" ON)
option(USE_SYSTEM_BOOST "use system supplied boost" OFF)

option(STATIC_EXE "static link" OFF)

include(cpacksettings.cmake)
include(CPack)

if(MSVC)
set (CMAKE_CONFIGURATION_TYPES "Release;Debug")
set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_RELEASE
   )

foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

foreach(CompilerFlag ${CompilerFlags})
  string(REPLACE "/W3" "/W1" ${CompilerFlag} "${${CompilerFlag}}")
endforeach()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /utf-8 /bigobj /MP")

#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}  /ignore:4099 /NODEFAULTLIB:libcmt.lib ")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER}  /SAFESEH:NO ")
else()
check_cxx_compiler_flag(-std=c++14 HAS_CXX14)
if (HAS_CXX14)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 ")
endif()
endif(MSVC)

if (STATIC_EXE)
	set(CMAKE_CXX_FLAGS "-static -static-libgcc")
endif()

find_package(Threads)

link_libraries(${CMAKE_THREAD_LIBS_INITD})

add_definitions(-DAVHTTP_ENABLE_OPENSSL)

if(USE_SYSTEM_OPENSSL)

find_package(OpenSSL REQUIRED)
set(OPENSSL_LIBRARIES OpenSSL::Crypto OpenSSL::SSL)

add_definitions(-DHAVE_DECL_EVP_MD_CTX_NEW)
else()

add_subdirectory(3rd-src/openssl-cmake)
set(OPENSSL_LIBRARIES crypto ssl)

endif()

if(WIN32)
	add_definitions(-DBOOST_ALL_STATIC_LINK -DBOOST_AUTO_LINK_NOMANGLE)
	add_definitions(-DBOOST_THREAD_USE_LIB)
	add_definitions(-DBOOST_FILESYSTEM_STATIC_LINK)
	add_definitions(-DWIN32_LEAN_AND_MEAN)
	add_definitions(-DNOMINMAX)
endif()

if (USE_SYSTEM_BOOST)
set(Boost_USE_STATIC_LIBS OFF)
find_package(Boost 1.64 COMPONENTS system filesystem locale thread program_options regex date_time coroutine)

else()
	add_definitions(-DBOOST_ALL_STATIC_LINK -DBOOST_AUTO_LINK_NOMANGLE)
	add_definitions(-DBOOST_THREAD_USE_LIB)

	set(Boost_USE_STATIC_LIBS	ON)
	set(Boost_USE_STATIC_RUNTIME	ON)
	set(BOOST_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost)

	add_definitions(-DBOOST_LOCALE_HIDE_AUTO_PTR)
	add_definitions(-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)
	add_subdirectory(3rd-src/boost EXCLUDE_FROM_ALL)
endif()

add_subdirectory(3rd-src/json11)

include_directories(3rd-src/avhttp/include)

##################
# real project stuff
##################
add_subdirectory(utility)

if(NOT WIN32)
add_subdirectory(iproute2)
endif()

add_subdirectory(src)

configure_file(ddns.service.in ddns.service)

install(FILES ddns.timer DESTINATION /usr/lib/systemd/system)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/ddns.service DESTINATION /usr/lib/systemd/system)

