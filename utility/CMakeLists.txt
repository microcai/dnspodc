﻿
add_library(utility STATIC
	include/bin_hex_iterator.hpp
	include/cache_map.hpp
	include/csv.hpp
	include/easyssl.hpp
	include/entropy.hpp
	include/escape_string.hpp
	include/fmt_helper.hpp
	include/html_form_autosubmit_page.hpp
	include/internal.hpp
	include/memunzip.hpp
	include/multipart.hpp
	include/pathutil.hpp
	include/security.hpp
	include/smart_timer.hpp
	include/smart_timer_var.hpp
	include/steady_clock.hpp
	include/timedcall.hpp
	include/url_reencode.hpp
	include/utf8.hpp
	include/ngx_setproctitle.hpp
	include/money.hpp
	include/proxy_pass.hpp

	src/easyssl.cpp
	src/entropy.cpp
	src/pathutil.cpp
	src/security.cpp
	src/ngx_setproctitle.cpp
	src/dec_util.cpp
	src/easyhttp.cpp
	src/default_cert.cpp
)

target_link_libraries(utility Boost::regex Boost::date_time Boost::filesystem Boost::coroutine Boost::thread
	json11 ${ZLIB_LIBRARIES}
	${CMAKE_THREAD_LIBS_INIT})

if (ANDROID)
target_link_libraries(utility crypto ssl)
else()
target_link_libraries(utility ${OPENSSL_LIBRARIES})
endif()


target_include_directories(utility PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(utility  PROPERTIES FOLDER "libs")

#add_executable(ipiptest test/ipiptest.cpp)
#target_link_libraries(ipiptest utility)
