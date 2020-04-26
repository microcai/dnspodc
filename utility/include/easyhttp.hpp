#pragma once

#include <string>
#include <boost/system/error_code.hpp>
#include <boost/asio/spawn.hpp>

void easy_http_get(boost::asio::io_context& io, std::string url, std::function<void(boost::system::error_code, std::string)>, std::string use_proxy = "");
void easy_http_get(boost::asio::io_context& io, std::string url, std::vector<std::pair<std::string, std::string>> additional_headers, std::function<void(boost::system::error_code, std::string)>, std::string use_proxy = "");

void easy_http_post(boost::asio::io_context& io, std::string url,
	std::pair<std::string, std::string> post_content,
	std::function<void(boost::system::error_code, std::string)>, std::string use_proxy = "");

std::string easy_http_post(boost::asio::io_context& io, std::string url, std::pair<std::string, std::string> post_content, boost::asio::yield_context, std::string use_proxy = "");

