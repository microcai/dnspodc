
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

#include "easyhttp.hpp"
#include "simple_http.hpp"

std::string easy_http_post(boost::asio::io_context& io, std::string _url, std::pair<std::string, std::string> post_content, boost::asio::yield_context yield, std::string use_proxy)
{
	boost::system::error_code ec;
	util::uri url{_url};
	httpclient::simple_http s{boost::asio::get_associated_executor(yield, io)};
	httpclient::http_request req{boost::beast::http::verb::post, url.path(), 11};
	req.set(boost::beast::http::field::user_agent, HTTPD_VERSION_STRING);
	req.set(boost::beast::http::field::host, url.host());
	req.set(boost::beast::http::field::content_type, post_content.first);

	req.body() = post_content.second;
	req.prepare_payload();

	httpclient::http_response res = s.async_perform(_url, req, yield[ec]);

	if (ec)
		return "";

	if (res.result() == boost::beast::http::status::ok)
		return boost::beast::buffers_to_string(res.body().data());
	if (res.result() == boost::beast::http::status::bad_request)
		return boost::beast::buffers_to_string(res.body().data());

	return "";
}
