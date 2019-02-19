
#include <iterator>
#include <algorithm>

#include "../include/sspay_error_code.hpp"

namespace sspay_error_code
{

	const char* detail::error_category_impl::name() const BOOST_SYSTEM_NOEXCEPT
	{
		return "sspay-error";
	}

	std::string detail::error_category_impl::message(int e) const
	{
		using namespace errc;
		switch (e)
		{
		case network_error:
			return "network error.";
		case invalid_json_response:
			return u8"无法解析返回的 json.";
		case invalid_xml_response:
			return u8"无法解析返回的 XML";
		case signature_error:
			return u8"验证返回值的签名错误";
		case quota_limited:
			return u8"渠道超限额";
		case payment_channel_not_enabled:
			return u8"渠道未开通";
		case bill_price_invalid:
			return u8"订单金额非法";
		case decryption_error:
			return u8"解密失败";
		case proxy_config_error:
			return u8"代理配置错误";
		default:
			return "Unknown error";
		}
	}

	const boost::system::error_category& error_category()
	{
		static detail::error_category_impl error_category_instance;
		return reinterpret_cast<const boost::system::error_category&>(error_category_instance);
	}

}
