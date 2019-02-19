
#pragma once

#include <boost/system/error_code.hpp>

namespace sspay_error_code {

	namespace errc {

		/// HTTP error codes.
		/**
		* The enumerators of type @c errc_t are implicitly convertible to objects of
		* type @c boost::system::error_code.
		*
		* @par Requirements
		* @e Header: @c <error_codec.hpp> @n
		* @e Namespace: @c avhttp::errc
		*/
		enum errc_t
		{
			/// wake_up called
			network_error = 1,
			invalid_json_response,
			invalid_xml_response,
			signature_error,
			quota_limited,
			payment_channel_not_enabled,
			bill_price_invalid,
			decryption_error,
			proxy_config_error,
		};

	} // namespace errc

	namespace detail {

		class error_category_impl
			: public boost::system::error_category
		{
			virtual const char* name() const BOOST_SYSTEM_NOEXCEPT;

			virtual std::string message(int e) const;
		};

	}

	const boost::system::error_category& error_category();

	namespace errc
	{

		/// Converts a value of type @c errc_t to a corresponding object of type
		/// @c boost::system::error_code.
		/**
		* @par Requirements
		* @e Header: @c <error_codec.hpp> @n
		* @e Namespace: @c avhttp::errc
		*/
		inline boost::system::error_code make_error_code(errc_t e)
		{
			return boost::system::error_code(static_cast<int>(e), error_category());
		}

	}

}

namespace boost {
	namespace system {

		template<> struct is_error_code_enum<sspay_error_code::errc::errc_t>
		{
			static const bool value = true;
		};
	}
}
