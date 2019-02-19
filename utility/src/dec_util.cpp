

#include <string>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>

#include "dec_util.hpp"

#include <boost/algorithm/string.hpp>

std::string dec_fmt(boost::multiprecision::cpp_dec_float_50 num)
{
	std::stringstream ss;

	ss << std::fixed;
	ss.precision(std::numeric_limits<boost::multiprecision::cpp_dec_float_50>::max_digits10);

	ss << num ;

	std::string dec_form = ss.str();

	auto dot_pos = dec_form.find('.');

	if (dot_pos == std::string::npos)
		return dec_form;

	boost::trim_right_if(dec_form, boost::is_any_of("0"));
	boost::trim_right_if(dec_form, boost::is_any_of("."));
	return dec_form;
}

boost::multiprecision::cpp_dec_float_50 dec_round(boost::multiprecision::cpp_dec_float_50 val, boost::multiprecision::cpp_dec_float_50 round_step)
{
	auto biginteger = ( (val + round_step/2) / round_step).convert_to<boost::multiprecision::cpp_int>();

	return boost::multiprecision::cpp_dec_float_50(biginteger) * round_step;
}

boost::multiprecision::cpp_dec_float_50 dec_round(boost::multiprecision::cpp_dec_float_50 val, const char* round_step)
{
	return dec_round(val, boost::multiprecision::cpp_dec_float_50(round_step));
}

boost::multiprecision::cpp_dec_float_50 dec_round_down(boost::multiprecision::cpp_dec_float_50 val, boost::multiprecision::cpp_dec_float_50 round_step)
{
	auto biginteger = (val / round_step).convert_to<boost::multiprecision::cpp_int>();

	return boost::multiprecision::cpp_dec_float_50(biginteger) * round_step;
}

boost::multiprecision::cpp_dec_float_50 dec_round_down(boost::multiprecision::cpp_dec_float_50 val, const char* round_step)
{
	return dec_round_down(val, boost::multiprecision::cpp_dec_float_50(round_step));

}
