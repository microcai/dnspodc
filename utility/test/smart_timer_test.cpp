
#include <boost/asio.hpp>
#include <boost/chrono.hpp>

#include "../include/smart_timer.hpp"

int main()
{
	boost::asio::io_context io;
	smart_timer::smart_timer<boost::asio::deadline_timer, int> abc(io);
	smart_timer::smart_timer<boost::asio::deadline_timer, int> abcd(io);

	abc.expires_from_now(boost::posix_time::seconds(2));
	abcd.expires_from_now(boost::posix_time::seconds(2));

	abc.async_wait([](boost::system::error_code ec, int abc){
		std::cerr << abc << std::endl;
	});

	abcd.async_wait([](boost::system::error_code ec, int abc){
		std::cerr << abc << std::endl;
	});

	abc.wake_up(333);

	//abcd.cancel();

	io.run();
}
