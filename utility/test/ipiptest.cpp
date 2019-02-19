
#include <iostream>
#include "ipip.hpp"

ipip d("/tmp/17monipdb.dat");


void run(std::string ip)
{
	std::vector<std::string> result = std::get<0>(d.find(boost::asio::ip::address_v4::from_string(ip)));
	for (auto s : result)
		std::cout << s << ".";

	std::cout << std::endl;
}

int main()
{
	run("8.8.8.8");
	run("114.114.114.114");
	run("171.212.191.62");
	return 0;
}
