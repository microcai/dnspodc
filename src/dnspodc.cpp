
#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
using po::options_description;
using po::variables_map;

#include <sys/types.h>
#include <ifaddrs.h>

extern "C" {
#include "../iproute2/include/libnetlink.h"
}

typedef std::shared_ptr<nlmsghdr> nlmsg;

static int store_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n,
		       void *arg)
{
	std::vector<nlmsg> & lchain = * (std::vector<nlmsg>*)arg;
	struct nlmsg_list *h;

	nlmsg copyed_nlmsg((nlmsghdr *) malloc(n->nlmsg_len), free);
	memcpy(copyed_nlmsg.get(), n, n->nlmsg_len);

	lchain.push_back(copyed_nlmsg);
	return 0;
}

std::string getifaddr(std::string ifname)
{
	std::shared_ptr<ifaddrs> auto_free;

	{
		struct ifaddrs *ifaddr;

		if (getifaddrs(&ifaddr) == -1)
		{
			perror("getifaddrs");
			exit(EXIT_FAILURE);
		}

		auto_free.reset(ifaddr, freeifaddrs);
	}

	rtnl_handle rth;

	rtnl_open(&rth, 0);
	std::vector<nlmsg> linfo;
	std::vector<nlmsg> ainfo;

	if (rtnl_wilddump_request(&rth, AF_INET6, RTM_GETADDR) < 0) {
		throw std::runtime_error("dump failed");
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, &ainfo) < 0) {
		throw std::runtime_error("dump failed");
	}

	rtnl_close(&rth);


	struct addr_info {
		boost::asio::ip::address_v6 addr_v6;
		int valid_lft;
	};

	std::vector<addr_info> addr_infos;

	for (auto ifaddr_iterator = auto_free.get(); ifaddr_iterator != NULL; ifaddr_iterator = ifaddr_iterator->ifa_next)
	{
		if (ifaddr_iterator->ifa_addr == NULL)
			continue;

		if ( ifname == ifaddr_iterator->ifa_name && (ifaddr_iterator->ifa_addr->sa_family==AF_INET6) )
		{
			sockaddr_in6 * soaddr6 = (sockaddr_in6 * )ifaddr_iterator->ifa_addr;

			if (soaddr6->sin6_scope_id == 0)
			{
				boost::asio::ip::address_v6::bytes_type rawbytes_of_addr;
				memcpy(rawbytes_of_addr.data(), soaddr6->sin6_addr.s6_addr, 16);

				boost::asio::ip::address_v6 v6addr(rawbytes_of_addr, soaddr6->sin6_scope_id);

				if (rawbytes_of_addr[0] == 0xfd)
					continue;

				printf("\tInterface : <%s>\n",ifaddr_iterator->ifa_name );
				printf("\t  Address : <%s>\n", v6addr.to_string().c_str());

				for (auto _ainfo : ainfo)
				{
					struct nlmsghdr *n1 = _ainfo.get();
					struct ifaddrmsg *ifa = (struct ifaddrmsg *) (  NLMSG_DATA(n1) );

					if (ifa->ifa_index != if_nametoindex(ifaddr_iterator->ifa_name))
						continue;

					if (n1->nlmsg_type != RTM_NEWADDR)
						continue;

					if (n1->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)))
						throw std::runtime_error("dump failed");

					struct rtattr *rta_tb[IFA_MAX+1];

					parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa),
							n1->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

					if (memcmp(rawbytes_of_addr.data(), RTA_DATA(rta_tb[IFA_ADDRESS]), 16) == 0)
					{
						if (rta_tb[IFA_CACHEINFO])
						{
							struct ifa_cacheinfo *ci = (struct ifa_cacheinfo *)(RTA_DATA(rta_tb[IFA_CACHEINFO]));
							printf("\t  valid_lft : %d sec\n", ci->ifa_prefered);
							addr_info info;
							info.addr_v6 = v6addr;
							info.valid_lft = ci->ifa_prefered;
							addr_infos.push_back(info);
						}
					}
				}
			}
		}
	}


	std::sort(addr_infos.begin(), addr_infos.end(), [](auto a , auto b)
	{
		return a.valid_lft >= b.valid_lft;
	});

	// then sort by preferred_lft. biggest wins. use that address to notify DNSPOD.

	if (addr_infos.empty())
		return "";

	return addr_infos[0].addr_v6.to_string();
}

static void update_record(std::string login_token, std::string domain, std::string subdomain, std::string address);

int main(int argc, char* argv[])
{
	std::string domain, subdomain, login_token, dev;
	bool v6only;

	options_description desc("options");
	desc.add_options()
		("help,h", "help message")
		("version,v", "current sspay version")
		("login_token", po::value<std::string>(&login_token), "login_token for operation")
		("domain", po::value<std::string>(&domain), "domain for operation")
		("subdomain", po::value<std::string>(&subdomain), "subdomain for operation")
		("v6only", po::value<bool>(&v6only)->default_value(true), "only update AAAA record")
		("dev", po::value<std::string>(&dev)->default_value("eth0"), "interface name")
		;

	variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (vm.count("help"))
	{
		std::cout << desc << "\n";
		return 0;
	}

	auto v6_address =  getifaddr(dev);

	// now, update the record.
	update_record(login_token, domain, subdomain, v6_address);
}

#include "easyhttp.hpp"

#include "pay_utility.hpp"

void update_record(std::string login_token, std::string domain, std::string subdomain, std::string address)
{
	boost::asio::io_context io;
	// 首先, 登录到 dnspod 获取 domian id, 然后用 domain 获取 record_id

	std::vector<std::pair<std::string, std::string>> params = {
		{ "login_token", login_token },
		{ "format" , "json" } ,
	};

	easy_http_post(io, "https://dnsapi.cn/Domain.List", { "application/x-www-form-urlencoded; charset=utf-8", pay_utility::map_to_string(params)}, [](boost::system::error_code ec, std::string response_body)
	{
		if (ec)
			std::cerr << ec.message() << std::endl;
		std::cerr << response_body << std::endl;
	});

	// 有了 record_id 就可以更新 AAAA 记录了.

	io.run();
}
