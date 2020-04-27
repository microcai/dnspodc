
#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>
#include <boost/bind.hpp>

#include <boost/program_options.hpp>
namespace po = boost::program_options;
using po::options_description;
using po::variables_map;

#include <sys/types.h>

static bool verbose_log = false;

#ifdef _WIN32
#include <iphlpapi.h>
#pragma comment(lib, "Iphlpapi.lib")

static std::string getifaddrv4(std::string ifname)
{
	std::vector<char> buf;
	ULONG buf_len = 65536*5;
	buf.resize(buf_len);
	GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER, 0, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(&buf[0]), &buf_len);

	for (IP_ADAPTER_ADDRESSES* pinfo = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(&buf[0]); pinfo != NULL; pinfo = pinfo->Next)
	{
		for (IP_ADAPTER_UNICAST_ADDRESS* addr = pinfo->FirstUnicastAddress; addr != NULL; addr = addr->Next)
		{
			boost::asio::ip::address_v4::bytes_type rb;
			memcpy(&rb, &(reinterpret_cast<const sockaddr_in*>(addr->Address.lpSockaddr)->sin_addr), 4);

			if (rb[0] == 127)
				continue;

			boost::asio::ip::address_v4 v4addr{ rb };

			return v4addr.to_string();
		}
	}

	return "";
}

static std::string getifaddrv6(std::string ifname)
{
	std::vector<char> buf;
	ULONG buf_len = 65536 * 5;
	buf.resize(buf_len);
	GetAdaptersAddresses(AF_INET6, GAA_FLAG_SKIP_DNS_SERVER, 0, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(&buf[0]), &buf_len);

	struct addr_info {
		boost::asio::ip::address_v6 addr_v6;
		ULONG valid_lft;
	};

	std::vector<addr_info> addr_infos;

	for (IP_ADAPTER_ADDRESSES* pinfo = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(&buf[0]); pinfo != NULL; pinfo = pinfo->Next)
	{
		for (IP_ADAPTER_UNICAST_ADDRESS* addr = pinfo->FirstUnicastAddress; addr != NULL; addr = addr->Next)
		{
			boost::asio::ip::address_v6::bytes_type rawbytes_of_addr;
			memcpy(rawbytes_of_addr.data(), &(reinterpret_cast<const sockaddr_in6*>(addr->Address.lpSockaddr)->sin6_addr), 16);

			boost::asio::ip::address_v6 v6addr(rawbytes_of_addr, reinterpret_cast<const sockaddr_in6*>(addr->Address.lpSockaddr)->sin6_scope_id);

			if (v6addr.is_link_local() || v6addr.is_site_local() || v6addr.is_loopback())
				continue;

			if (rawbytes_of_addr[0] == 0xfd || rawbytes_of_addr[0] == 0xfc)
				continue;


			wprintf(L"\tInterface : <%s>\n", pinfo->FriendlyName);
			printf("\t  Address : <%s>\n", v6addr.to_string().c_str());
			addr_info info;
			info.addr_v6 = v6addr;
			info.valid_lft = addr->PreferredLifetime;
			addr_infos.push_back(info);
			

		}
	}

	std::sort(addr_infos.begin(), addr_infos.end(), [](auto a, auto b)
		{
			return a.valid_lft > b.valid_lft;
		});

	// then sort by preferred_lft. biggest wins. use that address to notify DNSPOD.

	if (addr_infos.empty())
		return "";

	printf("selected address <%s>\n", addr_infos[0].addr_v6.to_string().c_str());
	return addr_infos[0].addr_v6.to_string();
}

#else

#include <ifaddrs.h>

extern "C" {
#include "../iproute2/include/libnetlink.h"
}
typedef std::shared_ptr<nlmsghdr> nlmsg;

static int store_nlmsg(const struct sockaddr_nl* who, struct nlmsghdr* n,
	void* arg)
{
	std::vector<nlmsg>& lchain = *(std::vector<nlmsg>*)arg;
	struct nlmsg_list* h;

	nlmsg copyed_nlmsg((nlmsghdr*)malloc(n->nlmsg_len), free);
	memcpy(copyed_nlmsg.get(), n, n->nlmsg_len);

	lchain.push_back(copyed_nlmsg);
	return 0;
}

static std::tuple<boost::asio::ip::address_v6, int> getifaddrv6(std::string ifname)
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

	(void)rtnl_open(&rth, 0);
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
		int prefix_len;
		int valid_lft;
	};

	std::vector<addr_info> addr_infos;

	for (auto ifaddr_iterator = auto_free.get(); ifaddr_iterator != NULL; ifaddr_iterator = ifaddr_iterator->ifa_next)
	{
		if (ifaddr_iterator->ifa_addr == NULL)
			continue;

		if ( ifaddr_iterator->ifa_addr->sa_family==AF_INET6 )
		{
			if (ifname.empty() || ifname == ifaddr_iterator->ifa_name)
			{
				sockaddr_in6 * soaddr6 = (sockaddr_in6 * )ifaddr_iterator->ifa_addr;

				if (soaddr6->sin6_scope_id == 0)
				{
					boost::asio::ip::address_v6::bytes_type rawbytes_of_addr;
					memcpy(rawbytes_of_addr.data(), soaddr6->sin6_addr.s6_addr, 16);

					boost::asio::ip::address_v6 v6addr(rawbytes_of_addr, soaddr6->sin6_scope_id);

					if (rawbytes_of_addr[0] == 0xfd || rawbytes_of_addr[0] == 0xfc)
						continue;

					if (v6addr.is_loopback())
						continue;

					if (verbose_log)
					{
						printf("\tInterface : <%s>\n",ifaddr_iterator->ifa_name );
						printf("\t  Address : <%s>\n", v6addr.to_string().c_str());
					}

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
								if (verbose_log)
									printf("\tvalid_lft : %d sec\n", ci->ifa_prefered);
								addr_info info;
								info.addr_v6 = v6addr;
								info.valid_lft = ci->ifa_prefered;
								info.prefix_len = ifa->ifa_prefixlen;
								addr_infos.push_back(info);
							}
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
		return {boost::asio::ip::address_v6(), 0};

	if (verbose_log)
		printf("selected address <%s>\n", addr_infos[0].addr_v6.to_string().c_str());
	return { addr_infos[0].addr_v6, addr_infos[0].prefix_len};//.to_string();
}

static std::string getifaddrv4(std::string ifname)
{
	std::shared_ptr<ifaddrs> auto_free;

	{
		struct ifaddrs* ifaddr;

		if (getifaddrs(&ifaddr) == -1)
		{
			perror("getifaddrs");
			exit(EXIT_FAILURE);
		}

		auto_free.reset(ifaddr, freeifaddrs);
	}


	for (auto ifaddr_iterator = auto_free.get(); ifaddr_iterator != NULL; ifaddr_iterator = ifaddr_iterator->ifa_next)
	{
		if (ifaddr_iterator->ifa_addr == NULL)
			continue;

		if (ifaddr_iterator->ifa_addr->sa_family == AF_INET)
		{
			if (ifname.empty() || ifname == ifaddr_iterator->ifa_name)
			{
				sockaddr_in* soaddr4 = (sockaddr_in*)ifaddr_iterator->ifa_addr;

				boost::asio::ip::address_v4::bytes_type rawbytes_of_addr;
				memcpy(rawbytes_of_addr.data(), &soaddr4->sin_addr, 4);

				boost::asio::ip::address_v4 v4addr(rawbytes_of_addr);

				if (rawbytes_of_addr[0] == 0xfd || rawbytes_of_addr[0] == 0xfc)
					continue;

				printf("\tInterface : <%s>\n", ifaddr_iterator->ifa_name);
				printf("\t  Address : <%s>\n", v4addr.to_string().c_str());

				return v4addr.to_string();
			}
		}
	}
	return "";
}

#endif

static void update_record(std::string login_token, std::string domain, std::string subdomain, std::string type, std::string address);

static std::string prefix_to_string(boost::asio::ip::address_v6 v6_address, int prefix_len)
{
	std::stringstream ss;
	bool pre_is_zero;
	// print prefix length!
	for (int i=0; i < prefix_len / 8; i++)
	{
		if ( i > 0 &&  (i % 2 == 0))
		{
			ss << ':';
		}

		if (i % 2 ==0)
		{
			if ( v6_address.to_bytes()[i] != 0)
			{
				pre_is_zero = false;
				ss << std::hex << int(v6_address.to_bytes()[i]);
			}
			else
			{
				pre_is_zero = true;
			}
		}
		else
		{
			if (pre_is_zero)
				ss << std::hex << int(v6_address.to_bytes()[i]);
			else
				ss << std::hex << std::setfill('0') << std::setw(2) << int(v6_address.to_bytes()[i]);
		}
	}

	ss << ':';
	return ss.str();
}

static std::string mac_to_v6_host_part(std::string mac_address_str)
{
	// convert mac to EUI-64
	std::array<int, 8> eui64;
	eui64[3] = 0xFF;
	eui64[4] = 0xFE;
	std::sscanf(mac_address_str.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", &eui64[0], &eui64[1], &eui64[2], &eui64[5], &eui64[6], &eui64[7]);

	eui64[0] ^= 0x2;
	// convert to host address part.

	std::stringstream ss;
	// print prefix length!
	for (int i=0; i < 4; i++)
	{
		if ( i > 0 )
		{
			ss << ':';
		}

		int hexpart = (eui64[i*2] << 8) + (eui64[i*2+1]);
		ss << std::hex << hexpart;
	}
	return ss.str();
}

int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "");

	std::string domain, subdomain, login_token, dev, addr, type;
	bool v6only;
	bool noupdate = false;
	std::string euid;
	std::string mac;

	options_description desc("options");
	desc.add_options()
		("help,h", "help message")
		("version", "current sspay version")
		("login_token", po::value<std::string>(&login_token), "login_token for operation")
		("domain", po::value<std::string>(&domain), "domain for operation")
		("subdomain", po::value<std::string>(&subdomain), "subdomain for operation")
		("v6only", po::value<bool>(&v6only)->default_value(true), "only update AAAA record")
		("dev", po::value<std::string>(&dev), "interface name")
		("type", po::value<std::string>(&type)->default_value("AAAA"), "update AAAA type or A type")
		("addr", po::value<std::string>(&addr), "manual set ipv6 address instead of query from NIC")
		("noupdate", "only print ipv6 address, no update")
		("prefix", "print prefix, implies noupdate")
		("eui", po::value<std::string>(&euid), "use this eui-64 as host bit")
		("frommac", po::value<std::string>(&mac), "use this mac to caculate eui-64")
		("verbose,v", "verbose log")
		;

	variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (vm.count("help"))
	{
		std::cout << desc << "\n";
		return 0;
	}

	verbose_log = vm.count("verbose");

	noupdate = vm.count("noupdate");

	if (vm.count("login_token") ==0 || vm.count("domain") ==0 || vm.count("subdomain") ==0)
		noupdate = true;

	if (addr.empty())
	{
		if (type == "AAAA")
		{
			boost::asio::ip::address_v6 v6_address;
			int prefix_len;
			std::tie(v6_address, prefix_len) = getifaddrv6(dev);

			if (prefix_len == 0)
			{
				return 1;
			}

			if (vm.count("prefix"))
			{
				std::cout << prefix_to_string(v6_address, prefix_len) << std::endl;
				return 0;
			}

			if (vm.count("eui"))
			{
				std::string constructed_addr = prefix_to_string(v6_address, prefix_len) + euid;

				if (noupdate)
					std::cout << constructed_addr << std::endl;
				else
					update_record(login_token, domain, subdomain, type, constructed_addr);
				return 0;
			}

			if (vm.count("frommac"))
			{
				std::string constructed_addr = prefix_to_string(v6_address, prefix_len) + mac_to_v6_host_part(mac);

				if (noupdate)
					std::cout << constructed_addr << std::endl;
				else
					update_record(login_token, domain, subdomain, type, constructed_addr);
				return 0;
			}

			// now, update the record.
			if (noupdate)
				std::cout << v6_address.to_string() << std::endl;
			else
				update_record(login_token, domain, subdomain, type, v6_address.to_string());
		}
		else
		{
			auto v4_address =  getifaddrv4(dev);
			// now, update the record.
			if (!noupdate)
				update_record(login_token, domain, subdomain, type, v4_address);
		}
	}
	else
	{
		if (!noupdate)
			update_record(login_token, domain, subdomain, type, addr);
	}
}

#include "easyhttp.hpp"

#include "pay_utility.hpp"

void do_update_record(boost::asio::io_context& io, std::string login_token, std::string domain, std::string subdomain, std::string type, std::string address, boost::asio::yield_context yield_context)
{
	// 首先, 登录到 dnspod 获取 domian id, 然后用 domain 获取 record_id

	if (verbose_log)
	{
		std::cout << "update dns: " << subdomain << "." << domain << " => " << address << std::endl;
	}

	std::vector<std::pair<std::string, std::string>> params = {
		{ "login_token", login_token },
		{ "format" , "json" },
		{ "domain", domain },
		{ "sub_domain", subdomain },
		{ "length", "3000" },
		{ "record_type", type },
	};

	std::string response_body;

	response_body = easy_http_post(io, "https://dnsapi.cn/Record.List", { "application/x-www-form-urlencoded; charset=utf-8", pay_utility::map_to_httpxform(params)}, yield_context);
	std::string err;
	auto resp = json11::Json::parse(response_body, err);

	if (resp["status"]["code"] == "1")
	{
		for (auto recordinfo : resp["records"].array_items())
		{

			auto record_id = recordinfo["id"].string_value();

			if (verbose_log)
				std::cout << "record_id is " << record_id << std::endl;
			// 有了 record_id 就可以更新 AAAA 记录了.

			std::vector<std::pair<std::string, std::string>> params = {
				{ "login_token", login_token },
				{ "format" , "json" },
				{ "domain", domain },
				{ "sub_domain", subdomain },
				{ "record_id", record_id },
				{ "record_line", recordinfo["line"].string_value() },
				{ "value", address },
				{ "record_type", type },
			};

			{
				response_body = easy_http_post(io, "https://dnsapi.cn/Record.Info", { "application/x-www-form-urlencoded; charset=utf-8", pay_utility::map_to_httpxform(params)}, yield_context);
				std::string err;
				auto resp = json11::Json::parse(response_body, err);

				if (resp["record"]["value"] == address)
				{
					if (verbose_log)
						std::cout << "address not changed, nothing to update!" << std::endl;
					return;
				}
			}

			response_body = easy_http_post(io, "https://dnsapi.cn/Record.Modify", { "application/x-www-form-urlencoded; charset=utf-8", pay_utility::map_to_httpxform(params)}, yield_context);

			std::string err;
			auto resp = json11::Json::parse(response_body, err);

			if (resp["status"]["code"] == "1")
			{
				if (verbose_log)
					std::cout << "update success full" << std::endl;
			}
			else
			{
				if (verbose_log)
					std::cerr << response_body << std::endl;
			}
		}
	}
	else
	{
		if (verbose_log)
			std::cerr << response_body << std::endl;
	}
}

void update_record(std::string login_token, std::string domain, std::string subdomain, std::string type, std::string address)
{
	boost::asio::io_context io;
	boost::asio::spawn(io, boost::bind(&do_update_record, boost::ref(io), login_token, domain, subdomain, type, address, _1));
	io.run();
}
