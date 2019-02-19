
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


static int iplink_filter_req(struct nlmsghdr *nlh, int reqlen)
{
	int err;
	err = addattr32(nlh, reqlen, IFLA_EXT_MASK, RTEXT_FILTER_VF);
	if (err)
		return err;
	return 0;
}


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

static unsigned int get_ifa_flags(struct ifaddrmsg *ifa,
				  struct rtattr *ifa_flags_attr)
{
	return ifa_flags_attr ? rta_getattr_u32(ifa_flags_attr) :
		ifa->ifa_flags;
}


std::string getifaddr()
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		exit(EXIT_FAILURE);
	}

	std::shared_ptr<ifaddrs> auto_free(ifaddr, freeifaddrs);

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		if((strcmp(ifa->ifa_name,"eth0")==0)&&(ifa->ifa_addr->sa_family==AF_INET6))
		{
			sockaddr_in6 * soaddr6 = (sockaddr_in6 * )ifa->ifa_addr;

			if (soaddr6->sin6_scope_id == 0)
			{
				boost::asio::ip::address_v6::bytes_type rawbytes_of_addr;
				memcpy(rawbytes_of_addr.data(), soaddr6->sin6_addr.s6_addr, 16);

				boost::asio::ip::address_v6 v6addr(rawbytes_of_addr, soaddr6->sin6_scope_id);

				if (rawbytes_of_addr[0] == 0xfd)
					continue;

				printf("\tInterface : <%s>\n",ifa->ifa_name );
				printf("\t  Address : <%s>\n", v6addr.to_string().c_str());

				rtnl_handle rth;

				rtnl_open(&rth, 0);

				std::vector<nlmsg> linfo;
				std::vector<nlmsg> ainfo;

				rtnl_wilddump_req_filter_fn(&rth, AF_INET6, RTM_GETLINK, iplink_filter_req);
				if (rtnl_dump_filter(&rth, store_nlmsg, &linfo) < 0) {
					throw std::runtime_error("dump failed");
				}

				if (rtnl_wilddump_request(&rth, AF_INET6, RTM_GETADDR) < 0) {
					throw std::runtime_error("dump failed");
				}

				if (rtnl_dump_filter(&rth, store_nlmsg, &ainfo) < 0) {
					throw std::runtime_error("dump failed");
				}

				for (auto n_s : linfo)
				{
					struct nlmsghdr *n = n_s.get();
					struct ifinfomsg *ifi = (struct ifinfomsg *) ( NLMSG_DATA(n) );
					int res = 0;

					if (ifi->ifi_index != if_nametoindex(ifa->ifa_name) )
						continue;

					for (auto _ainfo : ainfo)
					{
						struct nlmsghdr *n1 = _ainfo.get();
						struct ifaddrmsg *ifa = (struct ifaddrmsg *) (  NLMSG_DATA(n1) );

						if (ifa->ifa_index != ifi->ifi_index)
							continue;

						if (n1->nlmsg_type != RTM_NEWADDR)
							continue;

						if (n1->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)))
							throw std::runtime_error("dump failed");

						struct rtattr *rta_tb[IFA_MAX+1];

						parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa),
								n1->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

						auto ifa_flags = get_ifa_flags(ifa, rta_tb[IFA_FLAGS]);

						if (rta_tb[IFA_ADDRESS])
						{
							
						}

						if (rta_tb[IFA_CACHEINFO]) {

							struct ifa_cacheinfo *ci = (struct ifa_cacheinfo *)(RTA_DATA(rta_tb[IFA_CACHEINFO]));


							printf("\t  valid_lft : %d sec\n", ci->ifa_prefered);

						}

					}



				}

				// find out the address preferred_lft
				rtnl_close(&rth);
			}
		}
	}

	// then sort by preferred_lft. biggest wins. use that address to notify DNSPOD.

	return "";
}

int main(int argc, char* argv[])
{

	std::string domain, login_token, dev;
	bool v6only;

	options_description desc("options");
	desc.add_options()
		("help,h", "help message")
		("version,v", "current sspay version")
		("login_token", po::value<std::string>(&login_token), "login_token for operation")
		("domain", po::value<std::string>(&domain), "domain for operation")
		("subdomain", po::value<std::string>(&domain), "subdomain for operation")
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


	getifaddr();
}
