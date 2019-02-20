
# 汉语

## 介绍

dnspodc 是 dnspod 的 动态域名客户端。专用于 ipv6。

## 缘由
家庭拨号，并使用 DHCPv6-PD 获取前缀和 SLAAC 配置地址的情况下， 路由器如果重新拨号， 就会
获取新的前缀， 而老的前缀构成的地址并不会消失。还挂在许多内网机器上。一般的更新脚本没有考虑
这点，随机的选一个地址导致会把无法路由的地址更新到 dns 上。

dnspodc 使用了 ip 命令一样的 netlink 接口获取到了更多的信息， 最重要的是拿到了 SLAAC
配置的地址的 “寿命” 有了地址的寿命， 就知道哪个地址才是最近 RA 推过来的，就能正确更新可路由
的地址。

## 使用

dnspodc --login_token "your dnspod token" --domain=example.com --subdomain=www


# English

## Intro

dnspodc is a ipv6 ddns client for DNSPOD. It select the most recently SLAAC
configured ipv6 address and then update that into dnspod

## Rational

In DHCPv6-PD + SLAAC setup, when pppoe connection reconnect, the router will
advert new network prefix, but on the LAN side, client's interface will still
have old prefix address listed. Normal script will not be able to distingish
two (or even more) addresses, and randomly choose one
to update.

dnspodc, @ its core, is a ipv6 address selector that take SLAAC address valit
time into account. the most recently assigned address (also the only routeable
address) wins.

## Usage

dnspodc --login_token "your dnspod token" --domain=example.com --subdomain=www

