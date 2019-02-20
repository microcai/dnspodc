
# Chinese

## 介绍

## 缘由

## 使用


# English

## Intro

dnspodc is a ipv6 ddns client for DNSPOD. It select the most recently SLAAC
configured ipv6 address and then update that into dnspod

## Rational

In DHCPv6-PD + SLAAC setup, when pppoe connection reconnect, the router will
advert new network prefix, but the LAN size, client's interface will still
have old prefix address listed. Normal script will not be able to distingish
two (or even more) addresses, and randomly choose one
to update.

dnspodc, @ its core, is a ipv6 address selector that take SLAAC address valit
time into account. the most recently assigned address (also the only routeable
address) wins.

## Usage

dnspodc --login_token "your dnspod token" --domain=example.com --subdomain=www

