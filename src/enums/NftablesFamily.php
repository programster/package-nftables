<?php

namespace Programster\Nftables\Enums;

enum NftablesFamily: string
{
    case IP = "ip"; // IPv4
    case ARP = "arp";
    case IP6 = "ip6"; // IPv6
    case BRIDGE = "bridge";
    case INET = "inet"; // both ipv4 and ipv6
    case NETDEV = "netdev";
}
