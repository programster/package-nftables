<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * The type of the elements in a named set.
 */
enum SetType : string
{
    case IPV4_ADDR = "ipv4_addr";
    case IPV6_ADDR = "ipv6_addr";

    // A MAC address.
    case ETHER_ADDR = "ether_addr";

    // A protocol, e.g. tcp.
    case INET_PROTO = "inet_proto";

    // A port.
    case INET_SERVICE = "inet_service";

    // A packet mark.
    case MARK = "mark";

    // An interface name.
    case IFNAME = "ifname";
}
