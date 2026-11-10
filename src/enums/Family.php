<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * The address family of a table, which decides which packets its chains see.
 */
enum Family : string
{
    // IPv4 only.
    case IP = "ip";

    // IPv6 only.
    case IP6 = "ip6";

    // Both IPv4 and IPv6.
    case INET = "inet";

    // ARP packets.
    case ARP = "arp";

    // Packets passing through a bridge.
    case BRIDGE = "bridge";

    // Packets as they arrive at, or leave, a specific network device.
    case NETDEV = "netdev";
}
