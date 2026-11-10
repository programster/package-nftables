<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * The ICMP error a RejectStatement replies with, worded the same for IPv4 and IPv6. inet tables only.
 */
enum IcmpxRejectCode : string
{
    case PORT_UNREACHABLE = "port-unreachable";
    case ADMIN_PROHIBITED = "admin-prohibited";
    case NO_ROUTE = "no-route";
    case HOST_UNREACHABLE = "host-unreachable";
}
