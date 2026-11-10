<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * IPv4 or IPv6, using the names nftables uses for them.
 */
enum IpVersion : string
{
    case IPV4 = "ip";
    case IPV6 = "ip6";
}
