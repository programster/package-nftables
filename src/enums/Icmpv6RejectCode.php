<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * The ICMPv6 error a RejectStatement replies with. ip6 and inet tables only.
 */
enum Icmpv6RejectCode : string
{
    case NO_ROUTE = "no-route";
    case ADMIN_PROHIBITED = "admin-prohibited";
    case ADDR_UNREACHABLE = "addr-unreachable";
    case PORT_UNREACHABLE = "port-unreachable";
    case POLICY_FAIL = "policy-fail";
    case REJECT_ROUTE = "reject-route";
}
