<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Routing data about a packet, for an RtExpression.
 */
enum RtKey : string
{
    // The routing realm.
    case CLASSID = "classid";

    // The address of the next hop.
    case NEXTHOP = "nexthop";

    // The MTU of the route, e.g. to clamp TCP's maximum segment size to it.
    case MTU = "mtu";
}
