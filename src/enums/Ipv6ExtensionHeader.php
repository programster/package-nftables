<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * An IPv6 extension header, for an ExthdrExpression.
 */
enum Ipv6ExtensionHeader : string
{
    case HOP_BY_HOP = "hbh";
    case ROUTING = "rt";
    case FRAGMENT = "frag";
    case DESTINATION_OPTIONS = "dst";
    case MOBILITY = "mh";
}
