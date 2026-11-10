<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What a FibExpression's lookup uses. Exactly one of SADDR and DADDR is needed, and IIF and OIF can't both be
 * used.
 */
enum FibFlag : string
{
    // Look up the packet's source address.
    case SADDR = "saddr";

    // Look up the packet's destination address.
    case DADDR = "daddr";

    // Include the packet's mark in the lookup.
    case MARK = "mark";

    // Only consider routes through the interface the packet arrived on.
    case IIF = "iif";

    // Only consider routes through the interface the packet is leaving by.
    case OIF = "oif";
}
