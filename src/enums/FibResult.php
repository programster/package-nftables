<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What a FibExpression looks up in the routing table (forwarding information base).
 */
enum FibResult : string
{
    // The interface the packet would leave by, as an index. Check it with Existence::MISSING to find packets
    // there's no route for.
    case OIF = "oif";

    // The name of the interface the packet would leave by.
    case OIFNAME = "oifname";

    // The type of the address, compared with an AddressType (e.g. local).
    case TYPE = "type";
}
