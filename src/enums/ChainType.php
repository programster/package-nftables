<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What a base chain is for.
 */
enum ChainType : string
{
    // Accepting, dropping or otherwise filtering packets. Works in every family.
    case FILTER = "filter";

    // Network address translation. Only the first packet of a connection is seen. ip, ip6 and inet only.
    case NAT = "nat";

    // Rerouting packets whose marks or addresses change. The output hook in ip, ip6 and inet only.
    case ROUTE = "route";
}
