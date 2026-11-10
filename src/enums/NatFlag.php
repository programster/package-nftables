<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A flag for a NAT statement.
 */
enum NatFlag : string
{
    // Randomise the source port mapping.
    case RANDOM = "random";

    // Fully randomise the source port mapping.
    case FULLY_RANDOM = "fully-random";

    // Give a client the same source and destination address on every connection.
    case PERSISTENT = "persistent";
}
