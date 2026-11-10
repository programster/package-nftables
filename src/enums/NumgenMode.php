<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * How a NumgenExpression picks its numbers.
 */
enum NumgenMode : string
{
    // Count up, one per packet, going back to the start after the last, e.g. to take turns (round robin).
    case INCREMENTAL = "inc";

    // Pick at random.
    case RANDOM = "random";
}
