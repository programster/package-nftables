<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What happens to a packet that reaches the end of a base chain without a verdict.
 */
enum Policy : string
{
    // Let it through.
    case ACCEPT = "accept";

    // Silently discard it.
    case DROP = "drop";
}
