<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A flag for a named set.
 */
enum SetFlag : string
{
    // The elements can't be changed once loaded.
    case CONSTANT = "constant";

    // The set can hold ranges and CIDR prefixes, not just single values.
    case INTERVAL = "interval";

    // Elements can expire.
    case TIMEOUT = "timeout";
}
