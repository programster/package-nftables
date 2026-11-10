<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A flag for a table.
 *
 * The owner and persist flags aren't offered. They tie a table to the process that created it, and nft exits as soon as
 * it has loaded a file, so an owned table (and its firewall) would be deleted straight away.
 */
enum TableFlag : string
{
    // The table and its chains exist, but don't see any packets, so none of its rules apply.
    case DORMANT = "dormant";
}
