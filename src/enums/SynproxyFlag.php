<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * A TCP option a synproxy offers clients on behalf of the server behind it. Offer the ones the server supports.
 */
enum SynproxyFlag : string
{
    case TIMESTAMP = "timestamp";
    case SACK_PERMITTED = "sack-perm";
}
