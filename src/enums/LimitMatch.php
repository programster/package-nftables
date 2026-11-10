<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Which packets a LimitStatement matches. This is easy to get backwards: to drop the excess, match OVER_LIMIT
 * and drop. Matching WITHIN_LIMIT and dropping would drop the allowed packets and let the rest through.
 */
enum LimitMatch
{
    // Match packets up to the rate, e.g. to accept that many.
    case WITHIN_LIMIT;

    // Match packets beyond the rate, e.g. to drop the excess.
    case OVER_LIMIT;
}
