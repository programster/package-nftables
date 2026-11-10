<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Which packets a quota matches. This is easy to get backwards: to cut traffic off once it has used its quota, match
 * OVER_QUOTA and drop. Matching WITHIN_QUOTA and dropping would drop the quota's worth of traffic, then let everything
 * else through.
 */
enum QuotaMatch
{
    // Match packets until the quota is used up, e.g. to accept that much.
    case WITHIN_QUOTA;

    // Match packets once the quota is used up, e.g. to drop the rest.
    case OVER_QUOTA;
}
