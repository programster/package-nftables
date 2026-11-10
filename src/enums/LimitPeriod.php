<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * The period a LimitStatement's rate is measured over.
 */
enum LimitPeriod : string
{
    case SECOND = "second";
    case MINUTE = "minute";
    case HOUR = "hour";
    case DAY = "day";
    case WEEK = "week";
}
