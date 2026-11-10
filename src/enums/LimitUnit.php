<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What a LimitStatement's rate and burst count.
 */
enum LimitUnit : string
{
    case PACKETS = "packets";
    case BYTES = "bytes";
    case KBYTES = "kbytes";
    case MBYTES = "mbytes";
}
