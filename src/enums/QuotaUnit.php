<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * What a quota's amount is counted in. nft has no larger unit: it silently reads "gbytes" as bytes.
 */
enum QuotaUnit : string
{
    case BYTES = "bytes";
    case KBYTES = "kbytes";
    case MBYTES = "mbytes";

    /**
     * Get the number of bytes in one of this unit, as nft counts them (a kbyte is 1024 bytes).
     *
     * @return int
     */
    public function getBytes() : int
    {
        return match ($this) {
            self::BYTES => 1,
            self::KBYTES => 1024,
            self::MBYTES => 1024 * 1024,
        };
    }
}
