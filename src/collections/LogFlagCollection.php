<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Enums\LogFlag;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of the extra information a log statement includes. Anything that isn't a LogFlag is rejected as it's added.
 *
 * @extends AbstractCollection<LogFlag>
 */
final class LogFlagCollection extends AbstractCollection
{
    public function getType() : string
    {
        return LogFlag::class;
    }
}
