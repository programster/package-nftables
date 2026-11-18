<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Enums\LogFlag;

/**
 * A list of the extra information a log statement includes. It can't be changed once it's created, so it can be shared
 * freely.
 *
 * @extends AbstractReadonlyCollection<LogFlag>
 */
final readonly class LogFlagCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of the extra information a log statement includes.
     * @param LogFlag ...$flags - the extra information to log. There can be none.
     */
    public function __construct(LogFlag ...$flags)
    {
        parent::__construct(...$flags);
    }
}
