<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Enums\FibFlag;

/**
 * A list of what a fib lookup uses. It can't be changed once it's created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<FibFlag>
 */
final readonly class FibFlagCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of what a fib lookup uses.
     * @param FibFlag ...$flags - what the fib lookup uses. There can be none.
     */
    public function __construct(FibFlag ...$flags)
    {
        parent::__construct(...$flags);
    }
}
