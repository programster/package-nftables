<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Enums\FibFlag;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of what a fib lookup uses. Anything that isn't a FibFlag is rejected as it's added.
 *
 * @extends AbstractCollection<FibFlag>
 */
final class FibFlagCollection extends AbstractCollection
{
    public function getType() : string
    {
        return FibFlag::class;
    }
}
