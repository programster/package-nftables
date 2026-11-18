<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Chains\EmptyChain;

/**
 * A list of empty chains, for a Ruleset. It can't be changed once it's created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<EmptyChain>
 */
final readonly class EmptyChainCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of empty chains, for a Ruleset.
     * @param EmptyChain ...$chains - the empty chains. There can be none.
     */
    public function __construct(EmptyChain ...$chains)
    {
        parent::__construct(...$chains);
    }
}
