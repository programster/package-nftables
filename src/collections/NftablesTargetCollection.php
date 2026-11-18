<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Enums\NftablesTarget;

/**
 * A list of targets, e.g. the ones a feature was backported to. It can't be changed once it's created, so it can be
 * shared freely.
 *
 * @extends AbstractReadonlyCollection<NftablesTarget>
 */
final readonly class NftablesTargetCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of targets.
     * @param NftablesTarget ...$targets - the targets. There can be none.
     */
    public function __construct(NftablesTarget ...$targets)
    {
        parent::__construct(...$targets);
    }
}
