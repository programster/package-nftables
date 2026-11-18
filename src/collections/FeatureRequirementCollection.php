<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Internal\FeatureRequirement;

/**
 * A list of the features that need a newer nft (or kernel) than the oldest supported. It can't be changed once it's
 * created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<FeatureRequirement>
 */
final readonly class FeatureRequirementCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of the features that need a newer nft (or kernel) than the oldest supported.
     * @param FeatureRequirement ...$requirements - the features that need a newer nft (or kernel). There can be none.
     */
    public function __construct(FeatureRequirement ...$requirements)
    {
        parent::__construct(...$requirements);
    }
}
