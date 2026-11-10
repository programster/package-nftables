<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\FeatureRequirement;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of the features that need a newer nft (or kernel) than the oldest supported. Anything that isn't a
 * FeatureRequirement is rejected as it's added.
 *
 * @extends AbstractCollection<FeatureRequirement>
 */
final class FeatureRequirementCollection extends AbstractCollection
{
    public function getType() : string
    {
        return FeatureRequirement::class;
    }
}
