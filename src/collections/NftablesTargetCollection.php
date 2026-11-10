<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Enums\NftablesTarget;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of targets, e.g. the ones a feature was backported to. Anything that isn't a NftablesTarget is rejected as
 * it's added.
 *
 * @extends AbstractCollection<NftablesTarget>
 */
final class NftablesTargetCollection extends AbstractCollection
{
    public function getType() : string
    {
        return NftablesTarget::class;
    }
}
