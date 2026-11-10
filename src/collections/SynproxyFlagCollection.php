<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Enums\SynproxyFlag;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of the TCP options a synproxy offers. Anything that isn't a SynproxyFlag is rejected as it's added.
 *
 * @extends AbstractCollection<SynproxyFlag>
 */
final class SynproxyFlagCollection extends AbstractCollection
{
    public function getType() : string
    {
        return SynproxyFlag::class;
    }
}
