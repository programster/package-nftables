<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Objects\CtTimeoutPolicy;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of conntrack timeouts, one per connection state. Anything that isn't a CtTimeoutPolicy is rejected as it's
 * added.
 *
 * @extends AbstractCollection<CtTimeoutPolicy>
 */
final class CtTimeoutPolicyCollection extends AbstractCollection
{
    public function getType() : string
    {
        return CtTimeoutPolicy::class;
    }
}
