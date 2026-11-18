<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Objects\CtTimeoutPolicy;

/**
 * A list of conntrack timeouts, one per connection state. It can't be changed once it's created, so it can be shared
 * freely.
 *
 * @extends AbstractReadonlyCollection<CtTimeoutPolicy>
 */
final readonly class CtTimeoutPolicyCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of conntrack timeouts, one per connection state.
     * @param CtTimeoutPolicy ...$policies - the timeouts, one per connection state. There can be none.
     */
    public function __construct(CtTimeoutPolicy ...$policies)
    {
        parent::__construct(...$policies);
    }
}
