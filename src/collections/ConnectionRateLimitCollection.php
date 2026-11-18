<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Rules\ConnectionRateLimit;

/**
 * A list of connection rate limits, for PerSourceConnectionLimits. It can't be changed once it's created, so it can be
 * shared freely.
 *
 * @extends AbstractReadonlyCollection<ConnectionRateLimit>
 */
final readonly class ConnectionRateLimitCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of connection rate limits.
     * @param ConnectionRateLimit ...$rates - the rate limits. There can be none.
     */
    public function __construct(ConnectionRateLimit ...$rates)
    {
        parent::__construct(...$rates);
    }
}
