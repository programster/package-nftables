<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Enums\ConnectionState;

/**
 * A list of connection tracking states. It can't be changed once it's created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<ConnectionState>
 */
final readonly class ConnectionStateCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of connection tracking states.
     * @param ConnectionState ...$states - the connection tracking states. There can be none.
     */
    public function __construct(ConnectionState ...$states)
    {
        parent::__construct(...$states);
    }
}
