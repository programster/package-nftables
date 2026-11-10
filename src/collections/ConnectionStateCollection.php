<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Enums\ConnectionState;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of connection tracking states. Anything that isn't a ConnectionState is rejected as it's added.
 *
 * @extends AbstractCollection<ConnectionState>
 */
final class ConnectionStateCollection extends AbstractCollection
{
    public function getType() : string
    {
        return ConnectionState::class;
    }
}
