<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\ConnectionStateCollection;
use Programster\Nftables\Enums\ConnectionState;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\Expression;

/**
 * One or more connection tracking states, for matching a connection that's in any of them.
 */
final readonly class ConnectionStateSet implements Expression
{
    // Without duplicates.
    private ConnectionStateCollection $m_states;


    /**
     * Create a set of connection states. Duplicates are ignored.
     *
     * @param ConnectionState ...$states - the states. At least one is needed.
     *
     * @throws BadArgumentException - if there are no states.
     */
    public function __construct(ConnectionState ...$states)
    {
        if (count($states) === 0)
        {
            throw new BadArgumentException("A connection state set needs at least one state.");
        }

        $unique = [];

        foreach ($states as $state)
        {
            $unique[$state->value] = $state;
        }

        $this->m_states = new ConnectionStateCollection(array_values($unique));
    }


    public function toJsonValue() : array
    {
        return $this->m_states->column("value");
    }


    # Accessors
    public function getStates() : ConnectionStateCollection { return clone $this->m_states; }
}
