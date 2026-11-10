<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Enums\CtTimeoutState;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * How long a CtTimeout keeps connections in one state, e.g. established TCP connections for 2 hours.
 */
final readonly class CtTimeoutPolicy
{
    private CtTimeoutState $m_state;
    private int $m_seconds;


    /**
     * Create a timeout policy.
     *
     * @param CtTimeoutState $state - the connection state.
     *
     * @param int $seconds - how long a connection in that state lasts without traffic before conntrack forgets it.
     *
     * @throws BadArgumentException - if the time isn't positive.
     */
    public function __construct(CtTimeoutState $state, int $seconds)
    {
        if ($seconds < 1)
        {
            throw new BadArgumentException("A conntrack timeout must be at least 1 second.");
        }

        $this->m_state = $state;
        $this->m_seconds = $seconds;
    }


    # Accessors
    public function getState() : CtTimeoutState { return $this->m_state; }
    public function getSeconds() : int { return $this->m_seconds; }
}
