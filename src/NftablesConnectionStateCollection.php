<?php

namespace Programster\Nftables;


use Programster\Nftables\Enums\NftablesConnectionState;
use Programster\Nftables\Exceptions\ExceptionConnectionStateRequired;

readonly class NftablesConnectionStateCollection
{
    private array $m_connectionStates;


    /**
     * Create a collection of connection states.
     * @param NftablesConnectionState ...$connectionStates
     * @throws ExceptionConnectionStateRequired - if no connection states were provided.
     */
    public function __construct(NftablesConnectionState ...$connectionStates)
    {
        if (count($connectionStates) === 0)
        {
            throw new ExceptionConnectionStateRequired();
        }

        $this->m_connectionStates = $connectionStates;
    }

    public function getStates() : array { return $this->m_connectionStates; }
}
