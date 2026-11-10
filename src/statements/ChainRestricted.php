<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\BaseChain;
use Programster\Nftables\Exceptions\UnsuitableChainException;

/**
 * A statement that the kernel only allows in some base chains, e.g. flow offloading, which only works on the forward
 * hook. Creating a rule with one in an unsuitable base chain throws, rather than nft rejecting the whole ruleset. A
 * rule in a regular chain isn't checked, as that depends on which chains jump to it.
 */
interface ChainRestricted
{
    /**
     * Check that the statement can be used in a base chain.
     *
     * @param BaseChain $chain - the chain.
     *
     * @return void
     *
     * @throws UnsuitableChainException - if it can't.
     */
    public function assertSuitsChain(BaseChain $chain) : void;
}
