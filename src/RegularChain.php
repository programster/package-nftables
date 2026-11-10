<?php

declare(strict_types=1);

namespace Programster\Nftables;

/**
 * A chain that isn't attached to a hook, so it only sees the packets that a JumpStatement or GotoStatement sends to it.
 * Useful for grouping rules, e.g. all the rules for one service, and jumping to them from several places.
 */
final readonly class RegularChain extends Chain
{
    public function toArray() : array
    {
        return ["chain" => $this->getIdentifier()];
    }
}
