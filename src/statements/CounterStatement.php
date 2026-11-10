<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

/**
 * Counts the packets and bytes that reach it, as shown by "nft list ruleset".
 */
final readonly class CounterStatement implements Statement
{
    public function toArray() : array
    {
        return ["counter" => null];
    }
}
