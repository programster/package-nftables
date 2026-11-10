<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

/**
 * Exempts the packet from connection tracking. This only works before tracking starts, so it belongs in a chain on the
 * prerouting or output hook with Priority::RAW. Untracked packets can't match ct state established or related, so rules
 * that rely on that won't see them.
 */
final readonly class NotrackStatement implements Statement
{
    public function toArray() : array
    {
        return ["notrack" => null];
    }
}
