<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

use Programster\Nftables\Expressions\Expression;

/**
 * Whether something is in the packet, for an existence check (see MatchFactory::createExistence()), e.g.
 * whether it has an IPv6 fragment header, or whether a fib lookup found a route.
 */
enum Existence implements Expression
{
    // It's there.
    case EXISTS;

    // It isn't there.
    case MISSING;


    public function toJsonValue() : bool
    {
        return ($this === Existence::EXISTS);
    }
}
