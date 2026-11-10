<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

use Programster\Nftables\Expressions\Expression;

/**
 * The type of an address, as a FibExpression looks it up (fib ... type).
 */
enum AddressType : string implements Expression
{
    case UNSPEC = "unspec";
    case UNICAST = "unicast";

    // One of this machine's addresses.
    case LOCAL = "local";
    case BROADCAST = "broadcast";
    case ANYCAST = "anycast";
    case MULTICAST = "multicast";
    case BLACKHOLE = "blackhole";
    case UNREACHABLE = "unreachable";
    case PROHIBIT = "prohibit";


    public function toJsonValue() : string
    {
        return $this->value;
    }
}
