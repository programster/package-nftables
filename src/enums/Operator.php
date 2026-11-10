<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * How a MatchStatement compares its left side with its right.
 */
enum Operator : string
{
    // Equal to (or, with a set on the right, a member of it).
    case EQUALS = "==";

    // Not equal to (or, with a set on the right, not a member of it).
    case NOT_EQUALS = "!=";
    case LESS_THAN = "<";
    case GREATER_THAN = ">";
    case LESS_THAN_OR_EQUAL = "<=";
    case GREATER_THAN_OR_EQUAL = ">=";

    // Any of the flags on the right are set (e.g. ct state in [established, related]).
    case IN = "in";
}
