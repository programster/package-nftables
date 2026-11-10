<?php

declare(strict_types=1);

namespace Programster\Nftables\Enums;

/**
 * Whether a match created by MatchFactory is positive, or negated.
 */
enum MatchMode
{
    // Match packets that have the value.
    case MATCHES;

    // Match packets that don't have the value.
    case DOES_NOT_MATCH;

    /**
     * Get the operator for this mode.
     *
     * @return Operator - EQUALS or NOT_EQUALS.
     */
    public function getOperator() : Operator
    {
        return match ($this) {
            MatchMode::MATCHES => Operator::EQUALS,
            MatchMode::DOES_NOT_MATCH => Operator::NOT_EQUALS,
        };
    }
}
