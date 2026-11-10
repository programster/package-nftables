<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

/**
 * A value used inside a statement, e.g. a packet header field, an anonymous set, a range, a CIDR prefix, or a
 * reference to a named set. Statements also accept plain strings and integers wherever they take an expression.
 */
interface Expression
{
    /**
     * Get the expression in the form nftables expects.
     *
     * @return array|string|int|bool - an array for most expressions, a string for a set reference ("@name") or a
     * named value (e.g. an AddressType), or a bool for an Existence.
     */
    public function toJsonValue() : array|string|int|bool;
}
