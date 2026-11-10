<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

/**
 * Part of a rule, e.g. a match, a counter, a NAT statement or a verdict. A rule is a list of these, applied in order.
 */
interface Statement
{
    /**
     * Get the statement in the form nftables expects in a rule's "expr" list.
     *
     * @return array
     */
    public function toArray() : array;
}
