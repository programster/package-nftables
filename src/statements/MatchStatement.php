<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Enums\Operator;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\ExpressionLib;
use Programster\Nftables\ReferencesTableItems;
use Programster\Nftables\TableItemLib;

/**
 * Compares part of a packet with a value. If it doesn't match, the rest of the rule is skipped, and the packet moves on
 * to the next rule. MatchFactory creates the common ones.
 */
final readonly class MatchStatement implements Statement, ReferencesTableItems
{
    private Expression $m_left;
    private Operator $m_operator;
    private Expression|string|int $m_right;


    /**
     * Create a match.
     *
     * @param Expression $left - what to read from the packet, e.g. a PayloadExpression for its TCP destination port.
     *
     * @param Operator $operator - how to compare it.
     *
     * @param Expression|string|int $right - what to compare it with, e.g. 22, or a SetExpression of ports.
     *
     * @throws \Programster\Nftables\Exceptions\BadArgumentException - if $right is a string starting with "@", which
     * nftables would read as a set reference. Use NamedSet::getReference() for that.
     */
    public function __construct(Expression $left, Operator $operator, Expression|string|int $right)
    {
        // Converted here only to check it, so a bad value is caught where it's created.
        ExpressionLib::toJsonValue($right);
        $this->m_left = $left;
        $this->m_operator = $operator;
        $this->m_right = $right;
    }


    public function toArray() : array
    {
        $match = [
            "op" => $this->m_operator->value,
            "left" => $this->m_left->toJsonValue(),
            "right" => ExpressionLib::toJsonValue($this->m_right),
        ];

        return ["match" => $match];
    }


    public function getReferencedItems() : TableItemCollection
    {
        return TableItemLib::collectReferences($this->m_left, $this->m_right);
    }


    # Accessors
    public function getLeft() : Expression { return $this->m_left; }
    public function getOperator() : Operator { return $this->m_operator; }
    public function getRight() : Expression|string|int { return $this->m_right; }
}
