<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * Several values joined into one, so they can be matched together, e.g. a source address and destination port
 * (ip saddr . tcp dport), against a set of address and port pairs.
 */
final readonly class ConcatExpression implements Expression
{
    private array $m_parts;


    /**
     * Join values together.
     *
     * @param Expression|string|int ...$parts - the values, in order. At least two are needed.
     *
     * @throws BadArgumentException - if there are fewer than two.
     */
    public function __construct(Expression|string|int ...$parts)
    {
        if (count($parts) < 2)
        {
            throw new BadArgumentException("A concatenation needs at least two parts.");
        }

        $this->m_parts = ExpressionLib::toJsonList(...$parts);
    }


    public function toJsonValue() : array
    {
        return ["concat" => $this->m_parts];
    }
}
