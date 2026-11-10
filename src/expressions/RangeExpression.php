<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

/**
 * A range of values, from one to another inclusive, e.g. ports 5000-6000, or addresses 10.0.0.1-10.0.0.9.
 */
final readonly class RangeExpression implements Expression
{
    private array|string|int|bool $m_from;
    private array|string|int|bool $m_to;


    /**
     * Create a range.
     *
     * @param Expression|string|int $from - the lowest value in the range.
     *
     * @param Expression|string|int $to - the highest value in the range.
     */
    public function __construct(Expression|string|int $from, Expression|string|int $to)
    {
        $this->m_from = ExpressionLib::toJsonValue($from);
        $this->m_to = ExpressionLib::toJsonValue($to);
    }


    public function toJsonValue() : array
    {
        return ["range" => [$this->m_from, $this->m_to]];
    }
}
