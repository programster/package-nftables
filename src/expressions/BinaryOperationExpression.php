<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\BinaryOperator;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A bitwise operation on values, e.g. tcp flags & (fin | syn | rst | ack), to check only some of the flags.
 *
 * More than two operands are written as nested pairs, ((fin | syn) | rst) | ack, which means the same thing. nft
 * before 1.1 can't read an operation with more than two, and rejects (or on 0.9.8, crashes on) the whole ruleset.
 */
final readonly class BinaryOperationExpression implements Expression
{
    private BinaryOperator $m_operator;
    private array $m_operands;


    /**
     * Create a bitwise operation.
     *
     * @param BinaryOperator $operator - the operation.
     *
     * @param Expression|string|int ...$operands - the values to apply it to, in order. At least two are needed.
     *
     * @throws BadArgumentException - if there are fewer than two operands.
     */
    public function __construct(BinaryOperator $operator, Expression|string|int ...$operands)
    {
        if (count($operands) < 2)
        {
            throw new BadArgumentException("A binary operation needs at least two operands.");
        }

        $this->m_operator = $operator;
        $this->m_operands = ExpressionLib::toJsonList(...$operands);
    }


    public function toJsonValue() : array
    {
        $operation = [$this->m_operator->value => [$this->m_operands[0], $this->m_operands[1]]];

        foreach (array_slice($this->m_operands, 2) as $operand)
        {
            $operation = [$this->m_operator->value => [$operation, $operand]];
        }

        return $operation;
    }
}
