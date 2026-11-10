<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * An anonymous set of values, written into the rule itself, e.g. { 22, 80, 443 }. For a set that's shared between
 * rules, or changed without reloading, use a NamedSet instead.
 */
final readonly class SetExpression implements Expression
{
    private array $m_elements;


    /**
     * Create an anonymous set.
     *
     * @param Expression|string|int ...$elements - the values in the set. At least one is needed.
     *
     * @throws BadArgumentException - if there are no elements, or a plain string starts with "@".
     */
    public function __construct(Expression|string|int ...$elements)
    {
        if (count($elements) === 0)
        {
            throw new BadArgumentException("A set needs at least one element.");
        }

        $this->m_elements = ExpressionLib::toJsonList(...$elements);
    }


    public function toJsonValue() : array
    {
        return ["set" => $this->m_elements];
    }
}
