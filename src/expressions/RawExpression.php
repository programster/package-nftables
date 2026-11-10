<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

/**
 * An expression given directly in nftables' JSON form, for anything this package doesn't model yet (e.g. a numgen or
 * hash expression). It's passed to nftables exactly as given, without any checks, so double check it against the
 * libnftables-json documentation.
 */
final readonly class RawExpression implements Expression
{
    private array|string|int|bool $m_value;


    /**
     * Create a raw expression.
     *
     * @param array|string|int|bool $value - the expression, exactly as nftables' JSON expects it, e.g.
     * ["numgen" => ["mode" => "random", "mod" => 2]].
     */
    public function __construct(array|string|int|bool $value)
    {
        $this->m_value = $value;
    }


    public function toJsonValue() : array|string|int|bool
    {
        return $this->m_value;
    }
}
