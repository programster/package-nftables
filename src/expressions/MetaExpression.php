<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\MetaKey;

/**
 * Metadata about a packet, rather than its contents, e.g. the interface it arrived on, or its mark.
 */
final readonly class MetaExpression implements Expression
{
    private MetaKey $m_key;


    public function __construct(MetaKey $key)
    {
        $this->m_key = $key;
    }


    public function toJsonValue() : array
    {
        return ["meta" => ["key" => $this->m_key->value]];
    }


    # Accessors
    public function getKey() : MetaKey { return $this->m_key; }
}
