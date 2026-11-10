<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Enums\PayloadBase;
use Programster\Nftables\Enums\PayloadField;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A field in the packet's headers, e.g. its TCP destination port, or its IPv4 source address.
 */
final readonly class PayloadExpression implements Expression
{
    private array $m_value;


    private function __construct(array $value)
    {
        $this->m_value = $value;
    }


    /**
     * Create an expression for a named header field.
     *
     * @param PayloadField $field - the field, e.g. PayloadField::TCP_DPORT.
     *
     * @return PayloadExpression
     */
    public static function create(PayloadField $field) : PayloadExpression
    {
        return new PayloadExpression(["protocol" => $field->getProtocol(), "field" => $field->getField()]);
    }


    /**
     * Create an expression for any run of bits in the packet, for headers nftables doesn't name.
     *
     * @param PayloadBase $base - which header the offset is measured from.
     *
     * @param int $offset - where the bits start, in bits from the start of that header.
     *
     * @param int $length - how many bits to read.
     *
     * @return PayloadExpression
     *
     * @throws BadArgumentException - if the offset is negative, or the length isn't positive.
     */
    public static function createRaw(PayloadBase $base, int $offset, int $length) : PayloadExpression
    {
        if ($offset < 0 || $length < 1)
        {
            throw new BadArgumentException("A raw payload needs an offset of at least 0, and a length of at least 1.");
        }

        return new PayloadExpression(["base" => $base->value, "offset" => $offset, "len" => $length]);
    }


    public function toJsonValue() : array
    {
        return ["payload" => $this->m_value];
    }
}
