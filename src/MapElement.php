<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Expressions\ExpressionLib;

/**
 * One element of a map: a key, and the value it maps to, e.g. port 2222 to the address 10.0.0.2 (2222 : 10.0.0.2).
 */
final readonly class MapElement
{
    private Expression|string|int $m_key;
    private Expression|string|int $m_value;


    /**
     * Create a map element.
     *
     * @param Expression|string|int $key - the key, e.g. a port, an address, a PortRange or PrefixExpression (in a map
     * with the INTERVAL flag), or a ConcatExpression (in a map whose key is a concatenation).
     *
     * @param Expression|string|int $value - the value, e.g. an address, or a ConcatExpression of an address and a port.
     *
     * @throws BadArgumentException - if the key or value is a string starting with "@".
     */
    public function __construct(Expression|string|int $key, Expression|string|int $value)
    {
        // Converted here only to check them, so a bad value is caught where it's created.
        ExpressionLib::toJsonValue($key);
        ExpressionLib::toJsonValue($value);
        $this->m_key = $key;
        $this->m_value = $value;
    }


    /**
     * Get the element in the form nftables expects, as a key and value pair.
     *
     * @return array
     */
    public function toJsonValue() : array
    {
        return [ExpressionLib::toJsonValue($this->m_key), ExpressionLib::toJsonValue($this->m_value)];
    }


    # Accessors
    public function getKey() : Expression|string|int { return $this->m_key; }
    public function getValue() : Expression|string|int { return $this->m_value; }
}
