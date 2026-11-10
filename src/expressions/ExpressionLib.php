<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\PortRange;

/**
 * Converts the values statements and expressions accept into the form nftables expects.
 */
final class ExpressionLib
{
    private function __construct()
    {
    }


    /**
     * Convert an expression, or a plain string or integer, to the form nftables expects.
     *
     * @param Expression|string|int $value - the value to convert.
     *
     * @return array|string|int|bool
     *
     * @throws BadArgumentException - if a plain string starts with "@", which nftables would read as a reference to a
     * set. Use a SetReference (from NamedSet::getReference()) for that, so a value can't become one by accident.
     */
    public static function toJsonValue(Expression|string|int $value) : array|string|int|bool
    {
        if ($value instanceof Expression)
        {
            $result = $value->toJsonValue();
        }
        elseif (is_string($value) && str_starts_with($value, "@"))
        {
            $message = "\"{$value}\" would be read as a set reference. Use NamedSet::getReference() for that.";
            throw new BadArgumentException($message);
        }
        else
        {
            $result = $value;
        }

        return $result;
    }


    /**
     * Convert several values, as toJsonValue() does, into a JSON list.
     *
     * @param Expression|string|int ...$values - the values to convert.
     *
     * @return array
     *
     * @throws BadArgumentException - if a plain string starts with "@" (see toJsonValue()).
     */
    public static function toJsonList(Expression|string|int ...$values) : array
    {
        $list = [];

        foreach ($values as $value)
        {
            $list[] = self::toJsonValue($value);
        }

        return $list;
    }


    /**
     * Check whether any of some values is a range or a prefix, which a named set or map needs the INTERVAL flag to
     * hold.
     *
     * @param Expression|string|int ...$values - the values.
     *
     * @return bool
     */
    public static function isAnyInterval(Expression|string|int ...$values) : bool
    {
        $found = false;

        foreach ($values as $value)
        {
            if (
                   $value instanceof RangeExpression
                || $value instanceof PrefixExpression
                || $value instanceof PortRange
            )
            {
                $found = true;
            }
        }

        return $found;
    }
}
