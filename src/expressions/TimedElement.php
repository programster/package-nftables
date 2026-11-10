<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A set element with a timeout of its own, in place of the set's, e.g. to block one address for an hour in a set whose
 * elements normally last a minute. Use it as an element of a NamedSet (see NamedSet::withElements()), or as the element
 * a SetUpdateStatement adds. Either way, the set needs a timeout (see NamedSet::withTimeout()).
 */
final readonly class TimedElement implements Expression
{
    private Expression|string|int $m_value;
    private int $m_timeoutSeconds;


    /**
     * Create an element with its own timeout.
     *
     * @param Expression|string|int $value - the element, e.g. an address, or a PayloadExpression for the packet's
     * source address in a SetUpdateStatement.
     *
     * @param int $timeoutSeconds - how long the element lasts.
     *
     * @throws BadArgumentException - if the timeout isn't positive, or the value is a string starting with "@".
     */
    public function __construct(Expression|string|int $value, int $timeoutSeconds)
    {
        if ($timeoutSeconds < 1)
        {
            throw new BadArgumentException("An element's timeout must be at least 1 second.");
        }

        // Converted here only to check it, so a bad value is caught where it's created.
        ExpressionLib::toJsonValue($value);
        $this->m_value = $value;
        $this->m_timeoutSeconds = $timeoutSeconds;
    }


    public function toJsonValue() : array
    {
        $value = ExpressionLib::toJsonValue($this->m_value);
        return ["elem" => ["val" => $value, "timeout" => $this->m_timeoutSeconds]];
    }
}
