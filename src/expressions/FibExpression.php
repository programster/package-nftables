<?php

declare(strict_types=1);

namespace Programster\Nftables\Expressions;

use Programster\Nftables\Collections\FibFlagCollection;
use Programster\Nftables\Enums\FibFlag;
use Programster\Nftables\Enums\FibResult;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A lookup in the routing table (forwarding information base) for one of the packet's addresses, e.g. to find packets
 * whose source address couldn't have come in on the interface they did (fib saddr . iif oif missing), which is how
 * spoofed packets are spotted. RuleFactory::createReversePathFilter() creates that rule.
 */
final readonly class FibExpression implements Expression
{
    private FibResult $m_result;

    // Without duplicates.
    private FibFlagCollection $m_flags;


    /**
     * Create a fib lookup.
     *
     * @param FibResult $result - what to look up.
     *
     * @param FibFlag ...$flags - what the lookup uses. Exactly one of SADDR and DADDR is needed, and IIF and OIF can't
     * both be given.
     *
     * @throws BadArgumentException - if the flags don't include exactly one of SADDR and DADDR, or include both IIF and
     * OIF.
     */
    public function __construct(FibResult $result, FibFlag ...$flags)
    {
        // Keyed by value, to leave out duplicates.
        $uniqueFlags = [];

        foreach ($flags as $flag)
        {
            $uniqueFlags[$flag->value] = $flag;
        }

        $values = array_keys($uniqueFlags);
        $addresses = array_intersect($values, [FibFlag::SADDR->value, FibFlag::DADDR->value]);
        $interfaces = array_intersect($values, [FibFlag::IIF->value, FibFlag::OIF->value]);

        if (count($addresses) !== 1 || count($interfaces) > 1)
        {
            $message = "A fib lookup needs exactly one of SADDR and DADDR, and at most one of IIF and OIF.";
            throw new BadArgumentException($message);
        }

        $this->m_result = $result;
        $this->m_flags = new FibFlagCollection(array_values($uniqueFlags));
    }


    public function toJsonValue() : array
    {
        return ["fib" => ["result" => $this->m_result->value, "flags" => $this->m_flags->column("value")]];
    }


    # Accessors
    public function getResult() : FibResult { return $this->m_result; }
}
