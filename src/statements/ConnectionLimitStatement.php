<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Enums\LimitMatch;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * Matches packets depending on how many connections conntrack is tracking (ct count), e.g. to stop any one address
 * having more than 20 connections open at once. On its own in a rule, it counts every connection that reaches it. Its
 * usual use is per address, in a SetUpdateStatement (add @conns { ip saddr ct count over 20 }), so each address has its
 * own count, and the set's elements are removed by themselves once their count drops to zero.
 *
 * Which packets it matches has to be chosen explicitly, as for a LimitStatement: to drop connections beyond the
 * limit, match LimitMatch::OVER_LIMIT and then drop.
 */
final readonly class ConnectionLimitStatement implements Statement
{
    private int $m_count;
    private LimitMatch $m_match;


    /**
     * Create a connection limit.
     *
     * @param int $count - how many connections are allowed.
     *
     * @param LimitMatch $match - whether to match the packets of connections within the limit, or those over it.
     *
     * @throws BadArgumentException - if the count isn't positive.
     */
    public function __construct(int $count, LimitMatch $match)
    {
        if ($count < 1)
        {
            throw new BadArgumentException("A connection limit needs a count of at least 1.");
        }

        $this->m_count = $count;
        $this->m_match = $match;
    }


    public function toArray() : array
    {
        $limit = ["val" => $this->m_count];

        if ($this->m_match === LimitMatch::OVER_LIMIT)
        {
            $limit["inv"] = true;
        }

        return ["ct count" => $limit];
    }
}
