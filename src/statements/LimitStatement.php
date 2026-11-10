<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Enums\LimitMatch;
use Programster\Nftables\Enums\LimitPeriod;
use Programster\Nftables\Enums\LimitUnit;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * Matches packets depending on how fast they're arriving, e.g. to drop more than 10 new SSH connections a minute.
 *
 * Which packets it matches has to be chosen explicitly, as it's easy to get backwards: to drop the excess, match
 * LimitMatch::OVER_LIMIT and then drop. Matching WITHIN_LIMIT and then dropping drops the allowed packets instead.
 */
final readonly class LimitStatement implements Statement
{
    private int $m_rate;
    private LimitPeriod $m_period;
    private LimitMatch $m_match;
    private int $m_burst;
    private LimitUnit $m_unit;


    /**
     * Create a rate limit.
     *
     * @param int $rate - how many packets (or bytes, see $unit) are allowed per $period.
     *
     * @param LimitPeriod $period - the period the rate is measured over.
     *
     * @param LimitMatch $match - whether to match the packets within the limit, or those over it.
     *
     * @param int $burst - how far above the rate a short burst can go. Defaults to 0, which leaves it to nftables (5
     * packets).
     *
     * @param LimitUnit $unit - what the rate and burst count. Defaults to packets.
     *
     * @throws BadArgumentException - if the rate isn't positive, or the burst is negative.
     */
    public function __construct(
        int $rate,
        LimitPeriod $period,
        LimitMatch $match,
        int $burst = 0,
        LimitUnit $unit = LimitUnit::PACKETS,
    )
    {
        if ($rate < 1 || $burst < 0)
        {
            throw new BadArgumentException("A limit needs a rate of at least 1, and a burst of at least 0.");
        }

        $this->m_rate = $rate;
        $this->m_period = $period;
        $this->m_match = $match;
        $this->m_burst = $burst;
        $this->m_unit = $unit;
    }


    public function toArray() : array
    {
        $limit = ["rate" => $this->m_rate, "per" => $this->m_period->value];

        if ($this->m_unit !== LimitUnit::PACKETS)
        {
            $limit["rate_unit"] = $this->m_unit->value;
        }

        if ($this->m_burst > 0)
        {
            $limit["burst"] = $this->m_burst;
            $limit["burst_unit"] = $this->m_unit->value;
        }

        if ($this->m_match === LimitMatch::OVER_LIMIT)
        {
            $limit["inv"] = true;
        }

        return ["limit" => $limit];
    }
}
