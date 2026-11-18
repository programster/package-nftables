<?php

declare(strict_types=1);

namespace Programster\Nftables\Rules;

use Programster\Nftables\Enums\LimitPeriod;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A limit on the new connections each source address can open per period, e.g. 60 a minute, for
 * PerSourceConnectionLimits. They can all be opened at once (the burst is the same as the rate), as many clients (e.g.
 * mail libraries) open a new connection for each thing they do.
 */
final readonly class ConnectionRateLimit
{
    private int $m_maxNewConnections;
    private LimitPeriod $m_period;
    private int $m_periodSeconds;


    /**
     * Create a limit on the new connections each source address can open per period.
     *
     * @param int $maxNewConnections - the most new connections each source address can open per $period.
     *
     * @param LimitPeriod $period - the period they're counted over.
     *
     * @throws BadArgumentException - if $maxNewConnections is less than 1.
     */
    public function __construct(int $maxNewConnections, LimitPeriod $period)
    {
        if ($maxNewConnections < 1)
        {
            throw new BadArgumentException("A connection rate limit needs to allow at least 1 new connection.");
        }

        $this->m_maxNewConnections = $maxNewConnections;
        $this->m_period = $period;

        $this->m_periodSeconds = match ($period) {
            LimitPeriod::SECOND => 1,
            LimitPeriod::MINUTE => 60,
            LimitPeriod::HOUR => 3600,
            LimitPeriod::DAY => 86400,
            LimitPeriod::WEEK => 604800,
        };
    }


    # Accessors
    public function getMaxNewConnections() : int { return $this->m_maxNewConnections; }
    public function getPeriod() : LimitPeriod { return $this->m_period; }
    public function getPeriodSeconds() : int { return $this->m_periodSeconds; }
}
