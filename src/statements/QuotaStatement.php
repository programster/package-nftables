<?php

declare(strict_types=1);

namespace Programster\Nftables\Statements;

use Programster\Nftables\Enums\QuotaMatch;
use Programster\Nftables\Enums\QuotaUnit;
use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * Matches packets depending on how much traffic has reached it in total, e.g. to drop a guest's traffic once it has
 * used 10 gigabytes. The count starts again whenever the ruleset is reloaded. For a quota that several rules share, or
 * whose usage can be read with "nft list quotas", use a NamedQuota instead.
 *
 * Which packets it matches has to be chosen explicitly, as it's easy to get backwards: to cut traffic off, match
 * QuotaMatch::OVER_QUOTA and then drop. Matching WITHIN_QUOTA and then dropping drops the first part of the traffic
 * instead, and lets the rest through.
 */
final readonly class QuotaStatement implements Statement
{
    private int $m_amount;
    private QuotaUnit $m_unit;
    private QuotaMatch $m_match;
    private int $m_usedBytes;


    /**
     * Create a quota.
     *
     * @param int $amount - how much traffic it allows, in $unit, e.g. 10240 MBYTES for 10 gigabytes.
     *
     * @param QuotaUnit $unit - what the amount is counted in.
     *
     * @param QuotaMatch $match - whether to match the packets within the quota, or those over it.
     *
     * @param int $usedBytes - how much of it has been used already, in bytes, e.g. to carry on from a count saved
     * before reloading. Defaults to 0.
     *
     * @throws BadArgumentException - if the amount isn't positive, or the bytes used are negative.
     */
    public function __construct(int $amount, QuotaUnit $unit, QuotaMatch $match, int $usedBytes = 0)
    {
        if ($amount < 1 || $usedBytes < 0)
        {
            throw new BadArgumentException("A quota needs an amount of at least 1, and can't have used less than 0.");
        }

        $this->m_amount = $amount;
        $this->m_unit = $unit;
        $this->m_match = $match;
        $this->m_usedBytes = $usedBytes;
    }


    public function toArray() : array
    {
        $quota = ["val" => $this->m_amount, "val_unit" => $this->m_unit->value];

        if ($this->m_match === QuotaMatch::OVER_QUOTA)
        {
            $quota["inv"] = true;
        }

        if ($this->m_usedBytes > 0)
        {
            $quota["used"] = $this->m_usedBytes;
            $quota["used_unit"] = QuotaUnit::BYTES->value;
        }

        return ["quota" => $quota];
    }


    /**
     * Get how much traffic the quota allows, in bytes.
     *
     * @return int
     */
    public function getBytes() : int
    {
        return $this->m_amount * $this->m_unit->getBytes();
    }


    # Accessors
    public function getMatch() : QuotaMatch { return $this->m_match; }
    public function getUsedBytes() : int { return $this->m_usedBytes; }
}
