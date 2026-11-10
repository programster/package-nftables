<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Enums\QuotaMatch;
use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Statements\QuotaStatement;
use Programster\Nftables\Table;

/**
 * A named quota, which any number of rules can share (quota name "guest1"), e.g. so a guest's traffic in both
 * directions counts towards one allowance. "nft list quota <family> <table> <name>" shows how much has been used, and
 * "nft reset quota" starts it again. See QuotaStatement for which packets it matches.
 */
final readonly class NamedQuota extends NamedObject
{
    private QuotaStatement $m_quota;


    /**
     * Create a named quota.
     *
     * @param string $name - the quota's name, which must be unique among the quotas in its table.
     *
     * @param Table $table - the table it belongs to.
     *
     * @param QuotaStatement $quota - the amount, and which packets it matches.
     *
     * @throws BadArgumentException - if the name is empty or too long.
     */
    public function __construct(string $name, Table $table, QuotaStatement $quota)
    {
        parent::__construct($name, $table);
        $this->m_quota = $quota;
    }


    public function toArray() : array
    {
        $quota = [...$this->getIdentifier(), "bytes" => $this->m_quota->getBytes()];

        if ($this->m_quota->getUsedBytes() > 0)
        {
            $quota["used"] = $this->m_quota->getUsedBytes();
        }

        if ($this->m_quota->getMatch() === QuotaMatch::OVER_QUOTA)
        {
            $quota["inv"] = true;
        }

        return ["quota" => $quota];
    }
}
