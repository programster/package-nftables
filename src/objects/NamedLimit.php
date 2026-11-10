<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\Statements\LimitStatement;
use Programster\Nftables\Table;

/**
 * A named rate limit, which any number of rules can share (limit name "ssh"), so their packets count towards one
 * rate. See LimitStatement for which packets it matches.
 */
final readonly class NamedLimit extends NamedObject
{
    private LimitStatement $m_limit;


    /**
     * Create a named limit.
     *
     * @param string $name - the limit's name, which must be unique among the limits in its table.
     *
     * @param Table $table - the table it belongs to.
     *
     * @param LimitStatement $limit - the rate, and which packets it matches.
     *
     * @throws BadArgumentException - if the name is empty or too long.
     */
    public function __construct(string $name, Table $table, LimitStatement $limit)
    {
        parent::__construct($name, $table);
        $this->m_limit = $limit;
    }


    public function toArray() : array
    {
        return ["limit" => [...$this->getIdentifier(), ...$this->m_limit->toArray()["limit"]]];
    }
}
