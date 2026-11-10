<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Exceptions\BadArgumentException;

/**
 * A chain, which holds rules. A BaseChain is attached to a hook, so it sees packets. A RegularChain only sees the
 * packets that rules jump (or go) to it.
 */
abstract readonly class Chain implements TableItem
{
    protected string $m_name;
    protected Table $m_table;


    /**
     * Create a chain.
     *
     * @param string $name - the chain's name, which must be unique within its table.
     *
     * @param Table $table - the table the chain belongs to.
     *
     * @throws BadArgumentException - if the name is empty or too long.
     */
    public function __construct(string $name, Table $table)
    {
        NameLib::assertValidName($name, "chain");
        $this->m_name = $name;
        $this->m_table = $table;
    }


    abstract public function toArray() : array;


    /**
     * Get the parts of the chain's definition that every chain has.
     *
     * @return array
     */
    protected function getIdentifier() : array
    {
        $family = $this->m_table->getFamily()->value;
        return ["family" => $family, "table" => $this->m_table->getName(), "name" => $this->m_name];
    }


    # Accessors
    public function getName() : string { return $this->m_name; }
    public function getTable() : Table { return $this->m_table; }
}
