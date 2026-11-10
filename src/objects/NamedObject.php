<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

use Programster\Nftables\Exceptions\BadArgumentException;
use Programster\Nftables\NameLib;
use Programster\Nftables\Statements\NamedObjectStatement;
use Programster\Nftables\Table;
use Programster\Nftables\TableItem;

/**
 * A named, stateful object in a table, e.g. a counter or a quota, which any number of rules can use, and whose state
 * "nft list ruleset" shows. A rule uses one with createStatement(). Adding a rule that does to a Ruleset adds the
 * object as well.
 *
 * Reloading a Ruleset recreates its objects, so their state (e.g. a counter's count) starts again.
 */
abstract readonly class NamedObject implements TableItem
{
    protected string $m_name;
    protected Table $m_table;


    /**
     * Create a named object.
     *
     * @param string $name - the object's name, which must be unique among the objects of its kind in its table.
     *
     * @param Table $table - the table it belongs to. Only rules in the same table can use it.
     *
     * @throws BadArgumentException - if the name is empty or too long.
     */
    public function __construct(string $name, Table $table)
    {
        NameLib::assertValidName($name, "named object");
        $this->m_name = $name;
        $this->m_table = $table;
    }


    abstract public function toArray() : array;


    /**
     * Get a statement that uses the object for the packet, e.g. counts it, for a counter.
     *
     * @return NamedObjectStatement
     */
    public function createStatement() : NamedObjectStatement
    {
        return new NamedObjectStatement($this);
    }


    /**
     * Get the parts of the object's definition that every object has.
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
