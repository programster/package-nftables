<?php

declare(strict_types=1);

namespace Programster\Nftables;

/**
 * Something that belongs to a table and is defined in a Ruleset: a chain, set, map, flowtable or named object.
 */
interface TableItem
{
    /**
     * Get the item's name, which is unique within its table among items of its kind.
     *
     * @return string
     */
    public function getName() : string;


    /**
     * Get the table the item belongs to.
     *
     * @return Table
     */
    public function getTable() : Table;


    /**
     * Get the item in the form nftables expects.
     *
     * @return array
     */
    public function toArray() : array;
}
