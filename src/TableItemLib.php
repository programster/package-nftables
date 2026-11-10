<?php

declare(strict_types=1);

namespace Programster\Nftables;

use Programster\Nftables\Collections\TableItemCollection;
use Programster\Nftables\Exceptions\UnsuitableChainException;
use Programster\Nftables\Expressions\Expression;
use Programster\Nftables\Statements\Statement;

/**
 * Helps with the items (chains, sets, maps, flowtables and named objects) that rules and other items refer to.
 *
 * @internal
 */
final class TableItemLib
{
    private function __construct()
    {
    }


    /**
     * Get the items that some values refer to.
     *
     * @param Expression|Statement|string|int ...$values - the values. Only those that implement ReferencesTableItems
     * refer to anything.
     *
     * @return TableItemCollection
     */
    public static function collectReferences(Expression|Statement|string|int ...$values) : TableItemCollection
    {
        $items = new TableItemCollection();

        foreach ($values as $value)
        {
            if ($value instanceof ReferencesTableItems)
            {
                self::addAll($items, $value->getReferencedItems());
            }
        }

        return $items;
    }


    /**
     * Get the items that an item refers to, e.g. the chains a verdict map jumps to.
     *
     * @param TableItem $item - the item.
     *
     * @return TableItemCollection - empty if it doesn't refer to anything.
     */
    public static function collectReferencesOfItem(TableItem $item) : TableItemCollection
    {
        return ($item instanceof ReferencesTableItems) ? $item->getReferencedItems() : new TableItemCollection();
    }


    /**
     * Add every item in one collection to another.
     *
     * @param TableItemCollection $to - the collection to add them to.
     *
     * @param TableItemCollection $from - the items to add.
     *
     * @return void
     */
    public static function addAll(TableItemCollection $to, TableItemCollection $from) : void
    {
        foreach ($from as $item)
        {
            $to->add($item);
        }
    }


    /**
     * Check that the items something refers to are all in its table, as nftables can't refer across tables.
     *
     * @param Table $table - the table of the thing that refers to them.
     *
     * @param string $what - what refers to them, for the message, e.g. "A rule".
     *
     * @param TableItemCollection $items - the items it refers to.
     *
     * @return void
     *
     * @throws UnsuitableChainException - if any of them is in a different table.
     */
    public static function assertAllInTable(Table $table, string $what, TableItemCollection $items) : void
    {
        foreach ($items as $item)
        {
            if (!$item->getTable()->isSameTableAs($table))
            {
                $used = self::describe($item);
                $message = "{$what} in the {$table->getName()} table can't use the {$used}, from another table.";
                throw new UnsuitableChainException($message);
            }
        }
    }


    /**
     * Describe an item, for messages, e.g. "set blocklist".
     *
     * @param TableItem $item - the item.
     *
     * @return string
     */
    public static function describe(TableItem $item) : string
    {
        return array_key_first($item->toArray()) . " " . $item->getName();
    }
}
