<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractEntry;
use Programster\Nftables\Tables\TableItem;

/**
 * One entry in a TableItemMap: a table item (a chain, set, map, flowtable or named object), and the key it's looked up
 * by, which is unique to it.
 *
 * @extends AbstractEntry<TableItem>
 */
final readonly class TableItemEntry extends AbstractEntry
{
    /**
     * Create the entry.
     * @param string $key - the item's key.
     * @param TableItem $item - the item.
     */
    public function __construct(string $key, TableItem $item)
    {
        parent::__construct($key, $item);
    }
}
