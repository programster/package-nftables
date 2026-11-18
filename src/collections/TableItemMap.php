<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractMap;
use Programster\Nftables\Tables\TableItem;

/**
 * Table items (chains, sets, maps, flowtables and named objects), keyed by a string that's unique to each, for looking
 * them up. It keeps the order they were added in. It's mutable, so whatever holds one should never hand it out.
 *
 * @extends AbstractMap<TableItem, TableItemEntry>
 */
final class TableItemMap extends AbstractMap
{
    /**
     * Create a map of table items.
     * @param TableItemEntry ...$entries - the items, each with its key. There can be none.
     */
    public function __construct(TableItemEntry ...$entries)
    {
        parent::__construct(...$entries);
    }
}
