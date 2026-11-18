<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractMap;
use Programster\Nftables\Tables\Table;

/**
 * Tables, keyed by a string that's unique to each, e.g. its family and name, for looking them up. It keeps the order
 * they were added in. It's mutable, so whatever holds one should never hand it out.
 *
 * @extends AbstractMap<Table, TableEntry>
 */
final class TableMap extends AbstractMap
{
    /**
     * Create a map of tables.
     * @param TableEntry ...$entries - the tables, each with its key. There can be none.
     */
    public function __construct(TableEntry ...$entries)
    {
        parent::__construct(...$entries);
    }
}
