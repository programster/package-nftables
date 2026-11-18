<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractEntry;
use Programster\Nftables\Tables\Table;

/**
 * One entry in a TableMap: a table, and the key it's looked up by, which is unique to its family and name.
 *
 * @extends AbstractEntry<Table>
 */
final readonly class TableEntry extends AbstractEntry
{
    /**
     * Create the entry.
     * @param string $key - the table's key.
     * @param Table $table - the table.
     */
    public function __construct(string $key, Table $table)
    {
        parent::__construct($key, $table);
    }
}
