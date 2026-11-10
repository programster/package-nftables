<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Table;
use Ramsey\Collection\Map\AbstractTypedMap;

/**
 * Tables, keyed by a string that's unique to each, e.g. its family and name, for looking them up. Keys that aren't
 * strings, and values that aren't a Table, are rejected as they're added. It keeps the order they were added in.
 *
 * @extends AbstractTypedMap<string, Table>
 */
final class TableMap extends AbstractTypedMap
{
    public function getKeyType() : string
    {
        return "string";
    }


    public function getValueType() : string
    {
        return Table::class;
    }
}
