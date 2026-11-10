<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\TableItem;
use Ramsey\Collection\Map\AbstractTypedMap;

/**
 * Table items (chains, sets, maps, flowtables and named objects), keyed by a string that's unique to each, for looking
 * them up. Keys that aren't strings, and values that aren't a TableItem, are rejected as they're added. It keeps the
 * order they were added in.
 *
 * @extends AbstractTypedMap<string, TableItem>
 */
final class TableItemMap extends AbstractTypedMap
{
    public function getKeyType() : string
    {
        return "string";
    }


    public function getValueType() : string
    {
        return TableItem::class;
    }
}
