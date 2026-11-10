<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\TableItem;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of table items (chains, sets, maps, flowtables and named objects), e.g. the ones a rule uses. Anything that
 * isn't a TableItem is rejected as it's added.
 *
 * @extends AbstractCollection<TableItem>
 */
final class TableItemCollection extends AbstractCollection
{
    public function getType() : string
    {
        return TableItem::class;
    }
}
