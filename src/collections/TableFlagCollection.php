<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Enums\TableFlag;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of a table's flags. Anything that isn't a TableFlag is rejected as it's added.
 *
 * @extends AbstractCollection<TableFlag>
 */
final class TableFlagCollection extends AbstractCollection
{
    public function getType() : string
    {
        return TableFlag::class;
    }
}
