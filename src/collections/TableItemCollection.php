<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Tables\TableItem;

/**
 * A list of table items (chains, sets, maps, flowtables and named objects), e.g. the ones a rule uses. It can't be
 * changed once it's created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<TableItem>
 */
final readonly class TableItemCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of table items (chains, sets, maps, flowtables and named objects).
     * @param TableItem ...$items - the table items. There can be none.
     */
    public function __construct(TableItem ...$items)
    {
        parent::__construct(...$items);
    }
}
