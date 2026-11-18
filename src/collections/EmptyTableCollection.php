<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Tables\EmptyTable;

/**
 * A list of empty tables, for a Ruleset. It can't be changed once it's created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<EmptyTable>
 */
final readonly class EmptyTableCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of empty tables, for a Ruleset.
     * @param EmptyTable ...$tables - the empty tables. There can be none.
     */
    public function __construct(EmptyTable ...$tables)
    {
        parent::__construct(...$tables);
    }
}
