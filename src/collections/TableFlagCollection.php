<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Enums\TableFlag;

/**
 * A list of a table's flags. It can't be changed once it's created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<TableFlag>
 */
final readonly class TableFlagCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of a table's flags.
     * @param TableFlag ...$flags - the table's flags. There can be none.
     */
    public function __construct(TableFlag ...$flags)
    {
        parent::__construct(...$flags);
    }
}
