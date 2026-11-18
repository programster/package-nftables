<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Enums\SetFlag;

/**
 * A list of set flags. It can't be changed once it's created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<SetFlag>
 */
final readonly class SetFlagCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of set flags.
     * @param SetFlag ...$flags - the set flags. There can be none.
     */
    public function __construct(SetFlag ...$flags)
    {
        parent::__construct(...$flags);
    }
}
