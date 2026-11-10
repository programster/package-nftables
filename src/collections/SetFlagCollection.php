<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Enums\SetFlag;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of set flags. Anything that isn't a SetFlag is rejected as it's added.
 *
 * @extends AbstractCollection<SetFlag>
 */
final class SetFlagCollection extends AbstractCollection
{
    public function getType() : string
    {
        return SetFlag::class;
    }
}
