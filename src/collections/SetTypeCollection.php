<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Enums\SetType;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of set element types, for a set of concatenations (e.g. an address and a port). Anything that isn't a
 * SetType is rejected as it's added.
 *
 * @extends AbstractCollection<SetType>
 */
final class SetTypeCollection extends AbstractCollection
{
    public function getType() : string
    {
        return SetType::class;
    }
}
