<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Enums\SetType;

/**
 * A list of set element types, for a set of concatenations (e.g. an address and a port). It can't be changed once it's
 * created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<SetType>
 */
final readonly class SetTypeCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of set element types, for a set of concatenations.
     * @param SetType ...$types - the set element types. There can be none.
     */
    public function __construct(SetType ...$types)
    {
        parent::__construct(...$types);
    }
}
