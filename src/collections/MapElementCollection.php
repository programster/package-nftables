<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\MapElement;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of a map's elements, each a key and the value it maps to. Anything that isn't a MapElement is rejected as it's
 * added.
 *
 * @extends AbstractCollection<MapElement>
 */
final class MapElementCollection extends AbstractCollection
{
    public function getType() : string
    {
        return MapElement::class;
    }
}
