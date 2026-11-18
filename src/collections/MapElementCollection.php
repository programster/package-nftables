<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Maps\MapElement;

/**
 * A list of a map's elements, each a key and the value it maps to. It can't be changed once it's created, so it can be
 * shared freely.
 *
 * @extends AbstractReadonlyCollection<MapElement>
 */
final readonly class MapElementCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of a map's elements, each a key and the value it maps to.
     * @param MapElement ...$elements - the map's elements. There can be none.
     */
    public function __construct(MapElement ...$elements)
    {
        parent::__construct(...$elements);
    }
}
