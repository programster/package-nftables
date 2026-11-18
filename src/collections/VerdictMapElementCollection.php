<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Maps\VerdictMapElement;

/**
 * A list of a verdict map's elements, each a key and the verdict for it. It can't be changed once it's created, so it
 * can be shared freely.
 *
 * @extends AbstractReadonlyCollection<VerdictMapElement>
 */
final readonly class VerdictMapElementCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of a verdict map's elements, each a key and the verdict for it.
     * @param VerdictMapElement ...$elements - the verdict map's elements. There can be none.
     */
    public function __construct(VerdictMapElement ...$elements)
    {
        parent::__construct(...$elements);
    }
}
