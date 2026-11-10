<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\VerdictMapElement;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of a verdict map's elements, each a key and the verdict for it. Anything that isn't a VerdictMapElement is
 * rejected as it's added.
 *
 * @extends AbstractCollection<VerdictMapElement>
 */
final class VerdictMapElementCollection extends AbstractCollection
{
    public function getType() : string
    {
        return VerdictMapElement::class;
    }
}
