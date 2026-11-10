<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\PortForward;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of port forwards, for RuleFactory::createMapPortForward(). Anything that isn't a PortForward is rejected as
 * it's added.
 *
 * @extends AbstractCollection<PortForward>
 */
final class PortForwardCollection extends AbstractCollection
{
    public function getType() : string
    {
        return PortForward::class;
    }
}
