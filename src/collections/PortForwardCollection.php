<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Rules\PortForward;

/**
 * A list of port forwards, for RuleFactory::createMapPortForward(). It can't be changed once it's created, so it can be
 * shared freely.
 *
 * @extends AbstractReadonlyCollection<PortForward>
 */
final readonly class PortForwardCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of port forwards, for RuleFactory::createMapPortForward().
     * @param PortForward ...$forwards - the port forwards. There can be none.
     */
    public function __construct(PortForward ...$forwards)
    {
        parent::__construct(...$forwards);
    }
}
