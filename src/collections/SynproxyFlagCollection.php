<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Enums\SynproxyFlag;

/**
 * A list of the TCP options a synproxy offers. It can't be changed once it's created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<SynproxyFlag>
 */
final readonly class SynproxyFlagCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of the TCP options a synproxy offers.
     * @param SynproxyFlag ...$flags - the TCP options. There can be none.
     */
    public function __construct(SynproxyFlag ...$flags)
    {
        parent::__construct(...$flags);
    }
}
