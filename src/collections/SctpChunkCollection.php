<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Collections\AbstractReadonlyCollection;
use Programster\Nftables\Enums\SctpChunk;

/**
 * A list of SCTP chunk types. It can't be changed once it's created, so it can be shared freely.
 *
 * @extends AbstractReadonlyCollection<SctpChunk>
 */
final readonly class SctpChunkCollection extends AbstractReadonlyCollection
{
    /**
     * Create a list of SCTP chunk types.
     * @param SctpChunk ...$chunks - the SCTP chunk types. There can be none.
     */
    public function __construct(SctpChunk ...$chunks)
    {
        parent::__construct(...$chunks);
    }
}
