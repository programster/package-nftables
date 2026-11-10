<?php

declare(strict_types=1);

namespace Programster\Nftables\Collections;

use Programster\Nftables\Enums\SctpChunk;
use Ramsey\Collection\AbstractCollection;

/**
 * A list of SCTP chunk types. Anything that isn't a SctpChunk is rejected as it's added.
 *
 * @extends AbstractCollection<SctpChunk>
 */
final class SctpChunkCollection extends AbstractCollection
{
    public function getType() : string
    {
        return SctpChunk::class;
    }
}
