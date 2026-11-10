<?php

declare(strict_types=1);

namespace Programster\Nftables\Objects;

/**
 * A named counter of packets and bytes, which any number of rules can add to (counter name "guest1"), e.g. to total a
 * guest's traffic across all of its rules. "nft list counter <family> <table> <name>" shows its count, and
 * "nft reset counter" reads it and starts it again.
 */
final readonly class NamedCounter extends NamedObject
{
    public function toArray() : array
    {
        return ["counter" => $this->getIdentifier()];
    }
}
